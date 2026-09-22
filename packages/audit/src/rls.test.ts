import { PGlite } from '@electric-sql/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { verifyChain } from './chain.js';
import { type Handle, createLedger, scopeAuditTenant } from './ledger.js';
import { type AuditEventRow, auditEvents, tables } from './tables.js';
import { CORE, MIGRATION_SQL } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

/**
 * Row-level security (migrations/0005_rls.sql), as the runtime role.
 *
 * PGlite runs as a superuser, and a superuser bypasses RLS, so every test
 * here `set role`s to `postgres_rt` -- the `<database>_rt` the migrations
 * grant to -- exactly the role a host's app connects as. The role exists
 * before the migrations run, so their grant blocks fire as they would on a
 * real estate database.
 */
const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';

let client: PGlite;
let db: Handle;
const vocabulary = ledgerVocabularyFromCore(CORE);
const ledger = createLedger({ vocabulary });
const chained = createLedger({ vocabulary, hashChain: true });

const ada = { class: 'human', id: 'user_ada', display: 'Ada' };
function event(tenantId: string | null, targetId: string) {
  return {
    action: tenantId === null ? 'operator.bootstrapped' : 'membership.created',
    tenantId,
    actor: ada,
    context: tenantId === null ? 'operator' : 'standard',
    target: { type: 'membership', id: targetId },
  } as const;
}

async function asOwner<T>(fn: () => Promise<T>): Promise<T> {
  await client.exec('reset role');
  try {
    return await fn();
  } finally {
    await client.exec('set role postgres_rt');
  }
}

async function visibleTargets(handle: Handle = db): Promise<string[]> {
  const rows = await handle.select({ id: auditEvents.targetId }).from(auditEvents);
  return rows.map((r) => r.id).sort();
}

beforeAll(async () => {
  client = new PGlite();
  await client.exec('create role postgres_rt');
  await client.exec(MIGRATION_SQL);
  await client.exec('grant select, insert on audit_events to postgres_rt');
  db = drizzle(client, { schema: tables }) as unknown as Handle;
});

afterAll(async () => {
  await client.close();
});

beforeEach(async () => {
  await client.exec('reset role');
  await client.exec('alter role postgres_rt reset audit.require_tenant');
  await client.exec('alter table audit_events disable trigger all');
  await client.exec('delete from audit_events');
  await client.exec('alter table audit_events enable trigger all');
  await client.exec('set role postgres_rt');
  for (const [tenant, id] of [
    [TENANT_A, 'a1'],
    [TENANT_B, 'b1'],
    [null, 'estate1'],
  ] as const) {
    await ledger.sign(db, event(tenant, id));
  }
});

describe('row-level security on audit_events', () => {
  it('is on, and changes nothing for an unscoped runtime role', async () => {
    const [row] = (
      await asOwner(() =>
        client.query<{ on: boolean }>(
          "select relrowsecurity as on from pg_class where relname = 'audit_events'",
        ),
      )
    ).rows;
    expect(row?.on).toBe(true);
    expect(await visibleTargets()).toEqual(['a1', 'b1', 'estate1']);
  });

  it('scoped to a tenant, a query with no tenant predicate sees that tenant only', async () => {
    await db.transaction(async (tx) => {
      await scopeAuditTenant(tx, TENANT_A);
      expect(await visibleTargets(tx)).toEqual(['a1']);
      // ledger.page() with the wrong tenant, the mistake RLS is for.
      const leaked = await ledger.page(tx, { tenantId: TENANT_B });
      expect(leaked.items).toEqual([]);
    });
    // Transaction-local: gone at commit.
    expect(await visibleTargets()).toEqual(['a1', 'b1', 'estate1']);
  });

  it('with audit.require_tenant on, an unscoped read sees nothing and a scoped one its tenant', async () => {
    await asOwner(() => client.exec("alter role postgres_rt set audit.require_tenant = 'on'"));
    // A role-level setting applies at session start; re-enter the role's session defaults.
    await client.exec("set audit.require_tenant = 'on'");
    expect(await visibleTargets()).toEqual([]);
    expect((await ledger.exportRows(db, TENANT_A)).length).toBe(0);
    await db.transaction(async (tx) => {
      await scopeAuditTenant(tx, TENANT_B);
      expect(await visibleTargets(tx)).toEqual(['b1']);
    });
    await client.exec('reset audit.require_tenant');
  });

  it('still lets a scoped transaction append any row, and still refuses update and delete', async () => {
    await db.transaction(async (tx) => {
      await scopeAuditTenant(tx, TENANT_A);
      await ledger.sign(tx, event(TENANT_B, 'b2'));
      await ledger.sign(tx, event(null, 'estate2'));
    });
    expect(await visibleTargets()).toEqual(['a1', 'b1', 'b2', 'estate1', 'estate2']);
    await expect(client.exec("update audit_events set actor_display = 'x'")).rejects.toThrow(
      /permission denied/,
    );
    await expect(client.exec('delete from audit_events')).rejects.toThrow(/permission denied/);
  });

  it('refuses an empty tenant id rather than unscoping', async () => {
    await expect(scopeAuditTenant(db, '')).rejects.toThrow(/empty tenant id/);
  });

  it('hash chaining under a tenant scope chains onto the true tail, not the tenant’s', async () => {
    await asOwner(async () => {
      await client.exec('alter table audit_events disable trigger all');
      await client.exec('delete from audit_events');
      await client.exec('alter table audit_events enable trigger all');
    });
    await chained.sign(db, event(TENANT_A, 'a1'));
    await chained.sign(db, event(TENANT_B, 'b1'));
    await db.transaction(async (tx) => {
      await scopeAuditTenant(tx, TENANT_A);
      await chained.sign(tx, event(TENANT_A, 'a2'));
    });
    const rows = await asOwner(() => db.select().from(auditEvents));
    expect(rows).toHaveLength(3);
    expect(await verifyChain(rows as AuditEventRow[])).toEqual({ ok: true });
  });

  it('erase()’s pending sweep seals every tenant’s erased rows even when reads see nothing', async () => {
    await asOwner(async () => {
      await client.exec('alter table audit_events disable trigger all');
      await client.exec('delete from audit_events');
      await client.exec('alter table audit_events enable trigger all');
    });
    await chained.sign(db, event(TENANT_A, 'a1'));
    await chained.sign(db, event(TENANT_B, 'b1'));
    await client.exec("set audit.require_tenant = 'on'");
    try {
      await db.transaction(async (tx) => {
        await scopeAuditTenant(tx, TENANT_A);
        expect(await chained.erase(tx, { subject: 'user_ada', pseudonym: 'Erased' })).toBe(2);
      });
    } finally {
      await client.exec('reset audit.require_tenant');
    }
    const rows = await asOwner(() => db.select().from(auditEvents));
    expect(rows.map((r) => r.erasureHash !== null)).toEqual([true, true]);
    expect(await verifyChain(rows as AuditEventRow[])).toEqual({ ok: true });
  });
});
