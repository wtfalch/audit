import type { PGlite } from '@electric-sql/pglite';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/pglite';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type Handle, createLedger, scopeAuditTenant } from './ledger.js';
import { tables } from './tables.js';
import { CORE, grantsIn, migratedPglite } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

/**
 * A rolling deploy: a writer on the older package version (format 1 `sign()`)
 * still runs after migration 0007 and after the first format 2 row. Its
 * sealed format 1 row would break the chain for good, so 0007 refuses it. Run
 * as the runtime role, so row-level security is in force for the insert.
 */
const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';
const REFUSED = 'audit_events: a sealed format 1 row after a format 2 row is refused';

let client: PGlite;
let db: Handle;
const chained = createLedger({
  vocabulary: ledgerVocabularyFromCore(CORE),
  hashChain: true,
});
const plain = createLedger({ vocabulary: ledgerVocabularyFromCore(CORE) });
const ada = { class: 'human', id: 'user_ada', display: 'Ada' };
const event = (tenantId: string | null, targetId: string) =>
  ({
    action: tenantId === null ? 'operator.bootstrapped' : 'membership.created',
    tenantId,
    actor: ada,
    context: tenantId === null ? 'operator' : 'standard',
    target: { type: 'membership', id: targetId },
  }) as const;

/** What an old writer's sign() inserts: sealed, with no chain_version, seq or received_at. */
const oldWriterInsert = (tenant: string | null, hash: string) =>
  `insert into audit_events
     (tenant_id, actor_class, actor_id, actor_display, action, target_type, target_id,
      outcome, context, tenant_visible, row_hash, content_hash, content_salt)
   values (${tenant === null ? 'null' : `'${tenant}'`}, 'human', 'u', 'U', 'a.b', 't', 'x',
      'success', 'standard', false, '${hash}', '${hash}', 'salt')`;
const oldWriterScoped = (tenant: string) =>
  db.transaction(async (tx) => {
    await scopeAuditTenant(tx, tenant);
    await tx.execute(sql.raw(oldWriterInsert(tenant, 'a'.repeat(64))));
  });
const count = async () =>
  Number((await client.query<{ n: string }>('select count(*) as n from audit_events')).rows[0]?.n);

beforeAll(async () => {
  client = await migratedPglite();
  await client.exec('create role postgres_rt');
  await client.exec('grant select, insert on audit_events to postgres_rt');
  for (const signature of grantsIn('public')) {
    await client.exec(`grant execute on function ${signature} to postgres_rt`);
  }
  db = drizzle(client, { schema: tables }) as unknown as Handle;
});
afterAll(async () => {
  await client.close();
});
beforeEach(async () => {
  await client.exec('reset role');
  await client.exec('alter table audit_events disable trigger all');
  await client.exec('delete from audit_events');
  await client.exec('alter table audit_events enable trigger all');
  await client.exec('set role postgres_rt');
});

describe('a sealed format 1 row after the first format 2 row', () => {
  it('is refused with fixed text, and nothing is inserted', async () => {
    await chained.sign(db, event(TENANT_A, 'a1'));
    await expect(client.exec(oldWriterInsert(TENANT_A, 'a'.repeat(64)))).rejects.toThrow(REFUSED);
    expect(await count()).toBe(1);
  });

  it('is accepted before any format 2 row', async () => {
    await client.exec(oldWriterInsert(TENANT_A, 'a'.repeat(64)));
    await client.exec(oldWriterInsert(TENANT_A, 'b'.repeat(64)));
    expect(await count()).toBe(2);
  });

  it('is refused inside a tenant-scoped transaction that cannot see the format 2 row', async () => {
    await chained.sign(db, event(TENANT_B, 'b1'));
    await expect(oldWriterScoped(TENANT_A)).rejects.toThrow(REFUSED);
    expect(await count()).toBe(1);
  });

  it('is refused with audit.require_tenant on and a scope set', async () => {
    await chained.sign(db, event(TENANT_B, 'b1'));
    await client.exec("set audit.require_tenant = 'on'");
    try {
      await expect(oldWriterScoped(TENANT_A)).rejects.toThrow(REFUSED);
    } finally {
      await client.exec('reset audit.require_tenant');
    }
    expect(await count()).toBe(1);
  });
});

describe('rows the trigger must let through', () => {
  it('an unsealed row (hashChain off) inserts after format 2 rows', async () => {
    await chained.sign(db, event(TENANT_A, 'a1'));
    await plain.sign(db, event(TENANT_A, 'a2'));
    expect(await count()).toBe(2);
  });

  it('a format 2 row inserts after a format 2 row', async () => {
    await chained.sign(db, event(TENANT_A, 'a1'));
    await chained.sign(db, event(null, 'estate1'));
    expect(await count()).toBe(2);
  });
});
