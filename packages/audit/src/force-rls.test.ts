import { randomUUID } from 'node:crypto';
import { withDrizzle } from '@wtfalch/db/drizzle';
import { runMigrationSources } from '@wtfalch/db/migrate';
import { createDatabase } from '@wtfalch/db/postgres';
import { afterEach, describe, expect, it } from 'vitest';
import { createLedger, scopeAuditTenant } from './ledger.js';
import { tables } from './tables.js';
import { ALLOW_AUDIT_READ, auditResource } from './test/access.js';
import { CORE, type RuntimeRoleDb, sources, urlFor, withRuntimeRole } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

/**
 * `migrations/0006_force_rls.sql`, on a real Postgres only: PGlite's
 * connection is always a superuser, and a superuser bypasses RLS whether or
 * not it is forced, so PGlite can never tell a forced policy from an
 * unforced one. Every case runs in its own named schema and logs in as the
 * role under test; nothing uses `set role`.
 */
const url = process.env.TEST_DATABASE_URL;
const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';

const seed = (owner: { query: (text: string) => Promise<unknown> }) =>
  owner.query(
    `insert into audit_events (tenant_id, actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible) values
     ('${TENANT_A}','human','u1','U','membership.created','membership','a1','success','standard',true),
     ('${TENANT_B}','human','u1','U','membership.created','membership','b1','success','standard',true)`,
  );

let t: RuntimeRoleDb | undefined;
afterEach(async () => {
  await t?.close();
  t = undefined;
});

describe.skipIf(!url)('forced row-level security', () => {
  it('is forced on audit_events', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    const [row] = await t.owner.database.query(
      "select relforcerowsecurity as forced from pg_class where oid = 'audit_events'::regclass",
    );
    expect(row?.forced).toBe(true);
  });

  it('refuses a cross-tenant read with the tenant filter removed, run as the non-owner runtime role', async () => {
    if (!url) return;
    // A forgotten scope should see nothing, not everything: 0005_rls.sql's
    // own escape hatch for that, set the way a host sets it, as a role
    // setting through ensureRuntimeRole.
    t = await withRuntimeRole(url, { settings: { 'audit.require_tenant': 'on' } });

    // Seeded directly, as the owner -- bypassing the ledger entirely, so
    // this proves the table's own RLS, not any application-level filter.
    await seed(t.owner.database);

    const db = t.runtimeDb;
    const vocabulary = ledgerVocabularyFromCore(CORE);
    const ledger = createLedger({ vocabulary, checkRuntimeRole: false });

    // The tenant filter removed entirely: no scopeAuditTenant call, and
    // no tenantId passed to page() either.
    const unscoped = await ledger.page(db, {
      access: ALLOW_AUDIT_READ,
      resource: auditResource(null),
    });
    expect(unscoped.items).toEqual([]);

    // Scoped to TENANT_A, inside a transaction (set_config(..., true) is
    // transaction-local): sees its own row, never TENANT_B's -- this is
    // the same case rls.test.ts covers on PGlite's simulated RLS; here
    // it is a real Postgres engine, run as a genuine non-owner role, not
    // the always-superuser PGlite connection FORCE cannot mean anything
    // to.
    const scoped = await db.transaction(async (tx) => {
      await scopeAuditTenant(tx, TENANT_A);
      return ledger.page(tx, {
        access: ALLOW_AUDIT_READ,
        resource: auditResource(TENANT_A),
      });
    });
    expect(scoped.items.map((r) => r.targetId)).toEqual(['a1']);
  });

  it('scopes the table owner connection to a tenant, with FORCE the whole point', async () => {
    if (!url) return;
    // The case above proves 0005_rls.sql's ordinary policy, as the runtime
    // role -- a role RLS already governs with or without FORCE. FORCE's
    // entire job is applying that same policy to the table's *owner*, which
    // 0005_rls.sql explicitly left exempt. A superuser (or a BYPASSRLS role)
    // ignores RLS regardless of FORCE, same as PGlite always does -- this
    // repo's own TEST_DATABASE_URL fixture is exactly such a superuser -- so
    // this test builds its own definitely-unprivileged owner role, migrates
    // as it, and connects as it: that connection is the table's actual owner
    // throughout. Remove `force row level security` from 0006_force_rls.sql
    // and this is the case that turns red: the owner would bypass the policy
    // and see both tenants' rows.
    const id = randomUUID().replaceAll('-', '');
    const ownerRole = `audit_owner_${id.slice(0, 16)}`;
    const schema = `audit_test_${id}`;
    const ownerUrl = urlFor(url, ownerRole, 'owner');
    const admin = createDatabase({ url: () => url, max: 1, applicationName: 'audit-test' });
    const owner = createDatabase({
      url: () => ownerUrl,
      searchPath: [schema, 'public'],
      max: 1,
      applicationName: 'audit-test',
    });
    try {
      await admin.database.query(
        `create role "${ownerRole}" login password 'owner' nosuperuser nobypassrls`,
      );
      const [dbRow] = await admin.database.query('select current_database() as name');
      await admin.database.query(`grant create on database "${dbRow?.name}" to "${ownerRole}"`);
      await runMigrationSources({ url: ownerUrl, schema, sources, log: () => undefined });

      // Seeded directly, as the owner -- bypassing the ledger entirely, so
      // this proves the table's own RLS, not any application-level filter.
      const ownerDb = withDrizzle(owner, { schema: tables });
      await seed(ownerDb);

      const db = ownerDb.orm;
      const vocabulary = ledgerVocabularyFromCore(CORE);
      const ledger = createLedger({ vocabulary, checkRuntimeRole: false });

      const scoped = await db.transaction(async (tx) => {
        await scopeAuditTenant(tx, TENANT_A);
        return ledger.page(tx, {
          access: ALLOW_AUDIT_READ,
          resource: auditResource(TENANT_A),
        });
      });
      expect(scoped.items.map((r) => r.targetId)).toEqual(['a1']);
    } finally {
      await owner.close({ timeoutMs: 5000 }).catch(() => undefined);
      await admin.database
        .query(`drop schema if exists "${schema}" cascade`)
        .catch(() => undefined);
      await admin.database.query(`drop owned by "${ownerRole}"`).catch(() => undefined);
      await admin.database.query(`drop role if exists "${ownerRole}"`).catch(() => undefined);
      await admin.close({ timeoutMs: 5000 });
    }
  });
});
