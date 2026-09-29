import { drizzle as drizzlePostgres } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { describe, expect, it } from 'vitest';
import { type Handle, createLedger, scopeAuditTenant } from './ledger.js';
import { ALLOW_AUDIT_READ, auditResource } from './test/access.js';
import { CORE, MIGRATION_SQL } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

/**
 * `migrations/0006_force_rls.sql`, on a real Postgres only: PGlite's
 * connection is always a superuser, and a superuser bypasses RLS whether or
 * not it is forced, so PGlite can never tell a forced policy from an
 * unforced one. `max: 1` keeps every statement, including `set role`, on
 * the one connection the test's own queries reuse -- the same shape
 * `runtime-role-guard.test.ts` and `privileges.test.ts` use.
 */
const url = process.env.TEST_DATABASE_URL;
const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';

describe.skipIf(!url)('forced row-level security', () => {
  it('is forced on audit_events', async () => {
    if (!url) return;
    const client = postgres(url, { prepare: false, max: 1 });
    try {
      await client.unsafe('drop schema public cascade; create schema public;');
      await client.unsafe(MIGRATION_SQL);
      const [row] = await client.unsafe(
        "select relforcerowsecurity as forced from pg_class where relname = 'audit_events'",
      );
      expect(row?.forced).toBe(true);
    } finally {
      await client.end();
    }
  });

  it('refuses a cross-tenant read with the tenant filter removed, run as the non-owner runtime role', async () => {
    if (!url) return;
    const owner = postgres(url, { prepare: false, max: 1 });
    try {
      const dbName = String((await owner`select current_database() as d`)[0]?.d);
      const rt = `${dbName}_rt`;
      await owner.unsafe('drop schema public cascade; create schema public;');
      await owner.unsafe(
        `do $$ begin if not exists (select 1 from pg_roles where rolname = '${rt}') then create role "${rt}" login password 'rt'; end if; end $$;`,
      );
      await owner.unsafe(`grant usage on schema public to "${rt}"`);
      await owner.unsafe(MIGRATION_SQL);
      await owner.unsafe(`grant select, insert on audit_events to "${rt}"`);
      // A forgotten scope should see nothing, not everything: 0005_rls.sql's
      // own escape hatch for that. A role-level setting only applies at a
      // session's start, so the explicit `set` below re-asserts it for this
      // already-open connection too.
      await owner.unsafe(`alter role "${rt}" set audit.require_tenant = 'on'`);

      // Seeded directly, as the owner -- bypassing the ledger entirely, so
      // this proves the table's own RLS, not any application-level filter.
      await owner.unsafe(
        `insert into audit_events (tenant_id, actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible) values
         ('${TENANT_A}','human','u1','U','membership.created','membership','a1','success','standard',true),
         ('${TENANT_B}','human','u1','U','membership.created','membership','b1','success','standard',true)`,
      );

      await owner.unsafe(`set role "${rt}"`);
      await owner.unsafe("set audit.require_tenant = 'on'");
      const db = drizzlePostgres(owner) as unknown as Handle;
      const vocabulary = ledgerVocabularyFromCore(CORE);
      const ledger = createLedger({ vocabulary, checkRuntimeRole: false });

      try {
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
      } finally {
        await owner.unsafe('reset audit.require_tenant').catch(() => undefined);
        await owner.unsafe('reset role').catch(() => undefined);
      }
    } finally {
      await owner.end();
    }
  });

  it('scopes the table owner connection to a tenant, with FORCE the whole point', async () => {
    if (!url) return;
    // The case above proves 0005_rls.sql's ordinary policy, as `<database>_rt`
    // -- a role RLS already governs with or without FORCE. FORCE's entire
    // job is applying that same policy to the table's *owner*, which
    // 0005_rls.sql explicitly left exempt. A superuser (or a BYPASSRLS role)
    // ignores RLS regardless of FORCE, same as PGlite always does -- this
    // repo's own TEST_DATABASE_URL fixture is exactly such a superuser -- so
    // this test builds its own definitely-unprivileged owner role, creates
    // the schema as it, and never runs `set role`: that connection stays the
    // table's actual owner throughout. Remove `force row level security`
    // from 0006_force_rls.sql and this is the case that turns red: the owner
    // would bypass the policy and see both tenants' rows.
    const ownerRole = 'audit_force_rls_owner';
    const admin = postgres(url, { prepare: false, max: 1 });
    try {
      await admin.unsafe('drop schema public cascade;');
      await admin.unsafe(
        `do $$ begin
           if not exists (select 1 from pg_roles where rolname = '${ownerRole}') then
             create role "${ownerRole}" login password 'owner' nosuperuser nobypassrls;
           else
             alter role "${ownerRole}" nosuperuser nobypassrls password 'owner';
           end if;
         end $$;`,
      );
      await admin.unsafe(`create schema public authorization "${ownerRole}";`);
    } finally {
      await admin.end();
    }

    // A fresh connection authenticated as the role above, never the admin
    // connection with a `set role` -- so this genuinely is the object
    // owner's own session, not a superuser wearing it temporarily.
    const owner = postgres(url, { prepare: false, max: 1, user: ownerRole, password: 'owner' });
    try {
      await owner.unsafe(MIGRATION_SQL);

      // Seeded directly, as the owner -- bypassing the ledger entirely, so
      // this proves the table's own RLS, not any application-level filter.
      await owner.unsafe(
        `insert into audit_events (tenant_id, actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible) values
         ('${TENANT_A}','human','u1','U','membership.created','membership','a1','success','standard',true),
         ('${TENANT_B}','human','u1','U','membership.created','membership','b1','success','standard',true)`,
      );

      const db = drizzlePostgres(owner) as unknown as Handle;
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
      await owner.end();
    }
  });
});
