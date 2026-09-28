import { drizzle as drizzlePostgres } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { describe, expect, it } from 'vitest';
import { type Handle, createLedger } from './ledger.js';
import { UnsafeRuntimeRoleError, assertRuntimeRole } from './runtime-role-guard.js';
import { CORE, MIGRATION_SQL } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

/**
 * Real Postgres only: PGlite has one role, so there is no "wrong role" to
 * catch. `max: 1` keeps every statement, including `set role`, on the one
 * connection the test's own queries reuse.
 */
const url = process.env.TEST_DATABASE_URL;

describe.skipIf(!url)('assertRuntimeRole', () => {
  it('throws for the table owner', async () => {
    if (!url) return;
    const client = postgres(url, { prepare: false, max: 1 });
    try {
      await client.unsafe('drop schema public cascade; create schema public;');
      await client.unsafe(MIGRATION_SQL);
      const db = drizzlePostgres(client) as unknown as Handle;
      await expect(assertRuntimeRole(db)).rejects.toThrow(UnsafeRuntimeRoleError);
    } finally {
      await client.end();
    }
  });

  it('throws for a role with no name migrations/0001_audit.sql revoked from', async () => {
    if (!url) return;
    const owner = postgres(url, { prepare: false, max: 1 });
    try {
      await owner.unsafe('drop schema public cascade; create schema public;');
      await owner.unsafe(
        "do $$ begin if not exists (select 1 from pg_roles where rolname = 'audit_guard_other') then create role audit_guard_other login password 'other'; end if; end $$;",
      );
      await owner.unsafe('grant usage on schema public to audit_guard_other');
      await owner.unsafe(MIGRATION_SQL);
      await owner.unsafe(
        'grant select, insert, update, delete on audit_events to audit_guard_other',
      );
      await owner.unsafe('set role audit_guard_other');
      const db = drizzlePostgres(owner) as unknown as Handle;
      await expect(assertRuntimeRole(db)).rejects.toThrow(UnsafeRuntimeRoleError);
    } finally {
      await owner.unsafe('reset role').catch(() => undefined);
      await owner.end();
    }
  });

  it('resolves for the role migrations/0001_audit.sql revokes update/delete/truncate from', async () => {
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
      await owner.unsafe(`set role "${rt}"`);
      const db = drizzlePostgres(owner) as unknown as Handle;
      await expect(assertRuntimeRole(db)).resolves.toBeUndefined();
    } finally {
      await owner.unsafe('reset role').catch(() => undefined);
      await owner.end();
    }
  });
});

describe.skipIf(!url)("createLedger's own check (LedgerOptions.checkRuntimeRole)", () => {
  const vocabulary = ledgerVocabularyFromCore(CORE);
  const ada = { class: 'human', id: 'user_ada', display: 'Ada' };
  const event = {
    action: 'membership.created',
    tenantId: null,
    actor: ada,
    context: 'standard',
    target: { type: 'membership', id: 'm_1' },
  } as const;

  it('throws instead of writing, on for the table owner', async () => {
    if (!url) return;
    const client = postgres(url, { prepare: false, max: 1 });
    try {
      await client.unsafe('drop schema public cascade; create schema public;');
      await client.unsafe(MIGRATION_SQL);
      const db = drizzlePostgres(client) as unknown as Handle;
      const ledger = createLedger({ vocabulary });
      await expect(ledger.sign(db, event)).rejects.toThrow(UnsafeRuntimeRoleError);
      const count = Number(
        (await client`select count(*)::int as count from audit_events`)[0]?.count,
      );
      expect(count).toBe(0);
    } finally {
      await client.end();
    }
  });

  it('writes normally for the role migrations/0001_audit.sql revokes update/delete/truncate from', async () => {
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
      await owner.unsafe(`set role "${rt}"`);
      const db = drizzlePostgres(owner) as unknown as Handle;
      const ledger = createLedger({ vocabulary });
      await expect(ledger.sign(db, event)).resolves.toBeUndefined();
      // A second call on the same handle reuses the first check rather than
      // repeating it -- this would time out on a role the check itself
      // never resolves for, so a passing second write here also stands in
      // for that.
      await expect(ledger.sign(db, event)).resolves.toBeUndefined();
      const count = Number(
        (await owner`select count(*)::int as count from audit_events`)[0]?.count,
      );
      expect(count).toBe(2);
    } finally {
      await owner.unsafe('reset role').catch(() => undefined);
      await owner.end();
    }
  });

  it('writes for the table owner when checkRuntimeRole is false', async () => {
    if (!url) return;
    const client = postgres(url, { prepare: false, max: 1 });
    try {
      await client.unsafe('drop schema public cascade; create schema public;');
      await client.unsafe(MIGRATION_SQL);
      const db = drizzlePostgres(client) as unknown as Handle;
      const ledger = createLedger({ vocabulary, checkRuntimeRole: false });
      await expect(ledger.sign(db, event)).resolves.toBeUndefined();
      const count = Number(
        (await client`select count(*)::int as count from audit_events`)[0]?.count,
      );
      expect(count).toBe(1);
    } finally {
      await client.end();
    }
  });
});
