import { describe, expect, it } from 'vitest';
import { MIGRATION_SQL, testDb } from './test/db.js';

describe('the migrations', () => {
  it('applies twice without error', async () => {
    const t = await testDb();
    try {
      await t.exec(MIGRATION_SQL);
      const tables = await t.query(
        "select table_name from information_schema.tables where table_schema = current_schema() and table_name <> '_migrations_sources' order by 1",
      );
      expect(tables.map((r) => r.table_name)).toEqual([
        'audit_anchors',
        'audit_checkpoints',
        'audit_events',
        'audit_signing_keys',
      ]);
    } finally {
      await t.close();
    }
  });

  it('mirrors the drizzle table column for column', async () => {
    const t = await testDb();
    try {
      const { auditEvents } = await import('./tables.js');
      const { getTableColumns } = await import('drizzle-orm');
      const declared = Object.values(getTableColumns(auditEvents))
        .map((c) => c.name)
        .sort();
      const actual = await t.query(
        "select column_name from information_schema.columns where table_name = 'audit_events' and table_schema = current_schema() order by 1",
      );
      expect(actual.map((r) => r.column_name)).toEqual(declared);
    } finally {
      await t.close();
    }
  });

  it("pins the erasure function to the migration's search_path and revokes it from public", async () => {
    const t = await testDb();
    try {
      const [fn] = await t.query(
        "select prosecdef, proconfig, proacl::text as acl from pg_proc where proname = 'audit_erase_person' and pronamespace = current_schema()::regnamespace",
      );
      expect(fn?.prosecdef).toBe(true);
      // `set search_path from current`: whatever the migrating connection used, never a literal `public`.
      // The runner appends `pg_temp` (db 0.5.2), which `show` on a plain connection omits.
      const [path] = await t.query('show search_path');
      const squash = (text: unknown) =>
        String(text)
          .replaceAll(' ', '')
          .replace(/,pg_temp$/, '');
      expect((fn?.proconfig as string[]).map(squash)).toEqual([
        squash(`search_path=${path?.search_path}`),
      ]);
      // Revoked from public: the ACL is no longer the default (null).
      expect(fn?.acl).not.toBeNull();
      expect(String(fn?.acl)).not.toMatch(/(^|,)=X\//);
    } finally {
      await t.close();
    }
  });
});
