import { describe, expect, it } from 'vitest';
import { MIGRATION_SQL, testDb } from './test/db.js';

describe('0001_audit.sql', () => {
  it('applies twice without error', async () => {
    const t = await testDb();
    try {
      await t.exec(MIGRATION_SQL);
      const tables = await t.query(
        "select table_name from information_schema.tables where table_schema = 'public' order by 1",
      );
      expect(tables.map((r) => r.table_name)).toEqual(['audit_events']);
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
        "select column_name from information_schema.columns where table_name = 'audit_events' order by 1",
      );
      expect(actual.map((r) => r.column_name)).toEqual(declared);
    } finally {
      await t.close();
    }
  });

  it('pins the erasure function to the catalog and revokes it from public', async () => {
    const t = await testDb();
    try {
      const [fn] = await t.query(
        "select prosecdef, proconfig, proacl::text as acl from pg_proc where proname = 'audit_erase_person'",
      );
      expect(fn?.prosecdef).toBe(true);
      expect(fn?.proconfig).toEqual(['search_path=pg_catalog, public']);
      // Revoked from public: the ACL is no longer the default (null).
      expect(fn?.acl).not.toBeNull();
      expect(String(fn?.acl)).not.toMatch(/(^|,)=X\//);
    } finally {
      await t.close();
    }
  });
});
