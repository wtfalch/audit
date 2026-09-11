import postgres from 'postgres';
import { describe, expect, it } from 'vitest';
import { MIGRATION_SQL } from './test/db.js';

/**
 * The runtime-role wall, on a real Postgres only: PGlite has one role. With
 * TEST_DATABASE_URL set, creates <database>_rt, applies the migration, and
 * checks the role can insert and erase but not update, delete or truncate.
 */
const url = process.env.TEST_DATABASE_URL;

describe.skipIf(!url)('runtime role', () => {
  it('may append and erase, and nothing else', async () => {
    if (!url) return;
    const owner = postgres(url, { prepare: false, max: 2 });
    try {
      const dbName = String((await owner`select current_database() as d`)[0]?.d);
      const rt = `${dbName}_rt`;
      await owner.unsafe(`drop schema public cascade; create schema public;`);
      await owner.unsafe(
        `do $$ begin if not exists (select 1 from pg_roles where rolname = '${rt}') then create role "${rt}" login password 'rt'; end if; end $$;`,
      );
      await owner.unsafe(`grant usage on schema public to "${rt}"`);
      await owner.unsafe(MIGRATION_SQL);
      await owner.unsafe(`grant select, insert on audit_events to "${rt}"`);

      const asRt = async (text: string) => {
        await owner.unsafe(`set role "${rt}"`);
        try {
          return await owner.unsafe(text);
        } finally {
          await owner.unsafe('reset role');
        }
      };

      await asRt(
        "insert into audit_events (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible, after) values ('human','u1','U','x.y','t','1','success','standard',true,'{\"a\":1}')",
      );
      await expect(asRt("update audit_events set actor_display = 'x'")).rejects.toThrow(
        /permission denied/,
      );
      await expect(asRt('delete from audit_events')).rejects.toThrow(/permission denied/);
      await expect(asRt('truncate audit_events')).rejects.toThrow(/permission denied/);
      const erased = await asRt("select audit_erase_person('u1', 'Erased', null) as n");
      expect(Number(erased[0]?.n)).toBe(1);
      const [row] = await asRt('select actor_display, after from audit_events');
      expect(row).toMatchObject({ actor_display: 'Erased', after: { erased: true } });
    } finally {
      await owner.end();
    }
  });
});
