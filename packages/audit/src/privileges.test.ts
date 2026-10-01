import { afterEach, describe, expect, it } from 'vitest';
import { type RuntimeRoleDb, withRuntimeRole } from './test/db.js';

/**
 * The runtime-role wall, on a real Postgres only: PGlite has one role. With
 * TEST_DATABASE_URL set, migrates into a named schema, makes a non-owner
 * runtime role with `ensureRuntimeRole` (what the README tells a host to
 * pass), and checks it can insert and erase but not update, delete or
 * truncate.
 */
const url = process.env.TEST_DATABASE_URL;

let t: RuntimeRoleDb | undefined;
afterEach(async () => {
  await t?.close();
  t = undefined;
});

const asRt = (db: RuntimeRoleDb, text: string) => db.runtime.database.query(text);

describe.skipIf(!url)('runtime role', () => {
  it('may append and erase, and nothing else', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);

    await asRt(
      t,
      "insert into audit_events (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible, after) values ('human','u1','U','x.y','t','1','success','standard',true,'{\"a\":1}')",
    );
    await expect(asRt(t, "update audit_events set actor_display = 'x'")).rejects.toThrow(
      /permission denied/,
    );
    await expect(asRt(t, 'delete from audit_events')).rejects.toThrow(/permission denied/);
    await expect(asRt(t, 'truncate audit_events')).rejects.toThrow(/permission denied/);
    const erased = await asRt(t, "select audit_erase_person('u1', 'Erased', null) as n");
    expect(Number(erased[0]?.n)).toBe(1);
    const [row] = await asRt(t, 'select actor_display, after from audit_events');
    expect(row).toMatchObject({ actor_display: 'Erased', after: { erased: true } });
  });

  it('may seal a pending erasure and take the chain lock, but still not update directly', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);

    // pg_advisory_xact_lock: no grant needed, available to any role by default.
    await asRt(t, "select pg_advisory_xact_lock(hashtextextended('x', 0))");

    const hash64 = (c: string) => c.repeat(64);
    await asRt(
      t,
      `insert into audit_events (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible, row_hash, content_hash, content_salt) values ('human','u1','U','x.y','t','1','success','standard',true,'${hash64('a')}','${hash64('b')}','${hash64('c')}')`,
    );
    await expect(
      asRt(t, `update audit_events set content_salt = null, erasure_hash = '${hash64('f')}'`),
    ).rejects.toThrow(/permission denied/);

    const erased = await asRt(t, "select audit_erase_person('u1', 'Erased', null) as n");
    expect(Number(erased[0]?.n)).toBe(1);

    // 0005_rls.sql's two doors, which read past a tenant scope.
    const [tail] = await asRt(t, 'select audit_chain_tail() as h');
    expect(tail?.h).toBe(hash64('a'));
    const pendingRows = await asRt(t, 'select id from audit_pending_erasures()');
    expect(pendingRows).toHaveLength(1);

    const [id] = await asRt(t, 'select id from audit_events');
    await asRt(t, `select audit_seal_erasure(${id?.id}, '${hash64('f')}')`);
    const [row] = await asRt(t, 'select content_salt, erasure_hash from audit_events');
    expect(row).toMatchObject({ content_salt: null, erasure_hash: hash64('f') });
  });
});
