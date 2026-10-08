import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { anchorCheckpoints } from './anchor.js';
import { retireSigningKey, sealCheckpoint } from './checkpoint.js';
import { createLedger } from './ledger.js';
import { CORE, type RuntimeRoleDb, withRuntimeRole } from './test/db.js';
import { fakeTsa } from './test/tsa.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

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

  // db 0.5.2 migrates with `<schema>, public, pg_temp`. Before that, a
  // `set search_path from current` function froze a path without pg_temp, so a
  // temp table of the runtime role shadowed the function's table.
  it('freezes pg_temp last on every security definer function in the schema', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    const rows = await t.owner.database.query<{ proname: string; proconfig: string[] | null }>(
      `select proname, proconfig from pg_proc
        where prosecdef and pronamespace = '${t.schema}'::regnamespace order by 1`,
    );
    expect(rows.map((row) => row.proname)).toEqual([
      'audit_chain_leaves',
      'audit_chain_tail',
      'audit_chain_tail_v2',
      'audit_erase_person',
      'audit_events_refuse_v1',
      'audit_pending_erasures',
      'audit_retire_signing_key',
      'audit_seal_erasure',
    ]);
    for (const row of rows) {
      const path = (row.proconfig ?? []).find((entry) => entry.startsWith('search_path='));
      expect(path?.split(',').at(-1)?.trim(), row.proname).toBe('pg_temp');
    }
  });

  it("is not shadowed by the runtime role's own temp table", async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    const hash64 = (c: string) => c.repeat(64);
    await asRt(
      t,
      `insert into audit_events (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible, row_hash, content_hash, content_salt) values ('human','u1','U','x.y','t','1','success','standard',true,'${hash64('a')}','${hash64('b')}','${hash64('c')}')`,
    );
    const seen = await t.runtime.database.transaction(async (tx) => {
      // The same name, first on the path: an empty copy of the real table.
      await tx.query('create temp table audit_events (like audit_events including defaults)');
      const erased = await tx.query("select audit_erase_person('u1', 'Erased', null) as n");
      const tail = await tx.query('select audit_chain_tail() as h');
      return { erased: Number(erased[0]?.n), tail: tail[0]?.h };
    });
    expect(seen).toEqual({ erased: 1, tail: hash64('a') });
    const [row] = await t.owner.database.query('select actor_display from audit_events');
    expect(row).toMatchObject({ actor_display: 'Erased' });
  });

  it('may sign, seal, retire a key and anchor through the grants a host passes, and change none of it afterwards', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    const ledger = createLedger({
      vocabulary: ledgerVocabularyFromCore(CORE, {}),
      hashChain: true,
      checkRuntimeRole: false,
    });
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const spki = publicKey.export({ format: 'der', type: 'spki' });
    const signer = {
      publicKey: spki.subarray(spki.length - 32).toString('hex'),
      sign: async (message: Uint8Array) => new Uint8Array(nodeSign(null, message, privateKey)),
    };
    await ledger.sign(t.runtimeDb, {
      action: 'tenant.created',
      tenantId: null,
      actor: { class: 'human', id: 'u1', display: 'U' },
      context: 'standard',
      target: { type: 'tenant', id: 't1' },
    });
    const checkpoint = await sealCheckpoint(t.runtimeDb, { ledger: 'app', signer });
    expect(checkpoint?.tree_size).toBe(1);
    const tsa = await fakeTsa();
    try {
      expect(
        await anchorCheckpoints(t.runtimeDb, {
          tsaUrl: 'https://tsa.test/ts',
          provider: 'fake',
          fetch: tsa.fetch,
        }),
      ).toBe(1);
    } finally {
      await tsa.close();
    }
    await retireSigningKey(t.runtimeDb, signer.publicKey);
    for (const [table, column] of [
      ['audit_checkpoints', 'created_at'],
      ['audit_signing_keys', 'created_at'],
      ['audit_anchors', 'anchored_at'],
    ]) {
      await expect(asRt(t, `update ${table} set ${column} = ${column}`)).rejects.toThrow(
        /permission denied/,
      );
      await expect(asRt(t, `delete from ${table}`)).rejects.toThrow(/permission denied/);
      await expect(asRt(t, `truncate ${table}`)).rejects.toThrow(/permission denied/);
    }
  }, 30_000);
});
