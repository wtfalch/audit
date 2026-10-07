import { type KeyObject, generateKeyPairSync, sign } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { runMigrationSources } from '@wtfalch/db/migrate';
import { createPgliteDatabase } from '@wtfalch/db/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  type Checkpoint,
  type CheckpointSigner,
  type SigningKey,
  proveConsistency,
  proveInclusion,
  retireSigningKey,
  sealCheckpoint,
  verifyCheckpoint,
  verifyConsistency,
  verifyInclusion,
} from './checkpoint.js';
import { foldFrontier } from './merkle.js';
import { tables } from './tables.js';
import { insertLeaves, installChainV2Standin } from './test/chain-v2-standin.js';
import { type TestDb, sources, testDb } from './test/db.js';
import { mth, rowHashOf } from './test/rfc6962.js';

let t: TestDb;

beforeAll(async () => {
  t = await testDb();
  await installChainV2Standin(t.exec);
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  await t.exec(`
    alter table audit_events disable trigger all;
    alter table audit_checkpoints disable trigger all;
    alter table audit_signing_keys disable trigger all;
    delete from audit_checkpoints;
    delete from audit_signing_keys;
    delete from audit_events;
    alter table audit_events enable trigger all;
    alter table audit_checkpoints enable trigger all;
    alter table audit_signing_keys enable trigger all;
  `);
});

function newSigner(): CheckpointSigner & { privateKey: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKey: spki.subarray(spki.length - 32).toString('hex'),
    privateKey,
    sign: async (message) => new Uint8Array(sign(null, message, privateKey)),
  };
}

const rootOf = (n: number) =>
  mth(Array.from({ length: n }, (_, i) => Buffer.from(rowHashOf(i), 'hex'))).toString('hex');
const count = async (table: string) =>
  Number((await t.query(`select count(*) as n from ${table}`))[0]?.n);
const keysOf = async (): Promise<SigningKey[]> =>
  (await t.query('select public_key, created_at, retired_at from audit_signing_keys')).map((r) => ({
    public_key: r.public_key as string,
    created_at: (r.created_at as Date).toISOString(),
    retired_at: r.retired_at === null ? null : (r.retired_at as Date).toISOString(),
  }));

describe('sealCheckpoint', () => {
  it('seals every row into a signed checkpoint over the independent RFC 6962 root', async () => {
    const signer = newSigner();
    await insertLeaves(t.exec, 1, 5);
    const c = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
    expect(c).toMatchObject({
      v: 1,
      ledger: 'app',
      tree_size: 5,
      root: rootOf(5),
      prev_checkpoint: null,
      public_key: signer.publicKey,
    });
    expect(c.checkpoint_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(c.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(await verifyCheckpoint(c, await keysOf())).toBe(true);
    const [row] = await t.query('select tree_size, root, created_at from audit_checkpoints');
    expect(Number(row?.tree_size)).toBe(5);
    expect((row?.created_at as Date).toISOString()).toBe(c.created_at);
  });

  it('chains a second seal to the first and extends the cumulative tree', async () => {
    const signer = newSigner();
    await insertLeaves(t.exec, 1, 3);
    const first = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
    await insertLeaves(t.exec, 4, 7);
    const second = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
    expect(second.prev_checkpoint).toBe(first.checkpoint_hash);
    expect(second.tree_size).toBe(7);
    expect(second.root).toBe(rootOf(7));
    expect(await verifyCheckpoint(second, await keysOf())).toBe(true);
  });

  it('stores a frontier with one root per set bit that folds to the root', async () => {
    await insertLeaves(t.exec, 1, 11);
    const c = (await sealCheckpoint(t.db, { ledger: 'app', signer: newSigner() })) as Checkpoint;
    const [row] = await t.query('select frontier from audit_checkpoints');
    const frontier = row?.frontier as string[];
    expect(frontier).toHaveLength(3); // 11 = 0b1011
    expect(await foldFrontier(frontier)).toBe(c.root);
  });

  it('returns null and writes nothing when no row is new', async () => {
    const signer = newSigner();
    expect(await sealCheckpoint(t.db, { ledger: 'app', signer })).toBeNull();
    expect(await count('audit_checkpoints')).toBe(0);
    expect(await count('audit_signing_keys')).toBe(0);
    await insertLeaves(t.exec, 1, 2);
    await sealCheckpoint(t.db, { ledger: 'app', signer });
    expect(await sealCheckpoint(t.db, { ledger: 'app', signer })).toBeNull();
    expect(await count('audit_checkpoints')).toBe(1);
  });

  it('registers a key once, however many checkpoints it signs', async () => {
    const signer = newSigner();
    await insertLeaves(t.exec, 1, 1);
    await sealCheckpoint(t.db, { ledger: 'app', signer });
    await insertLeaves(t.exec, 2, 2);
    await sealCheckpoint(t.db, { ledger: 'app', signer });
    expect(await count('audit_checkpoints')).toBe(2);
    expect((await keysOf()).map((k) => k.public_key)).toEqual([signer.publicKey]);
  });

  it('refuses a ledger name that differs from the previous checkpoint, writing nothing', async () => {
    const signer = newSigner();
    await insertLeaves(t.exec, 1, 1);
    await sealCheckpoint(t.db, { ledger: 'app', signer });
    await insertLeaves(t.exec, 2, 2);
    await expect(sealCheckpoint(t.db, { ledger: 'other', signer })).rejects.toThrow(
      'ledger name differs',
    );
    expect(await count('audit_checkpoints')).toBe(1);
  });

  it('refuses a retired key and writes nothing', async () => {
    const signer = newSigner();
    await insertLeaves(t.exec, 1, 1);
    await sealCheckpoint(t.db, { ledger: 'app', signer });
    await retireSigningKey(t.db, signer.publicKey);
    await insertLeaves(t.exec, 2, 2);
    await expect(sealCheckpoint(t.db, { ledger: 'app', signer })).rejects.toThrow('retired');
    expect(await count('audit_checkpoints')).toBe(1);
    // A new key carries on the chain.
    const next = (await sealCheckpoint(t.db, { ledger: 'app', signer: newSigner() })) as Checkpoint;
    expect(next.tree_size).toBe(2);
    expect(await count('audit_signing_keys')).toBe(2);
  });

  it('writes nothing when the signer returns a signature that does not verify', async () => {
    const good = newSigner();
    const liar: CheckpointSigner = {
      publicKey: good.publicKey,
      sign: async () => new Uint8Array(64),
    };
    await insertLeaves(t.exec, 1, 2);
    await expect(sealCheckpoint(t.db, { ledger: 'app', signer: liar })).rejects.toThrow(
      'does not verify',
    );
    // A real signature from a different key than the one announced fails too.
    const other = newSigner();
    const impostor: CheckpointSigner = { publicKey: good.publicKey, sign: other.sign };
    await expect(sealCheckpoint(t.db, { ledger: 'app', signer: impostor })).rejects.toThrow(
      'does not verify',
    );
    expect(await count('audit_checkpoints')).toBe(0);
    expect(await count('audit_signing_keys')).toBe(0);
  });

  it('throws on a gap in seq and writes nothing', async () => {
    await insertLeaves(t.exec, 1, 2);
    await insertLeaves(t.exec, 4, 4);
    await expect(sealCheckpoint(t.db, { ledger: 'app', signer: newSigner() })).rejects.toThrow(
      'gap in seq',
    );
    expect(await count('audit_checkpoints')).toBe(0);
    expect(await count('audit_signing_keys')).toBe(0);
  });

  it('refuses a malformed public key before touching the database', async () => {
    const signer = { ...newSigner(), publicKey: 'AB'.repeat(32) };
    await expect(sealCheckpoint(t.db, { ledger: 'app', signer })).rejects.toThrow('64 lower-case');
  });
});

describe('verifyCheckpoint', () => {
  async function sealed() {
    const signer = newSigner();
    await insertLeaves(t.exec, 1, 4);
    const c = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
    return { c, keys: await keysOf(), signer };
  }

  it('fails when any signed field, the signature or the key changes', async () => {
    const { c, keys } = await sealed();
    expect(await verifyCheckpoint(c, keys)).toBe(true);
    expect(await verifyCheckpoint({ ...c, root: '00'.repeat(32) }, keys)).toBe(false);
    expect(await verifyCheckpoint({ ...c, tree_size: 5 }, keys)).toBe(false);
    expect(await verifyCheckpoint({ ...c, ledger: 'other' }, keys)).toBe(false);
    expect(await verifyCheckpoint({ ...c, prev_checkpoint: '11'.repeat(32) }, keys)).toBe(false);
    expect(await verifyCheckpoint({ ...c, signature: '00'.repeat(64) }, keys)).toBe(false);
    expect(await verifyCheckpoint(c, [])).toBe(false);
  });

  it('fails a checkpoint dated after its key was retired, and one dated before it existed', async () => {
    const { c, keys } = await sealed();
    const at = Date.parse(c.created_at);
    const key = keys[0] as SigningKey;
    const window = (from: number, to: number | null): SigningKey[] => [
      {
        ...key,
        created_at: new Date(from).toISOString(),
        retired_at: to === null ? null : new Date(to).toISOString(),
      },
    ];
    expect(await verifyCheckpoint(c, window(at, at))).toBe(true);
    expect(await verifyCheckpoint(c, window(at - 1000, at + 1000))).toBe(true);
    expect(await verifyCheckpoint(c, window(at - 1000, at - 1))).toBe(false);
    expect(await verifyCheckpoint(c, window(at + 1, null))).toBe(false);
  });

  it('fails after the key is retired through the database, once the checkpoint is dated later', async () => {
    const { c, signer } = await sealed();
    await retireSigningKey(t.db, signer.publicKey);
    const keys = await keysOf();
    expect(keys[0]?.retired_at).not.toBeNull();
    expect(await verifyCheckpoint(c, keys)).toBe(true);
    const late = {
      ...c,
      created_at: new Date(Date.parse(keys[0]?.retired_at as string) + 1).toISOString(),
    };
    expect(await verifyCheckpoint(late, keys)).toBe(false);
  });
});

describe('proofs', () => {
  async function twoCheckpoints() {
    const signer = newSigner();
    await insertLeaves(t.exec, 1, 3);
    const first = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
    await insertLeaves(t.exec, 4, 7);
    const second = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
    return { first, second };
  }

  it('proves each row into the first checkpoint that covers it', async () => {
    const { first, second } = await twoCheckpoints();
    for (let seq = 1; seq <= 7; seq++) {
      const proof = await proveInclusion(t.db, seq);
      const covering = seq <= 3 ? first : second;
      expect(proof).toMatchObject({
        seq,
        leaf_index: seq - 1,
        tree_size: covering.tree_size,
        row_hash: rowHashOf(seq - 1),
        checkpoint: covering,
      });
      expect(await verifyInclusion(proof)).toBe(true);
    }
  });

  it('refuses a row that is not sealed yet, and a seq that is not a positive integer', async () => {
    await twoCheckpoints();
    await insertLeaves(t.exec, 8, 8);
    await expect(proveInclusion(t.db, 8)).rejects.toThrow('row 8 is not sealed');
    await expect(proveInclusion(t.db, 0)).rejects.toThrow('positive integer');
    await expect(proveInclusion(t.db, 1.5)).rejects.toThrow('positive integer');
  });

  it('refuses to prove against rows that no longer hash to the checkpoint root', async () => {
    await twoCheckpoints();
    await t.exec('alter table audit_events disable trigger all');
    await t.exec(`update audit_events set row_hash = '${'ab'.repeat(32)}' where seq = 2`);
    await t.exec('alter table audit_events enable trigger all');
    await expect(proveInclusion(t.db, 1)).rejects.toThrow('do not hash to the checkpoint root');
  });

  it('fails an inclusion proof whose row, path, index, size or root was changed', async () => {
    await twoCheckpoints();
    const proof = await proveInclusion(t.db, 5);
    const flip = (h: string) => (h[0] === '0' ? '1' : '0') + h.slice(1);
    expect(await verifyInclusion({ ...proof, row_hash: flip(proof.row_hash) })).toBe(false);
    expect(await verifyInclusion({ ...proof, leaf_index: 4 + 1, seq: 5 })).toBe(false);
    expect(await verifyInclusion({ ...proof, seq: 6 })).toBe(false);
    expect(await verifyInclusion({ ...proof, tree_size: 8 })).toBe(false);
    expect(await verifyInclusion({ ...proof, audit_path: proof.audit_path.slice(1) })).toBe(false);
    expect(
      await verifyInclusion({
        ...proof,
        audit_path: proof.audit_path.map((x, i) => (i === 0 ? flip(x) : x)),
      }),
    ).toBe(false);
    expect(
      await verifyInclusion({
        ...proof,
        checkpoint: { ...proof.checkpoint, root: flip(proof.checkpoint.root) },
      }),
    ).toBe(false);
  });

  it('proves the first checkpoint is a prefix of the second', async () => {
    const { first, second } = await twoCheckpoints();
    const proof = await proveConsistency(t.db, first.tree_size, second.tree_size);
    expect(proof.from_size).toBe(3);
    expect(proof.to_size).toBe(7);
    expect(await verifyConsistency(proof, first.root, second.root)).toBe(true);
    expect(await verifyConsistency(proof, second.root, first.root)).toBe(false);
    expect(await verifyConsistency({ ...proof, from_size: 2 }, first.root, second.root)).toBe(
      false,
    );
    expect(await verifyConsistency({ ...proof, to_size: 3 }, first.root, second.root)).toBe(false);
    expect(
      await verifyConsistency({ ...proof, nodes: proof.nodes.slice(1) }, first.root, second.root),
    ).toBe(false);
    expect(await proveConsistency(t.db, 7, 7)).toEqual({ from_size: 7, to_size: 7, nodes: [] });
  });

  it('refuses sizes that are not 1 <= from <= to, and a size beyond the chain', async () => {
    await twoCheckpoints();
    await expect(proveConsistency(t.db, 0, 3)).rejects.toThrow('1 <= fromSize <= toSize');
    await expect(proveConsistency(t.db, 4, 3)).rejects.toThrow('1 <= fromSize <= toSize');
    await expect(proveConsistency(t.db, 1, 2.5)).rejects.toThrow('1 <= fromSize <= toSize');
    await expect(proveConsistency(t.db, 1, 8)).rejects.toThrow('fewer rows');
  });
});

describe('append-only tables', () => {
  async function refused(text: string, message: string) {
    await expect(t.exec(text)).rejects.toThrow(message);
  }

  it('refuses update, delete and truncate on audit_checkpoints', async () => {
    await insertLeaves(t.exec, 1, 1);
    await sealCheckpoint(t.db, { ledger: 'app', signer: newSigner() });
    await refused("update audit_checkpoints set ledger = 'x'", 'update refused');
    await refused('delete from audit_checkpoints', 'delete refused');
    await refused('truncate audit_checkpoints', 'truncate refused');
    expect(await count('audit_checkpoints')).toBe(1);
  });

  it('lets a key retire once and refuses every other change', async () => {
    const signer = newSigner();
    await insertLeaves(t.exec, 1, 1);
    await sealCheckpoint(t.db, { ledger: 'app', signer });
    await refused('delete from audit_signing_keys', 'delete refused');
    await refused('truncate audit_signing_keys cascade', 'truncate refused');
    await refused(
      `update audit_signing_keys set created_at = created_at + interval '1 second'`,
      'only retired_at',
    );
    await refused(
      `update audit_signing_keys set retired_at = now(), created_at = created_at + interval '1 second'`,
      'only retired_at',
    );
    await refused(
      `update audit_signing_keys set retired_at = now(), public_key = '${'11'.repeat(32)}'`,
      'only retired_at',
    );
    await retireSigningKey(t.db, signer.publicKey);
    await expect(retireSigningKey(t.db, signer.publicKey)).rejects.toThrow('already retired');
    await refused('update audit_signing_keys set retired_at = null', 'only retired_at');
    await expect(retireSigningKey(t.db, '00'.repeat(32))).rejects.toThrow('unknown');
    await expect(retireSigningKey(t.db, 'nope')).rejects.toThrow('64 lower-case');
  });
});

describe('migration 0008 in a named schema', () => {
  let pglite: PGlite;
  afterAll(async () => {
    await pglite.close();
  });

  it('creates the tables and the function in the schema and seals on a schema-only search_path', async () => {
    pglite = new PGlite();
    await runMigrationSources({
      owner: createPgliteDatabase(pglite),
      schema: 'svc',
      sources,
      log: () => undefined,
    });
    const where = await pglite.query<{ table_schema: string }>(
      `select table_schema from information_schema.tables
        where table_name in ('audit_checkpoints', 'audit_signing_keys') order by 1`,
    );
    expect(where.rows.map((r) => r.table_schema)).toEqual(['svc', 'svc']);
    const fn = await pglite.query<{ schema: string; proconfig: string[] }>(
      `select pronamespace::regnamespace::text as schema, proconfig from pg_proc
        where proname = 'audit_retire_signing_key'`,
    );
    expect(fn.rows).toEqual([{ schema: 'svc', proconfig: ['search_path=svc, public, pg_temp'] }]);

    await pglite.exec('set search_path to svc');
    const exec = (text: string) => pglite.exec(text).then(() => undefined);
    await installChainV2Standin(exec);
    await insertLeaves(exec, 1, 3);
    const signer = newSigner();
    const db = drizzle(pglite, { schema: tables });
    const c = (await sealCheckpoint(db, { ledger: 'app', signer })) as Checkpoint;
    expect(c.root).toBe(rootOf(3));
    await retireSigningKey(db, signer.publicKey);
    const keys = await pglite.query<{ retired_at: unknown }>(
      'select retired_at from audit_signing_keys',
    );
    expect(keys.rows[0]?.retired_at).not.toBeNull();
  });
});
