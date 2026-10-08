import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { canonicalJsonV2 } from './canonical.js';
import {
  type Checkpoint,
  type CheckpointSigner,
  type SigningKey,
  proveConsistency,
  proveInclusion,
  retireSigningKey,
  sealCheckpoint,
  verifyCheckpoint,
} from './checkpoint.js';
import { type TestDb, insertLeaves, testDb } from './test/db.js';
import { mth } from './test/rfc6962.js';

/** Guards of checkpoint.ts that the main test file leaves to other checks. */
let t: TestDb;
beforeAll(async () => {
  t = await testDb();
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  const off = ['audit_events', 'audit_checkpoints', 'audit_signing_keys'];
  for (const table of off) await t.exec(`alter table ${table} disable trigger all`);
  await t.exec(
    'delete from audit_checkpoints; delete from audit_signing_keys; delete from audit_events',
  );
  for (const table of off) await t.exec(`alter table ${table} enable trigger all`);
});

const pair = generateKeyPairSync('ed25519');
const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
const publicKey = spki.subarray(spki.length - 32).toString('hex');
const signer: CheckpointSigner = {
  publicKey,
  sign: async (message) => new Uint8Array(sign(null, message, pair.privateKey)),
};
const slowSigner = (ms: number): CheckpointSigner => ({
  publicKey,
  sign: async (message) => {
    await new Promise((resolve) => setTimeout(resolve, ms));
    return new Uint8Array(sign(null, message, pair.privateKey));
  },
});
const count = async (table: string) =>
  Number((await t.query(`select count(*) as n from ${table}`))[0]?.n);

describe('verifyCheckpoint on a checkpoint that is signed but malformed', () => {
  const key: SigningKey = {
    public_key: publicKey,
    created_at: '2000-01-01T00:00:00.000Z',
    retired_at: null,
  };
  const good = {
    ledger: 'app',
    tree_size: 4,
    root: '0a'.repeat(32),
    prev_checkpoint: null as string | null,
    created_at: '2026-10-03T00:00:00.000Z',
  };
  /** Hashes and signs exactly the fields given, so only the shape is wrong. */
  function signed(over: Record<string, unknown> = {}, bodyOver: Record<string, unknown> = {}) {
    const body = { ...good, ...bodyOver };
    const hash = createHash('sha256')
      .update(canonicalJsonV2({ v: 1, ...body }))
      .digest('hex');
    const signature = sign(null, Buffer.from(hash, 'hex'), pair.privateKey).toString('hex');
    return {
      v: 1,
      ...body,
      checkpoint_hash: hash,
      signature,
      public_key: publicKey,
      ...over,
    } as unknown as Checkpoint;
  }

  it('accepts the unspoiled one (so each case below fails for its one field)', async () => {
    expect(await verifyCheckpoint(signed(), [key])).toBe(true);
  });

  it('refuses a v other than 1, which the hash does not cover', async () => {
    expect(await verifyCheckpoint(signed({ v: 2 }), [key])).toBe(false);
  });

  it.each([
    ['an upper-case root', { root: 'AB'.repeat(32) }],
    ['a short root', { root: 'ab' }],
    ['a malformed prev_checkpoint', { prev_checkpoint: 'zz' }],
    ['a tree size of 0', { tree_size: 0 }],
    ['a fractional tree size', { tree_size: 1.5 }],
    ['a created_at without milliseconds', { created_at: '2026-10-03T00:00:00Z' }],
    ['a created_at that is not a date', { created_at: 'yesterday' }],
  ])('refuses %s, though hash and signature are right for it', async (_name, body) => {
    // canonicalJsonV2 refuses 1.5, so that case cannot be hashed: sign over 1 and claim 1.5.
    if ('tree_size' in body && body.tree_size === 1.5) {
      expect(await verifyCheckpoint(signed({ tree_size: 1.5 }), [key])).toBe(false);
      return;
    }
    expect(await verifyCheckpoint(signed({}, body), [key])).toBe(false);
  });

  it('answers false, not an error, for a signature or key that is not hex of the right length', async () => {
    expect(await verifyCheckpoint(signed({ signature: 'zz' }), [key])).toBe(false);
    const odd: SigningKey = { ...key, public_key: 'ab' };
    expect(await verifyCheckpoint(signed({ public_key: 'ab' }), [odd])).toBe(false);
  });
});

describe('sealCheckpoint guards', () => {
  it('refuses an empty ledger name and one past 256 characters, and takes 256', async () => {
    await insertLeaves(t.exec, 1, 1);
    await expect(sealCheckpoint(t.db, { ledger: '', signer })).rejects.toThrow(
      'ledger name must be 1 to 256 characters',
    );
    await expect(sealCheckpoint(t.db, { ledger: 'x'.repeat(257), signer })).rejects.toThrow(
      'ledger name must be 1 to 256 characters',
    );
    expect(await sealCheckpoint(t.db, { ledger: 'x'.repeat(256), signer })).not.toBeNull();
  });

  it('seals more rows than one read page holds, in one checkpoint with the right root', async () => {
    const rows = 5001;
    await t.exec(`
      insert into audit_events
        (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context,
         tenant_visible, chain_version, seq, received_at, row_hash)
      select 'human', 'u', 'U', 'a.b', 't', 'x', 'success', 'standard', false, 2, n, now(),
             encode(sha256(convert_to('r' || n::text, 'utf8')), 'hex')
        from generate_series(1, ${rows}) n`);
    const cp = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
    const hashes = (await t.query('select row_hash from audit_events order by seq')).map((r) =>
      Buffer.from(String(r.row_hash), 'hex'),
    );
    expect(cp.tree_size).toBe(rows);
    expect(cp.root).toBe(mth(hashes).toString('hex'));
  });
});

describe('the chain lock', () => {
  it('two seals at once make one checkpoint and the other finds nothing new', async () => {
    if (!t.real) return; // one connection serialises them on PGlite; the lock is a real-server matter
    await insertLeaves(t.exec, 1, 3);
    const results = await Promise.all([
      sealCheckpoint(t.db, { ledger: 'app', signer: slowSigner(250) }),
      sealCheckpoint(t.db, { ledger: 'app', signer: slowSigner(250) }),
    ]);
    expect(results.filter((r) => r !== null)).toHaveLength(1);
    expect(await count('audit_checkpoints')).toBe(1);
  });

  it('a retirement waits for a seal in flight, so that seal is not refused and not signed after it', async () => {
    if (!t.real) return;
    await insertLeaves(t.exec, 1, 2);
    await sealCheckpoint(t.db, { ledger: 'app', signer });
    await insertLeaves(t.exec, 3, 4);
    const sealing = sealCheckpoint(t.db, { ledger: 'app', signer: slowSigner(400) });
    await new Promise((resolve) => setTimeout(resolve, 100));
    await retireSigningKey(t.db, publicKey);
    const cp = await sealing;
    expect(cp?.tree_size).toBe(4);
    const [key] = await t.query('select created_at, retired_at from audit_signing_keys');
    // The checkpoint committed before the key was retired, so it is inside the window.
    expect((cp as Checkpoint).created_at <= (key?.retired_at as Date).toISOString()).toBe(true);
  });
});

describe('proofs read the chain again', () => {
  it('a gap in seq under a sealed range is refused by a consistency proof too', async () => {
    await insertLeaves(t.exec, 1, 3);
    await sealCheckpoint(t.db, { ledger: 'app', signer });
    await t.exec('alter table audit_events disable trigger all');
    await t.exec('delete from audit_events where seq = 2');
    await insertLeaves(t.exec, 4, 4);
    await t.exec('alter table audit_events enable trigger all');
    await expect(proveConsistency(t.db, 1, 3)).rejects.toThrow('gap in seq');
    await expect(proveInclusion(t.db, 1)).rejects.toThrow();
  });

  it('a proof over rows the chain does not have loops no further than the first empty read', async () => {
    let reads = 0;
    const empty = {
      execute: async () => {
        reads += 1;
        if (reads > 3) throw new Error('read again after an empty page');
        return { rows: [] };
      },
    };
    await expect(proveConsistency(empty as never, 1, 8)).rejects.toThrow('fewer rows');
    expect(reads).toBe(1);
  });
});
