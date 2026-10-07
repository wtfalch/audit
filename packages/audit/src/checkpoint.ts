import { asc, desc, eq, sql } from 'drizzle-orm';
import { auditCheckpoints, auditSigningKeys } from './checkpoint-tables.js';
import type { AuditCheckpointRow } from './checkpoint-tables.js';
import type { Handle } from './ledger.js';
import { appendLeaf, foldFrontier, fromHex, isHash, leafHash, sha256, toHex } from './merkle.js';
import { resultRows } from './sql-result.js';

/**
 * Signed Merkle checkpoints. `sealCheckpoint` folds every row sealed since the
 * last checkpoint into one cumulative tree (leaf `i` is the row with
 * `seq = i + 1`, merkle.ts), hashes the tree's root with the ledger's name and
 * the link to the previous checkpoint, and has the host's signer sign that
 * hash. The database keeps the checkpoints and the keys that signed them
 * (migrations/0008_checkpoints.sql); a verifier trusts only the keys it is
 * handed.
 */

// TEMP: replace with import from ./canonical.js at integration
// RFC 8785, restricted: null, booleans, safe integers, well-formed strings,
// arrays, and objects with keys sorted by UTF-16 code units. Anything else throws.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
function canonicalJsonV2(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value))
      throw new Error('canonical json: number is not a safe integer');
    return JSON.stringify(value === 0 ? 0 : value);
  }
  if (typeof value === 'string') {
    if (LONE_SURROGATE.test(value)) throw new Error('canonical json: string is not well formed');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJsonV2).join(',')}]`;
  if (typeof value === 'object' && value !== undefined) {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    return `{${entries.map(([k, v]) => `${canonicalJsonV2(k)}:${canonicalJsonV2(v)}`).join(',')}}`;
  }
  throw new Error('canonical json: value cannot be written');
}

// TEMP: replace with the export from ./ledger.js at integration
const CHAIN_LOCK_NAME = 'wtfalch/audit chain';

/** Leaves read per query while sealing. */
const LEAF_PAGE = 5000;

/** The host's signer. The private key stays inside it; the ledger only ever sees the public key and signatures. */
export interface CheckpointSigner {
  /** The raw 32-byte Ed25519 public key, 64 lower-case hex characters. */
  readonly publicKey: string;
  /** Signs the message and returns the 64-byte Ed25519 signature. */
  sign(message: Uint8Array<ArrayBuffer>): Promise<Uint8Array>;
}

export interface Checkpoint {
  v: 1;
  ledger: string;
  tree_size: number;
  root: string;
  prev_checkpoint: string | null;
  /** `Date#toISOString()`: UTC, milliseconds. */
  created_at: string;
  checkpoint_hash: string;
  /** Ed25519 over the 32 raw bytes of `checkpoint_hash`, 128 hex. */
  signature: string;
  public_key: string;
}

/** A signing key and the window it may sign in. Timestamps are ISO strings. */
export interface SigningKey {
  public_key: string;
  created_at: string;
  retired_at: string | null;
}

async function sha256Hex(text: string): Promise<string> {
  return toHex(await sha256(new TextEncoder().encode(text)));
}

function checkpointHash(
  c: Pick<Checkpoint, 'ledger' | 'tree_size' | 'root' | 'prev_checkpoint' | 'created_at'>,
) {
  return sha256Hex(
    canonicalJsonV2({
      v: 1,
      ledger: c.ledger,
      tree_size: c.tree_size,
      root: c.root,
      prev_checkpoint: c.prev_checkpoint,
      created_at: c.created_at,
    }),
  );
}

async function ed25519Verify(
  publicKey: string,
  signature: string,
  message: Uint8Array<ArrayBuffer>,
) {
  if (!/^[0-9a-f]{64}$/.test(publicKey) || !/^[0-9a-f]{128}$/.test(signature)) return false;
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    fromHex(publicKey),
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  return globalThis.crypto.subtle.verify({ name: 'Ed25519' }, key, fromHex(signature), message);
}

/** One page of leaves after `afterSeq`, through `audit_chain_leaves` (security definer: sees every tenant's rows). */
export async function readLeaves(
  handle: Handle,
  afterSeq: number,
  maxRows = LEAF_PAGE,
): Promise<{ seq: number; row_hash: string }[]> {
  const rows = resultRows<{ seq: unknown; row_hash: unknown }>(
    await handle.execute(
      sql`select seq, row_hash from audit_chain_leaves(${afterSeq}::bigint, ${maxRows}::int)`,
    ),
  );
  return rows.map((row) => {
    const seq = Number(row.seq);
    if (!Number.isSafeInteger(seq) || !isHash(row.row_hash))
      throw new Error('audit_chain_leaves returned a malformed leaf');
    return { seq, row_hash: row.row_hash };
  });
}

function toCheckpoint(row: AuditCheckpointRow): Checkpoint {
  return {
    v: 1,
    ledger: row.ledger,
    tree_size: row.treeSize,
    root: row.root,
    prev_checkpoint: row.prevCheckpoint,
    created_at: row.createdAt.toISOString(),
    checkpoint_hash: row.checkpointHash,
    signature: row.signature,
    public_key: row.publicKey,
  };
}

/**
 * Seals every row since the last checkpoint into a new one, or returns null
 * when there is no new row. One transaction holding the chain's advisory lock,
 * so `sign()` waits while a seal runs and two seals never interleave; the
 * signer is called inside it, so a slow signer holds the lock. A failure at
 * any point (a signer that throws or returns a bad signature, a gap in `seq`,
 * a retired key) rolls the transaction back and leaves nothing behind: no
 * checkpoint, no key row. The handle must see every row through
 * `audit_chain_leaves`, which is security definer, so a runtime role may call it.
 */
export async function sealCheckpoint(
  handle: Handle,
  options: { ledger: string; signer: CheckpointSigner },
): Promise<Checkpoint | null> {
  const { ledger, signer } = options;
  if (ledger.length < 1 || ledger.length > 256)
    throw new Error('ledger name must be 1 to 256 characters');
  if (!isHash(signer.publicKey) || !/^[0-9a-f]{64}$/.test(signer.publicKey))
    throw new Error('signer.publicKey must be 64 lower-case hex characters');
  return handle.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${CHAIN_LOCK_NAME}, 0))`);
    const [last] = await tx
      .select()
      .from(auditCheckpoints)
      .orderBy(desc(auditCheckpoints.treeSize))
      .limit(1);
    if (last && last.ledger !== ledger)
      throw new Error('ledger name differs from the previous checkpoint');
    let size = last?.treeSize ?? 0;
    let frontier = last ? [...last.frontier] : [];
    for (;;) {
      const page = await readLeaves(tx, size);
      for (const leaf of page) {
        if (leaf.seq !== size + 1) throw new Error('the chain has a gap in seq');
        frontier = await appendLeaf(frontier, size, await leafHash(leaf.row_hash));
        size++;
      }
      if (page.length < LEAF_PAGE) break;
    }
    if (size === (last?.treeSize ?? 0)) return null;

    const root = await foldFrontier(frontier);
    const created = new Date();
    const body = {
      ledger,
      tree_size: size,
      root,
      prev_checkpoint: last?.checkpointHash ?? null,
      created_at: created.toISOString(),
    };
    const hash = await checkpointHash(body);
    const signature = toHex(await signer.sign(fromHex(hash)));
    if (!(await ed25519Verify(signer.publicKey, signature, fromHex(hash))))
      throw new Error('the signer returned a signature that does not verify');

    const [key] = await tx
      .select()
      .from(auditSigningKeys)
      .where(eq(auditSigningKeys.publicKey, signer.publicKey));
    if (key?.retiredAt) throw new Error('the signing key is retired');
    if (!key)
      await tx.insert(auditSigningKeys).values({ publicKey: signer.publicKey, createdAt: created });

    await tx.insert(auditCheckpoints).values({
      v: 1,
      ledger,
      treeSize: size,
      root,
      prevCheckpoint: body.prev_checkpoint,
      createdAt: created,
      checkpointHash: hash,
      signature,
      publicKey: signer.publicKey,
      frontier,
    });
    return { v: 1, ...body, checkpoint_hash: hash, signature, public_key: signer.publicKey };
  });
}

/** Retires a signing key: sealing with it is refused from now on, and a checkpoint dated after this instant no longer verifies. Throws on an unknown or already retired key. */
export async function retireSigningKey(handle: Handle, publicKey: string): Promise<void> {
  if (!/^[0-9a-f]{64}$/.test(publicKey))
    throw new Error('public key must be 64 lower-case hex characters');
  await handle.transaction(async (tx) => {
    // Behind any seal in flight, so a checkpoint is never signed by a key retired before it commits.
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${CHAIN_LOCK_NAME}, 0))`);
    await tx.execute(sql`select audit_retire_signing_key(${publicKey})`);
  });
}

/**
 * Is this checkpoint what its key signed, inside the key's window? Checks the
 * hash over its fields, the signature, and that `created_at` lies in
 * `[created_at, retired_at]` of the matching key in `keys`. It does not check
 * the root against any rows or the link to a previous checkpoint.
 */
export async function verifyCheckpoint(
  checkpoint: Checkpoint,
  keys: readonly SigningKey[],
): Promise<boolean> {
  const c = checkpoint;
  if (c.v !== 1 || !isHash(c.root) || !isHash(c.checkpoint_hash)) return false;
  if (c.prev_checkpoint !== null && !isHash(c.prev_checkpoint)) return false;
  if (typeof c.ledger !== 'string' || !Number.isSafeInteger(c.tree_size) || c.tree_size < 1)
    return false;
  const at = Date.parse(c.created_at);
  if (Number.isNaN(at) || new Date(at).toISOString() !== c.created_at) return false;
  const key = keys.find((k) => k.public_key === c.public_key);
  if (!key) return false;
  if (at < Date.parse(key.created_at)) return false;
  if (key.retired_at !== null && at > Date.parse(key.retired_at)) return false;
  if ((await checkpointHash(c)) !== c.checkpoint_hash) return false;
  return ed25519Verify(c.public_key, c.signature, fromHex(c.checkpoint_hash));
}

/** The checkpoints, oldest first. */
export async function listCheckpoints(handle: Handle): Promise<Checkpoint[]> {
  const rows = await handle.select().from(auditCheckpoints).orderBy(asc(auditCheckpoints.treeSize));
  return rows.map(toCheckpoint);
}
