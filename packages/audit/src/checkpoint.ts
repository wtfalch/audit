import { asc, desc, eq, gte, sql } from 'drizzle-orm';
import { canonicalJsonV2 } from './canonical.js';
import { auditCheckpoints, auditSigningKeys } from './checkpoint-tables.js';
import type { AuditCheckpointRow } from './checkpoint-tables.js';
import { type AuditEnvironment, assertProduction } from './environment.js';
import { CHAIN_LOCK_NAME, type Handle } from './ledger.js';
import {
  appendLeaf,
  consistencyNodes,
  foldFrontier,
  fromHex,
  inclusionPath,
  isHash,
  leafHash,
  merkleRoot,
  sha256,
  toHex,
  verifyConsistencyNodes,
  verifyInclusionPath,
} from './merkle.js';
import { resultRows } from './sql-result.js';
import { verifyTable } from './verify-table.js';

/**
 * Signed Merkle checkpoints. `sealCheckpoint` folds every row sealed since the
 * last checkpoint into one cumulative tree (leaf `i` is the row with
 * `seq = i + 1`, merkle.ts), hashes the tree's root with the ledger's name and
 * the link to the previous checkpoint, and has the host's signer sign that
 * hash. The database keeps the checkpoints and the keys that signed them
 * (migrations/0008_checkpoints.sql); a verifier trusts only the keys it is
 * handed.
 */

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
async function readLeaves(
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
  options: { ledger: string; signer: CheckpointSigner; environment?: AuditEnvironment },
): Promise<Checkpoint | null> {
  const { ledger, signer } = options;
  assertProduction(options.environment, 'sealing a checkpoint');
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
    if (last && last.frontier.length === 0)
      throw new Error('the last checkpoint is a remote seal; this ledger is sealed remotely');
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

export interface InclusionProof {
  seq: number;
  /** `seq - 1`. */
  leaf_index: number;
  /** The tree size of `checkpoint`. */
  tree_size: number;
  row_hash: string;
  /** Sibling hashes from the leaf up to the root, hex. */
  audit_path: string[];
  checkpoint: Checkpoint;
}

export interface ConsistencyProof {
  from_size: number;
  to_size: number;
  nodes: string[];
}

/** The leaf hashes of rows `1..upTo`, read again from the database: no tree nodes are stored. */
async function readLeafHashes(handle: Handle, upTo: number): Promise<string[]> {
  const hashes: string[] = [];
  while (hashes.length < upTo) {
    const page = await readLeaves(handle, hashes.length, Math.min(LEAF_PAGE, upTo - hashes.length));
    if (page.length === 0) throw new Error('the chain has fewer rows than the proof needs');
    for (const leaf of page) {
      if (leaf.seq !== hashes.length + 1) throw new Error('the chain has a gap in seq');
      hashes.push(await leafHash(leaf.row_hash));
    }
  }
  return hashes;
}

/**
 * The path from row `seq` to the root of the first checkpoint that covers it.
 * Throws when no checkpoint does yet, or when the rows no longer hash to that
 * checkpoint's root. Reads every leaf up to the checkpoint's size.
 */
export async function proveInclusion(handle: Handle, seq: number): Promise<InclusionProof> {
  if (!Number.isSafeInteger(seq) || seq < 1) throw new Error('seq must be a positive integer');
  const [row] = await handle
    .select()
    .from(auditCheckpoints)
    .where(gte(auditCheckpoints.treeSize, seq))
    .orderBy(asc(auditCheckpoints.treeSize))
    .limit(1);
  if (!row) throw new Error(`row ${seq} is not sealed in a checkpoint yet`);
  const leaves = await readLeafHashes(handle, row.treeSize);
  if ((await merkleRoot(leaves)) !== row.root)
    throw new Error('the rows do not hash to the checkpoint root');
  const rows = await readLeaves(handle, seq - 1, 1);
  return {
    seq,
    leaf_index: seq - 1,
    tree_size: row.treeSize,
    row_hash: (rows[0] as { row_hash: string }).row_hash,
    audit_path: await inclusionPath(leaves, seq - 1),
    checkpoint: toCheckpoint(row),
  };
}

/** Does the path take the row's hash to `checkpoint.root`? Checks the path only; `verifyCheckpoint` checks the checkpoint. */
export async function verifyInclusion(proof: InclusionProof): Promise<boolean> {
  const { seq, leaf_index, tree_size, row_hash, audit_path, checkpoint } = proof;
  if (!isHash(row_hash) || !Number.isSafeInteger(seq) || leaf_index !== seq - 1) return false;
  if (checkpoint.tree_size !== tree_size) return false;
  return verifyInclusionPath(
    await leafHash(row_hash),
    leaf_index,
    tree_size,
    audit_path,
    checkpoint.root,
  );
}

/** The nodes that prove the tree of the first `fromSize` rows is a prefix of the tree of the first `toSize`. Reads every leaf up to `toSize`. */
export async function proveConsistency(
  handle: Handle,
  fromSize: number,
  toSize: number,
): Promise<ConsistencyProof> {
  if (
    !Number.isSafeInteger(fromSize) ||
    !Number.isSafeInteger(toSize) ||
    fromSize < 1 ||
    fromSize > toSize
  )
    throw new Error('sizes must be integers with 1 <= fromSize <= toSize');
  const leaves = await readLeafHashes(handle, toSize);
  return { from_size: fromSize, to_size: toSize, nodes: await consistencyNodes(leaves, fromSize) };
}

/** Does the proof show the tree with `fromRoot` is a prefix of the tree with `toRoot`? */
export function verifyConsistency(
  proof: ConsistencyProof,
  fromRoot: string,
  toRoot: string,
): Promise<boolean> {
  return verifyConsistencyNodes(proof.from_size, proof.to_size, proof.nodes, fromRoot, toRoot);
}

/** A sealer's request: the ledger's name and the head row's sequence and hash. Nothing else leaves the app. */
export interface SealRequest {
  ledger: string;
  seq: number;
  head_hash: string;
}

/** Asks a sealer outside the app to sign a head. The app holds no signing key. */
export interface RemoteSealer {
  seal(request: SealRequest): Promise<Checkpoint>;
}

export interface RemoteSealerOptions {
  /** The sealing address. */
  url: string;
  /** The app's own credential, sent as a bearer token. */
  credential: string;
  /** Default 10,000. */
  timeoutMs?: number;
  /** Default `globalThis.fetch`. */
  fetch?: typeof globalThis.fetch;
}

/** A seal the client refused to send, or a head it refused to store. */
export class SealRefusal extends Error {
  constructor(
    readonly reason: 'not_extending' | 'bad_response',
    message: string,
  ) {
    super(message);
    this.name = 'SealRefusal';
  }
}

/**
 * A sealer that POSTs the request as JSON to `url` with the credential and
 * expects the signed checkpoint back. A timeout, a non-2xx answer or a body
 * that is not JSON throws; nothing is skipped silently.
 */
export function remoteSealer(options: RemoteSealerOptions): RemoteSealer {
  const { url, credential } = options;
  if (!url) throw new Error('url is required');
  if (!credential) throw new Error('credential is required');
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0)
    throw new Error('timeoutMs must be a positive number');
  const doFetch = options.fetch ?? globalThis.fetch;
  return {
    async seal(request) {
      const response = await doFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${credential}` },
        body: JSON.stringify(request),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new Error(`the sealer answered ${response.status}`);
      return (await response.json()) as Checkpoint;
    },
  };
}

async function chainHead(handle: Handle): Promise<{ seq: number; row_hash: string } | null> {
  const [row] = resultRows<{ seq: unknown; row_hash: unknown }>(
    await handle.execute(sql`select seq, row_hash from audit_chain_tail_v2()`),
  );
  if (!row || row.seq === null || row.seq === undefined) return null;
  const seq = Number(row.seq);
  if (!Number.isSafeInteger(seq) || !isHash(row.row_hash))
    throw new Error('audit_chain_tail_v2 returned a malformed head');
  return { seq, row_hash: row.row_hash };
}

/**
 * Seals the chain's head through a remote sealer, or returns null when the
 * head is already sealed. The stored checkpoint has `tree_size` = the head's
 * `seq`, `root` = the head row's `row_hash` (which commits to every row
 * before it) and an empty frontier. Refused with `SealRefusal`, before
 * anything is sent, when the head does not extend the last sealed head: the
 * row at the last sealed seq must still have the sealed hash and the head
 * must be past it. The answer must verify under `keys`, the sealer's public
 * keys the host trusts, and match the request, or it is not stored. Runs in
 * the advisory-locked transaction, like `sealCheckpoint`.
 */
export async function seal(
  handle: Handle,
  options: {
    ledger: string;
    sealer: RemoteSealer;
    keys: readonly SigningKey[];
    environment?: AuditEnvironment;
  },
): Promise<Checkpoint | null> {
  const { ledger, sealer, keys } = options;
  assertProduction(options.environment, 'sealing a checkpoint');
  if (ledger.length < 1 || ledger.length > 256)
    throw new Error('ledger name must be 1 to 256 characters');
  return handle.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${CHAIN_LOCK_NAME}, 0))`);
    const [last] = await tx
      .select()
      .from(auditCheckpoints)
      .orderBy(desc(auditCheckpoints.treeSize))
      .limit(1);
    if (last && last.ledger !== ledger)
      throw new Error('ledger name differs from the previous checkpoint');
    if (last && last.frontier.length > 0)
      throw new Error('the last checkpoint is a Merkle seal; this ledger is sealed locally');
    const head = await chainHead(tx);
    if (!head) return null;
    if (last) {
      if (head.seq === last.treeSize && head.row_hash === last.root) return null;
      const [sealed] = head.seq < last.treeSize ? [] : await readLeaves(tx, last.treeSize - 1, 1);
      if (
        head.seq <= last.treeSize ||
        sealed?.seq !== last.treeSize ||
        sealed.row_hash !== last.root
      )
        throw new SealRefusal(
          'not_extending',
          `the head (seq ${head.seq}) does not extend the last sealed head (seq ${last.treeSize})`,
        );
    }
    const answer = await sealer.seal({ ledger, seq: head.seq, head_hash: head.row_hash });
    if (
      !answer ||
      answer.ledger !== ledger ||
      answer.tree_size !== head.seq ||
      answer.root !== head.row_hash ||
      answer.prev_checkpoint !== (last?.checkpointHash ?? null) ||
      !(await verifyCheckpoint(answer, keys))
    )
      throw new SealRefusal(
        'bad_response',
        'the sealer returned a checkpoint that does not verify',
      );
    const key = keys.find((k) => k.public_key === answer.public_key) as SigningKey;
    const [stored] = await tx
      .select()
      .from(auditSigningKeys)
      .where(eq(auditSigningKeys.publicKey, key.public_key));
    if (!stored)
      await tx.insert(auditSigningKeys).values({
        publicKey: key.public_key,
        createdAt: new Date(key.created_at),
        ...(key.retired_at ? { retiredAt: new Date(key.retired_at) } : {}),
      });
    await tx.insert(auditCheckpoints).values({
      v: 1,
      ledger,
      treeSize: answer.tree_size,
      root: answer.root,
      prevCheckpoint: answer.prev_checkpoint,
      createdAt: new Date(answer.created_at),
      checkpointHash: answer.checkpoint_hash,
      signature: answer.signature,
      publicKey: answer.public_key,
      frontier: [],
    });
    return answer;
  });
}

export type RemoteVerifyResult =
  | {
      ok: true;
      /** Rows `1..sealed_through` are covered by a verified seal. */
      sealed_through: number;
      /** Rows written after the last seal: not verified, only intact so far as the chain links. */
      unsealed_rows: number;
    }
  | {
      ok: false;
      reason: 'chain' | 'checkpoint' | 'head' | 'no_seal';
      /** `audit_events.id` of the first bad row, for `reason: 'chain'`. */
      id?: number;
      /** The seq of that row, or of the checkpoint whose head no longer matches. */
      seq?: number;
    };

/**
 * Checks the chain against the stored remote seals and the sealer's public
 * keys: every checkpoint must verify under `keys` and link to the one before
 * it, the chain must be intact (a bad row is named by id and seq), and at each
 * checkpoint's seq the row's hash must still be the sealed one, so a ledger
 * rewritten from scratch fails at its first seal. Rows after the last seal are
 * counted as unsealed, never as verified. The handle sees every row.
 */
export async function verify(
  handle: Handle,
  options: { ledger: string; keys: readonly SigningKey[] },
): Promise<RemoteVerifyResult> {
  const rows = await handle.select().from(auditCheckpoints).orderBy(asc(auditCheckpoints.treeSize));
  const last = rows[rows.length - 1];
  if (!last) return { ok: false, reason: 'no_seal' };
  let prev: string | null = null;
  for (const row of rows) {
    const checkpoint = toCheckpoint(row);
    if (
      row.ledger !== options.ledger ||
      row.prevCheckpoint !== prev ||
      !(await verifyCheckpoint(checkpoint, options.keys))
    )
      return { ok: false, reason: 'checkpoint', seq: row.treeSize };
    prev = row.checkpointHash;
  }
  const chain = await verifyTable(handle);
  if (!chain.ok) {
    const [bad] = resultRows<{ seq: unknown }>(
      await handle.execute(sql`select seq from audit_events where id = ${chain.id}`),
    );
    return {
      ok: false,
      reason: 'chain',
      id: chain.id,
      ...(bad?.seq === null || bad?.seq === undefined ? {} : { seq: Number(bad.seq) }),
    };
  }
  for (const row of rows) {
    const [leaf] = await readLeaves(handle, row.treeSize - 1, 1);
    if (leaf?.seq !== row.treeSize || leaf.row_hash !== row.root)
      return { ok: false, reason: 'head', seq: row.treeSize };
  }
  const head = await chainHead(handle);
  return {
    ok: true,
    sealed_through: last.treeSize,
    unsealed_rows: (head?.seq ?? 0) - last.treeSize,
  };
}
