import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * A bundle writer for tests of the standalone verifier. It shares nothing with
 * `bin/verify-bundle.ts` or with the package's own hashing: canonical JSON,
 * the row hash and the Merkle tree are written here a second time, in a
 * different style, from the format description alone. A rule that drifts in
 * one copy shows up as a failing test, not as a quiet pass.
 */
type Obj = Record<string, unknown>;

export const sha = (data: string | Uint8Array): Buffer =>
  createHash('sha256').update(data).digest();
export const shaHex = (data: string | Uint8Array): string => sha(data).toString('hex');

/** RFC 8785 for the values rows hold: safe integers only. */
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Obj).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
  }
  if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new Error('float');
  return JSON.stringify(value);
}

const leaf = (rowHash: string) =>
  sha(Buffer.concat([Buffer.from([0]), Buffer.from(rowHash, 'hex')]));
const pair = (a: Buffer, b: Buffer) => sha(Buffer.concat([Buffer.from([1]), a, b]));
/** RFC 6962 2.1, by recursion on the split point. */
export function mth(leaves: Buffer[]): Buffer {
  const first = leaves[0];
  if (leaves.length === 1 && first) return first;
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return pair(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}
/** Roots of the complete subtrees, largest first: one per set bit of the size. */
export function frontierOf(leaves: Buffer[]): Buffer[] {
  const out: Buffer[] = [];
  let at = 0;
  for (let bit = 2 ** 20; bit >= 1; bit /= 2) {
    if (leaves.length & bit) {
      out.push(mth(leaves.slice(at, at + bit)));
      at += bit;
    }
  }
  return out;
}

export interface Key {
  privateKey: KeyObject;
  publicKey: string;
}
export function newKey(): Key {
  const pair = generateKeyPairSync('ed25519');
  const der = pair.publicKey.export({ format: 'der', type: 'spki' });
  return { privateKey: pair.privateKey, publicKey: der.subarray(der.length - 32).toString('hex') };
}

export interface FixtureOptions {
  /** Events in the range. Default 6. */
  count?: number;
  /** First seq of the range. Default 1; above 1 the bundle carries a base. */
  from?: number;
  /** Checkpoint sizes in the range. Default: 3 and the end (from 1), the end only above. */
  sizes?: number[];
  /** Seqs whose rows are erased. */
  erase?: number[];
  key?: Key;
  /** Changes the row data, so two fixtures with different variants diverge. */
  variant?: string;
  /** Edits a checkpoint before it is hashed and signed. */
  tweakCheckpoint?: (cp: Obj, index: number) => void;
}

export interface Fixture {
  dir: string;
  /** A keys file for `--keys`, outside the bundle. */
  keysFile: string;
  key: Key;
  keys: { public_key: string; created_at: string; retired_at: string | null }[];
  events: Obj[];
  checkpoints: Obj[];
}

const KEY_CREATED = '2026-09-01T00:00:00.000Z';

function row(seq: number, prev: string | null, variant: string, erased: boolean): Obj {
  const base: Obj = {
    seq,
    received_at: new Date(Date.UTC(2026, 9, 1, 0, 0, seq)).toISOString(),
    occurred_at: new Date(Date.UTC(2026, 9, 1, 0, 0, seq) - 5).toISOString(),
    tenant_id: seq % 2 ? 'tenant-a' : null,
    tenant_display: seq % 2 ? 'Tenant A' : null,
    actor_class: 'human',
    actor_id: `user_${variant}${seq}`,
    action: 'invoice.paid',
    target_type: 'invoice',
    target_id: `i_${seq}`,
    outcome: 'success',
    context: 'standard',
    session_id: null,
    reason: null,
    reference: null,
    request_id: `req_${seq}`,
    ip: null,
    user_agent: null,
    tenant_visible: true,
    schema_version: 1,
    subject_class: null,
    subject_id: null,
    prev_hash: prev,
  };
  const salt = shaHex(`salt${variant}${seq}`).slice(0, 32);
  const content = {
    actor_display: `Ada ${seq}`,
    target_display: null,
    before: null,
    after: { n: seq, nested: { list: [1, 2, seq], text: 'ö' } },
  };
  base.content_hash = shaHex(salt + canonical(content));
  const rowHash = shaHex(canonical({ v: 2, ...base }));
  const out: Obj = {
    v: 2,
    ...base,
    ...content,
    row_hash: rowHash,
    content_salt: salt,
    erased_at: null,
    erasure_hash: null,
  };
  if (erased) {
    const erasedAt = '2026-10-02T00:00:00.000Z';
    Object.assign(out, {
      actor_display: 'Erased',
      after: null,
      content_salt: null,
      erased_at: erasedAt,
      erasure_hash: shaHex(canonical({ row_hash: rowHash, erased_at: erasedAt })),
    });
  }
  return out;
}

export function writeFixture(options: FixtureOptions = {}): Fixture {
  const from = options.from ?? 1;
  const count = options.count ?? 6;
  const to = from - 1 + count;
  const variant = options.variant ?? '';
  const key = options.key ?? newKey();
  const root = mkdtempSync(join(tmpdir(), 'audit-bundle-'));
  const dir = join(root, 'bundle');
  mkdirSync(dir);

  const all: Obj[] = [];
  for (let seq = 1; seq <= to; seq += 1) {
    const prev = all[seq - 2]?.row_hash;
    all.push(
      row(
        seq,
        typeof prev === 'string' ? prev : null,
        variant,
        options.erase?.includes(seq) ?? false,
      ),
    );
  }
  const leaves = all.map((ev) => leaf(String(ev.row_hash)));
  const events = all.slice(from - 1);

  const sizes = options.sizes ?? (from === 1 ? [Math.min(3, to), to] : [to]);
  const wanted = from > 1 ? [from - 1, ...sizes] : sizes;
  const checkpoints: Obj[] = [];
  wanted.forEach((size, index) => {
    const cp: Obj = {
      v: 1,
      ledger: 'test-ledger',
      tree_size: size,
      root: mth(leaves.slice(0, size)).toString('hex'),
      prev_checkpoint: (checkpoints[index - 1]?.checkpoint_hash as string | undefined) ?? null,
      created_at: new Date(Date.UTC(2026, 9, 3, 0, 0, index)).toISOString(),
    };
    options.tweakCheckpoint?.(cp, index);
    const hash = shaHex(canonical(cp));
    checkpoints.push({
      ...cp,
      checkpoint_hash: hash,
      signature: sign(null, Buffer.from(hash, 'hex'), key.privateKey).toString('hex'),
      public_key: key.publicKey,
    });
  });

  const keys = [{ public_key: key.publicKey, created_at: KEY_CREATED, retired_at: null }];
  const manifest = {
    format: 'wtfalch-audit-evidence/1',
    generated_at: '2026-10-04T00:00:00.000Z',
    ledger: 'test-ledger',
    range: { from, to },
    event_count: count,
    signing_keys: keys,
    base:
      from === 1
        ? null
        : {
            tree_size: from - 1,
            frontier: frontierOf(leaves.slice(0, from - 1)).map((h) => h.toString('hex')),
          },
  };
  writeFileSync(join(dir, 'manifest.json'), JSON.stringify(manifest));
  writeFileSync(join(dir, 'events.ndjson'), events.map((ev) => `${canonical(ev)}\n`).join(''));
  writeFileSync(join(dir, 'checkpoints.json'), JSON.stringify({ checkpoints }));
  writeFileSync(join(dir, 'anchors.json'), JSON.stringify({ anchors: [] }));
  const keysFile = join(root, 'keys.json');
  writeFileSync(keysFile, JSON.stringify(keys));
  return { dir, keysFile, key, keys, events, checkpoints };
}
