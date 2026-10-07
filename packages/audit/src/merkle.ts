/**
 * The Merkle tree under the checkpoints (RFC 6962 section 2.1), pure: no
 * database, no clock. Leaf `i` (0-based) is the row with `seq = i + 1`. Every
 * hash is passed around as 64 lower-case hex characters.
 *
 *   leaf hash = SHA-256(0x00 || the 32 raw bytes of row_hash)
 *   node hash = SHA-256(0x01 || left || right)
 *
 * A tree splits at the largest power of two strictly less than its leaf
 * count. The frontier is the roots of the complete subtrees of a tree of size
 * n, largest first, one per set bit of n: enough to append a leaf and to read
 * the root without keeping the tree.
 */

const HEX_32 = /^[0-9a-f]{64}$/;

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}

function hash32(hex: string, what: string): Uint8Array {
  if (!HEX_32.test(hex)) throw new Error(`${what} is not 64 lower-case hex characters`);
  return fromHex(hex);
}

async function prefixed(prefix: number, ...parts: Uint8Array[]): Promise<string> {
  const bytes = new Uint8Array(1 + parts.reduce((n, part) => n + part.length, 0));
  bytes[0] = prefix;
  let at = 1;
  for (const part of parts) {
    bytes.set(part, at);
    at += part.length;
  }
  return toHex(await sha256(bytes));
}

/** The hash of one leaf, from the row's `row_hash`. */
export async function leafHash(rowHash: string): Promise<string> {
  return prefixed(0, hash32(rowHash, 'row_hash'));
}

/** The hash of an inner node over two child hashes. */
export async function nodeHash(left: string, right: string): Promise<string> {
  return prefixed(1, hash32(left, 'node hash'), hash32(right, 'node hash'));
}

/** The frontier of a tree of `size` leaves with one more leaf (already a leaf hash) appended. */
export async function appendLeaf(
  frontier: readonly string[],
  size: number,
  leaf: string,
): Promise<string[]> {
  const next = [...frontier];
  let acc = leaf;
  for (let n = size; n % 2 === 1; n = (n - 1) / 2) {
    const left = next.pop();
    if (left === undefined) throw new Error('frontier is shorter than the tree size says');
    acc = await nodeHash(left, acc);
  }
  next.push(acc);
  return next;
}

/** The root of a tree, from its frontier: fold from the right. */
export async function foldFrontier(frontier: readonly string[]): Promise<string> {
  const last = frontier[frontier.length - 1];
  if (last === undefined) throw new Error('an empty tree has no root');
  let acc = last;
  for (let i = frontier.length - 2; i >= 0; i--) acc = await nodeHash(frontier[i] as string, acc);
  return acc;
}

/** The largest power of two strictly less than `n`, for n > 1. */
function split(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** MTH of leaf hashes `[start, end)`. */
async function subtreeRoot(leaves: readonly string[], start: number, end: number): Promise<string> {
  if (end - start === 1) return leaves[start] as string;
  const k = split(end - start);
  return nodeHash(
    await subtreeRoot(leaves, start, start + k),
    await subtreeRoot(leaves, start + k, end),
  );
}

/** The root of a tree over leaf hashes (not row hashes). */
export async function merkleRoot(leaves: readonly string[]): Promise<string> {
  if (leaves.length === 0) throw new Error('an empty tree has no root');
  return subtreeRoot(leaves, 0, leaves.length);
}

/** Is this 64 lower-case hex characters? */
export function isHash(value: unknown): value is string {
  return typeof value === 'string' && HEX_32.test(value);
}
