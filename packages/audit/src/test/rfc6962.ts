import { createHash } from 'node:crypto';

/**
 * RFC 6962 section 2.1, written from the RFC's text with node:crypto and
 * Buffers, sharing no code with src/merkle.ts: the reference the tests hold
 * the real implementation to.
 */
const sha = (...parts: Buffer[]) => createHash('sha256').update(Buffer.concat(parts)).digest();

/** The largest power of two strictly less than n. */
function k(n: number): number {
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

/** MTH over raw entries (here: the 32 raw bytes of each row_hash). */
export function mth(entries: Buffer[]): Buffer {
  if (entries.length === 0) return sha();
  if (entries.length === 1) return sha(Buffer.from([0]), entries[0] as Buffer);
  const split = k(entries.length);
  return sha(Buffer.from([1]), mth(entries.slice(0, split)), mth(entries.slice(split)));
}

/** PATH(m, D[n]). */
export function path(m: number, entries: Buffer[]): Buffer[] {
  if (entries.length === 1) return [];
  const split = k(entries.length);
  return m < split
    ? [...path(m, entries.slice(0, split)), mth(entries.slice(split))]
    : [...path(m - split, entries.slice(split)), mth(entries.slice(0, split))];
}

function subproof(m: number, entries: Buffer[], b: boolean): Buffer[] {
  if (m === entries.length) return b ? [] : [mth(entries)];
  const split = k(entries.length);
  return m <= split
    ? [...subproof(m, entries.slice(0, split), b), mth(entries.slice(split))]
    : [...subproof(m - split, entries.slice(split), false), mth(entries.slice(0, split))];
}

/** PROOF(m, D[n]). */
export const proof = (m: number, entries: Buffer[]) => subproof(m, entries, true);

/** A deterministic 64-hex row hash for leaf `i`. */
export const rowHashOf = (i: number) => createHash('sha256').update(`row ${i}`).digest('hex');
