import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { appendLeaf, foldFrontier, leafHash, merkleRoot, nodeHash } from './merkle.js';
import { mth, rowHashOf } from './test/rfc6962.js';

const SIZES = Array.from({ length: 20 }, (_, i) => i + 1);
const entries = (n: number) =>
  Array.from({ length: n }, (_, i) => Buffer.from(rowHashOf(i), 'hex'));
const leaves = (n: number) =>
  Promise.all(Array.from({ length: n }, (_, i) => leafHash(rowHashOf(i))));

describe('merkle root', () => {
  it('matches an independent RFC 6962 implementation for sizes 1 to 20', async () => {
    for (const n of SIZES)
      expect(await merkleRoot(await leaves(n))).toBe(mth(entries(n)).toString('hex'));
  });

  it('hashes a leaf and a node with their domain prefixes', async () => {
    const zero = '00'.repeat(32);
    expect(await leafHash(zero)).toBe(createHash('sha256').update(Buffer.alloc(33)).digest('hex'));
    expect(await nodeHash(zero, zero)).toBe(
      createHash('sha256')
        .update(Buffer.concat([Buffer.from([1]), Buffer.alloc(64)]))
        .digest('hex'),
    );
  });

  it('refuses an empty tree and a hash that is not 64 lower-case hex', async () => {
    await expect(merkleRoot([])).rejects.toThrow('empty tree');
    await expect(leafHash('AB'.repeat(32))).rejects.toThrow('64 lower-case hex');
    await expect(leafHash('ab')).rejects.toThrow('64 lower-case hex');
    await expect(nodeHash('ab'.repeat(32), 'xyz')).rejects.toThrow('64 lower-case hex');
  });
});

describe('frontier', () => {
  it('has one root per set bit of the size, and folds to the root, at every size 1 to 20', async () => {
    let frontier: string[] = [];
    const all = await leaves(20);
    for (const n of SIZES) {
      frontier = await appendLeaf(frontier, n - 1, all[n - 1] as string);
      expect(frontier).toHaveLength(n.toString(2).replaceAll('0', '').length);
      expect(await foldFrontier(frontier)).toBe(mth(entries(n)).toString('hex'));
    }
  });

  it('refuses a frontier shorter than the size says, and an empty one', async () => {
    await expect(appendLeaf([], 1, '00'.repeat(32))).rejects.toThrow('shorter');
    await expect(foldFrontier([])).rejects.toThrow('empty tree');
  });
});
