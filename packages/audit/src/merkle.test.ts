import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  appendLeaf,
  consistencyNodes,
  foldFrontier,
  inclusionPath,
  leafHash,
  merkleRoot,
  nodeHash,
  verifyConsistencyNodes,
  verifyInclusionPath,
} from './merkle.js';
import { path, mth, proof, rowHashOf } from './test/rfc6962.js';

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

const hex = (nodes: Buffer[]) => nodes.map((n) => n.toString('hex'));
const flip = (h: string) => (h[0] === '0' ? '1' : '0') + h.slice(1);

describe('inclusion paths', () => {
  it('match the RFC 6962 path and verify, for every leaf of every size 1 to 20', async () => {
    for (const n of SIZES) {
      const all = await leaves(n);
      const root = mth(entries(n)).toString('hex');
      for (let m = 0; m < n; m++) {
        const got = await inclusionPath(all, m);
        expect(got).toEqual(hex(path(m, entries(n))));
        expect(await verifyInclusionPath(all[m] as string, m, n, got, root)).toBe(true);
      }
    }
  });

  it('fail on a wrong leaf, a wrong path node, a wrong size (against the root for that size), a wrong index and a wrong root', async () => {
    for (const n of [1, 2, 5, 8, 13]) {
      const all = await leaves(n);
      const root = mth(entries(n)).toString('hex');
      for (let m = 0; m < n; m++) {
        const p = await inclusionPath(all, m);
        const leaf = all[m] as string;
        expect(await verifyInclusionPath(flip(leaf), m, n, p, root)).toBe(false);
        expect(await verifyInclusionPath(leaf, m, n, p, flip(root))).toBe(false);
        // The size is bound by the root claimed for it, not by the path alone.
        const next = mth(entries(n + 1)).toString('hex');
        expect(await verifyInclusionPath(leaf, m, n + 1, p, next)).toBe(false);
        expect(await verifyInclusionPath(leaf, m, n, [...p, root], root)).toBe(false);
        if (n > 1) {
          expect(await verifyInclusionPath(leaf, m, n, p.slice(1), root)).toBe(false);
          expect(await verifyInclusionPath(leaf, (m + 1) % n, n, p, root)).toBe(false);
        }
        for (let i = 0; i < p.length; i++)
          expect(
            await verifyInclusionPath(
              leaf,
              m,
              n,
              p.map((x, j) => (j === i ? flip(x) : x)),
              root,
            ),
          ).toBe(false);
      }
    }
  });

  it('reject an index outside the tree and a malformed hash', async () => {
    const all = await leaves(4);
    const root = await merkleRoot(all);
    await expect(inclusionPath(all, 4)).rejects.toThrow('outside the tree');
    await expect(inclusionPath(all, -1)).rejects.toThrow('outside the tree');
    expect(await verifyInclusionPath(all[0] as string, 4, 4, [], root)).toBe(false);
    expect(await verifyInclusionPath(all[0] as string, 0, 0, [], root)).toBe(false);
    expect(await verifyInclusionPath('zz', 0, 4, [], root)).toBe(false);
  });
});

describe('consistency proofs', () => {
  it('match the RFC 6962 proof and verify, for every pair 1 <= m <= n <= 20', async () => {
    for (const n of SIZES) {
      const all = await leaves(n);
      const toRoot = mth(entries(n)).toString('hex');
      for (let m = 1; m <= n; m++) {
        const nodes = await consistencyNodes(all, m);
        expect(nodes).toEqual(hex(proof(m, entries(n))));
        const fromRoot = mth(entries(m)).toString('hex');
        expect(await verifyConsistencyNodes(m, n, nodes, fromRoot, toRoot)).toBe(true);
      }
    }
  });

  it('fail on a wrong node, a wrong size, a wrong root and a truncated or extended proof', async () => {
    for (const n of [2, 5, 8, 13]) {
      const all = await leaves(n);
      const toRoot = mth(entries(n)).toString('hex');
      for (let m = 1; m < n; m++) {
        const nodes = await consistencyNodes(all, m);
        const fromRoot = mth(entries(m)).toString('hex');
        expect(await verifyConsistencyNodes(m, n, nodes, flip(fromRoot), toRoot)).toBe(false);
        expect(await verifyConsistencyNodes(m, n, nodes, fromRoot, flip(toRoot))).toBe(false);
        const nextTo = mth(entries(n + 1)).toString('hex');
        const nextFrom = mth(entries(m + 1)).toString('hex');
        expect(await verifyConsistencyNodes(m, n + 1, nodes, fromRoot, nextTo)).toBe(false);
        expect(await verifyConsistencyNodes(m + 1, n, nodes, nextFrom, toRoot)).toBe(false);
        expect(await verifyConsistencyNodes(m, n, nodes.slice(0, -1), fromRoot, toRoot)).toBe(
          false,
        );
        expect(await verifyConsistencyNodes(m, n, [...nodes, toRoot], fromRoot, toRoot)).toBe(
          false,
        );
        for (let i = 0; i < nodes.length; i++)
          expect(
            await verifyConsistencyNodes(
              m,
              n,
              nodes.map((x, j) => (j === i ? flip(x) : x)),
              fromRoot,
              toRoot,
            ),
          ).toBe(false);
      }
      // Equal sizes: an empty proof and equal roots, nothing else.
      expect(await verifyConsistencyNodes(n, n, [], toRoot, toRoot)).toBe(true);
      expect(await verifyConsistencyNodes(n, n, [], flip(toRoot), toRoot)).toBe(false);
      expect(await verifyConsistencyNodes(n, n, [toRoot], toRoot, toRoot)).toBe(false);
    }
  });

  it('reject sizes that cannot be a prefix, and a size outside the tree', async () => {
    const all = await leaves(4);
    const root = await merkleRoot(all);
    expect(await verifyConsistencyNodes(0, 4, [], root, root)).toBe(false);
    expect(await verifyConsistencyNodes(5, 4, [], root, root)).toBe(false);
    expect(await verifyConsistencyNodes(2, 4, ['zz'], root, root)).toBe(false);
    await expect(consistencyNodes(all, 0)).rejects.toThrow('outside the tree');
    await expect(consistencyNodes(all, 5)).rejects.toThrow('outside the tree');
  });
});
