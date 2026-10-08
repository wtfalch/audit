import { describe, expect, it } from 'vitest';
import { leafHash, nodeHash, verifyConsistencyNodes, verifyInclusionPath } from './merkle.js';
import { rowHashOf } from './test/rfc6962.js';

/** Each case is a proof that would pass if one bound check were missing; a verifier says false, never true or a throw. */
describe('verifyInclusionPath bounds', () => {
  it('refuses an index equal to the size, even for a one-leaf tree whose root is the leaf', async () => {
    const leaf = await leafHash(rowHashOf(0));
    expect(await verifyInclusionPath(leaf, 0, 1, [], leaf)).toBe(true);
    expect(await verifyInclusionPath(leaf, 1, 1, [], leaf)).toBe(false);
  });

  it('refuses a path with a node more than the tree needs', async () => {
    const leaf = await leafHash(rowHashOf(0));
    const extra = await leafHash(rowHashOf(1));
    expect(await verifyInclusionPath(leaf, 0, 1, [extra], await nodeHash(extra, leaf))).toBe(false);
  });

  it('refuses a path that stops short of the root', async () => {
    const leaf = await leafHash(rowHashOf(0));
    expect(await verifyInclusionPath(leaf, 0, 2, [], leaf)).toBe(false);
  });

  it('says false, not an error, for a hash that is not 64 lower-case hex', async () => {
    const leaf = await leafHash(rowHashOf(0));
    expect(await verifyInclusionPath(leaf, 0, 2, ['zz'], leaf)).toBe(false);
    expect(await verifyInclusionPath(leaf, 0, 1, [], 'AB'.repeat(32))).toBe(false);
    expect(await verifyInclusionPath('short', 0, 1, [], leaf)).toBe(false);
  });
});

describe('verifyConsistencyNodes bounds', () => {
  it('refuses a larger tree as a prefix of a smaller one', async () => {
    const root = await leafHash(rowHashOf(0));
    expect(await verifyConsistencyNodes(2, 1, [], root, root)).toBe(false);
  });

  it('says false, not an error, for a hash that is not 64 lower-case hex', async () => {
    const root = await leafHash(rowHashOf(0));
    expect(await verifyConsistencyNodes(1, 2, ['zz'], root, root)).toBe(false);
    expect(await verifyConsistencyNodes(1, 2, [], 'AB'.repeat(32), root)).toBe(false);
    expect(await verifyConsistencyNodes(1, 2, [], root, 'short')).toBe(false);
  });
});
