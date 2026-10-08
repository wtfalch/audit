import { createHash } from 'node:crypto';
import { rmSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { anchorCheckpoints } from './anchor.js';
import {
  children,
  encode,
  integer,
  integerMagnitude,
  nullValue,
  octetString,
  oid,
  readDerExact,
  sequence,
} from './der.js';
import { type Fixture, writeFixture } from './test/bundle-fixture.js';
import { type TestDb, testDb } from './test/db.js';
import { type FakeTsa, fakeTsa } from './test/tsa.js';

/** Guards of anchor.ts that the main anchor tests leave to other checks. */
let t: TestDb;
let tsa: FakeTsa;
let fx: Fixture;

beforeAll(async () => {
  tsa = await fakeTsa();
});
afterAll(async () => {
  await tsa.close();
});
beforeEach(async () => {
  t = await testDb();
  fx = writeFixture({ sizes: [2, 4, 6] });
  const [key] = fx.keys;
  await t.exec(
    `insert into audit_signing_keys (public_key, created_at) values ('${key?.public_key}', '${key?.created_at}')`,
  );
  for (const cp of fx.checkpoints) {
    await t.exec(`
      insert into audit_checkpoints
        (v, ledger, tree_size, root, prev_checkpoint, created_at, checkpoint_hash, signature, public_key, frontier)
      values (1, 'test-ledger', ${cp.tree_size}, '${cp.root}',
        ${cp.prev_checkpoint === null ? 'null' : `'${cp.prev_checkpoint}'`},
        '${cp.created_at}', '${cp.checkpoint_hash}', '${cp.signature}', '${cp.public_key}', '[]')`);
  }
});
afterEach(async () => {
  vi.restoreAllMocks();
  await t.close();
  rmSync(join(fx.dir, '..'), { recursive: true, force: true });
});

const options = (over: Record<string, unknown> = {}) => ({
  tsaUrl: 'https://tsa.test/ts',
  provider: 'fake',
  fetch: tsa.fetch,
  ...over,
});
const rows = () => t.query('select checkpoint_hash, anchored_at from audit_anchors order by id');

/** A reply the authority did not make: a granted status around a token openssl signed over a TSTInfo built here. */
function replying(genTime: string, imprintOid = '2.16.840.1.101.3.4.2.1') {
  return (async (_url: string, init: RequestInit) => {
    const [, messageImprint, nonce] = children(readDerExact(init.body as Uint8Array));
    const digest = children(messageImprint as never)[1]?.body ?? new Uint8Array();
    const tst = sequence(
      integer(Uint8Array.of(1)),
      oid('1.2.3.4.1'),
      sequence(sequence(oid(imprintOid), nullValue()), octetString(digest)),
      integer(Uint8Array.of(5)),
      encode(0x18, new TextEncoder().encode(genTime)),
      integer(integerMagnitude(nonce as never)),
    );
    const token = await tsa.forge(tst);
    return new Response(sequence(sequence(integer(Uint8Array.of(0))), token));
  }) as unknown as typeof fetch;
}

describe('anchorCheckpoints guards', () => {
  it('stores the authority’s time, not the time it was asked', async () => {
    await anchorCheckpoints(t.db, options({ fetch: replying('20200102030405Z') }));
    const stored = await rows();
    expect(stored).toHaveLength(3);
    for (const row of stored) {
      expect((row.anchored_at as Date).toISOString()).toBe('2020-01-02T03:04:05.000Z');
    }
  });

  it('refuses a token whose imprint is not SHA-256, though the digest bytes are right', async () => {
    const sha1 = replying('20200102030405Z', '1.3.14.3.2.26');
    await expect(anchorCheckpoints(t.db, options({ fetch: sha1 }))).rejects.toThrow(
      '3 of 3 checkpoints',
    );
    expect(await rows()).toEqual([]);
  });

  it('refuses a good reply that came with an HTTP error status', async () => {
    const real = tsa.fetch;
    const erroring = (async (url: string, init: RequestInit) => {
      const response = await real(url, init);
      return new Response(await response.arrayBuffer(), { status: 500 });
    }) as unknown as typeof fetch;
    await expect(anchorCheckpoints(t.db, options({ fetch: erroring }))).rejects.toThrow(
      '3 of 3 checkpoints',
    );
    expect(await rows()).toEqual([]);
  });

  it('keeps the nonce a positive INTEGER whatever random bytes it draws', async () => {
    vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(((array: Uint8Array) =>
      array.fill(0)) as never);
    expect(await anchorCheckpoints(t.db, options())).toBe(3);
  });

  it('two runs at once anchor each checkpoint once and neither fails', async () => {
    const results = await Promise.all([
      anchorCheckpoints(t.db, options()),
      anchorCheckpoints(t.db, options()),
    ]);
    expect(results[0] + results[1]).toBe(3);
    expect(await rows()).toHaveLength(3);
  });

  it('the stored token hash is the hash of the stored token', async () => {
    await anchorCheckpoints(t.db, options());
    const [row] = await t.query('select token, token_hash from audit_anchors limit 1');
    const der = Buffer.from(String(row?.token), 'base64');
    expect(row?.token_hash).toBe(createHash('sha256').update(der).digest('hex'));
  });
});
