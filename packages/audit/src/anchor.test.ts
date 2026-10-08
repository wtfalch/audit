import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { runMigrationSources } from '@wtfalch/db/migrate';
import { createPgliteDatabase } from '@wtfalch/db/pglite';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { anchorCheckpoints, buildTimestampRequest } from './anchor.js';
import { verifyBundle } from './bin/verify-bundle.js';
import {
  DerError,
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
import { type TestDb, sources, testDb } from './test/db.js';
import { type FakeTsa, fakeTsa } from './test/tsa.js';

const sha256hex = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

let t: TestDb;
let tsa: FakeTsa;
let fx: Fixture;
let scratch: string;
const extra: { close(): Promise<void> }[] = [];

beforeAll(async () => {
  tsa = await fakeTsa();
});
afterAll(async () => {
  await tsa.close();
});
beforeEach(async () => {
  t = await testDb();
  fx = writeFixture({ sizes: [2, 4, 6] });
  await insertCheckpoints(t, fx);
  scratch = mkdtempSync(join(tmpdir(), 'audit-anchor-'));
});
afterEach(async () => {
  await t.close();
  for (const e of extra.splice(0)) await e.close();
  rmSync(scratch, { recursive: true, force: true });
  rmSync(join(fx.dir, '..'), { recursive: true, force: true });
});

/** The fixture's key and checkpoints as rows in the real tables, hashes and signatures as the fixture made them. */
async function insertCheckpoints(db: TestDb, fixture: Fixture): Promise<void> {
  const [key] = fixture.keys;
  await db.exec(
    `insert into audit_signing_keys (public_key, created_at) values ('${key?.public_key}', '${key?.created_at}')`,
  );
  for (const cp of fixture.checkpoints) {
    await db.exec(`
      insert into audit_checkpoints
        (v, ledger, tree_size, root, prev_checkpoint, created_at, checkpoint_hash, signature, public_key, frontier)
      values (1, 'test-ledger', ${cp.tree_size}, '${cp.root}',
        ${cp.prev_checkpoint === null ? 'null' : `'${cp.prev_checkpoint}'`},
        '${cp.created_at}', '${cp.checkpoint_hash}', '${cp.signature}', '${cp.public_key}', '[]')`);
  }
}

const options = () => ({ tsaUrl: 'https://tsa.test/ts', provider: 'fake', fetch: tsa.fetch });
const rootsFile = (pem: string) => {
  const path = join(scratch, `roots-${Math.random().toString(16).slice(2)}.pem`);
  writeFileSync(path, pem);
  return path;
};
const anchorRows = () =>
  t.query(
    `select checkpoint_hash, provider, token, token_hash,
            to_char(anchored_at at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') as anchored_at
       from audit_anchors order by id`,
  );
/** Writes the stored anchors into the bundle, as the bundle writer would. */
async function exportAnchors(
  overrides: (rows: Record<string, unknown>[]) => void = () => undefined,
) {
  const rows = await anchorRows();
  overrides(rows);
  writeFileSync(join(fx.dir, 'anchors.json'), JSON.stringify({ anchors: rows }));
}
const verify = (roots?: string) =>
  verifyBundle(fx.dir, { keys: fx.keysFile, ...(roots ? { tsaRoots: rootsFile(roots) } : {}) });
const hashOf = (i: number) => String(fx.checkpoints[i]?.checkpoint_hash);

describe('the request', () => {
  it('is a version 1 TimeStampReq with a SHA-256 imprint, the nonce and certReq, as openssl reads it', () => {
    const imprint = createHash('sha256').update('x').digest();
    const nonce = Uint8Array.from([0x41, 2, 3, 4, 5, 6, 7, 8]);
    const request = buildTimestampRequest(imprint, nonce);
    const path = join(scratch, 'req.tsq');
    writeFileSync(path, request);
    const text = execFileSync('openssl', ['ts', '-query', '-in', path, '-text'], {
      encoding: 'utf8',
    });
    expect(text).toContain('Version: 1');
    expect(text).toContain('Hash Algorithm: sha256');
    expect(text).toContain('Nonce: 0x4102030405060708');
    expect(text).toContain('Certificate required: yes');
    // The imprint, as openssl dumps it: sixteen bytes a line.
    expect(text.replaceAll(/\s|-|[0-9a-f]{4}(?= )/g, '')).toContain(hex(imprint).slice(0, 10));
  });

  it('puts the nonce in as a positive INTEGER and the imprint as an OCTET STRING', () => {
    const imprint = new Uint8Array(32).fill(0xab);
    const request = readDerExact(buildTimestampRequest(imprint, Uint8Array.from([0xff, 1])));
    const [version, messageImprint, nonce, certReq] = children(request);
    expect(hex(version?.raw ?? new Uint8Array())).toBe('020101');
    expect(hex(children(messageImprint as never)[1]?.body ?? new Uint8Array())).toBe(hex(imprint));
    // 0xff01 would read negative without the leading zero.
    expect(hex(nonce?.raw ?? new Uint8Array())).toBe('020300ff01');
    expect(hex(certReq?.raw ?? new Uint8Array())).toBe('0101ff');
  });
});

describe('the DER reader', () => {
  it('refuses truncated, indefinite and oversized input', () => {
    expect(() => readDerExact(Uint8Array.of(0x30, 0x05, 0x01))).toThrow(DerError);
    expect(() => readDerExact(Uint8Array.of(0x30, 0x80, 0x00, 0x00))).toThrow(DerError);
    expect(() => readDerExact(Uint8Array.of(0x30, 0x85, 1, 2, 3, 4, 5))).toThrow(DerError);
    expect(() => readDerExact(Uint8Array.of(0x1f, 0x01, 0x00))).toThrow(DerError);
    expect(() => readDerExact(Uint8Array.of(0x30, 0x00, 0x00))).toThrow(DerError);
    expect(() => readDerExact(new Uint8Array())).toThrow(DerError);
  });

  it('writes and reads long lengths and integers', () => {
    const big = sequence(new Uint8Array(300).fill(1));
    expect(hex(big.subarray(0, 4))).toBe('3082012c');
    expect(readDerExact(big).body).toHaveLength(300);
    expect(hex(integerMagnitude(readDerExact(integer(Uint8Array.of(0, 0, 0x80)))))).toBe('80');
  });
});

describe('anchorCheckpoints', () => {
  it('anchors every checkpoint once and stores the token, its hash and the authority time', async () => {
    const before = Date.now();
    expect(await anchorCheckpoints(t.db, options())).toBe(3);
    const rows = await anchorRows();
    expect(rows.map((r) => r.checkpoint_hash)).toEqual([hashOf(0), hashOf(1), hashOf(2)]);
    for (const row of rows) {
      expect(row.provider).toBe('fake');
      const der = Buffer.from(String(row.token), 'base64');
      expect(row.token_hash).toBe(sha256hex(der));
      // The authority's own clock, to the second, near now.
      expect(Math.abs(Date.parse(String(row.anchored_at)) - before)).toBeLessThan(60_000);
      // The token holds the imprint of the raw checkpoint hash.
      const imprint = createHash('sha256').update(Buffer.from(String(row.checkpoint_hash), 'hex'));
      expect(der.indexOf(imprint.digest())).toBeGreaterThan(0);
    }
  });

  it('a second run anchors nothing and asks nobody', async () => {
    await anchorCheckpoints(t.db, options());
    let calls = 0;
    const counting = ((...args: Parameters<typeof fetch>) => {
      calls += 1;
      return tsa.fetch(...args);
    }) as typeof fetch;
    expect(await anchorCheckpoints(t.db, { ...options(), fetch: counting })).toBe(0);
    expect(calls).toBe(0);
    expect(await anchorRows()).toHaveLength(3);
  });

  it('another provider anchors the same checkpoints again', async () => {
    await anchorCheckpoints(t.db, options());
    expect(await anchorCheckpoints(t.db, { ...options(), provider: 'second' })).toBe(3);
    expect(await anchorRows()).toHaveLength(6);
  });

  it('opens no transaction during the call, and posts the query type with the timeout signal', async () => {
    const seen: { fresh: unknown; type: string | null; signal: boolean }[] = [];
    const watching = (async (url: string, init: RequestInit) => {
      // Outside a transaction a statement starts its own, so these two clocks agree.
      const [row] = await t.query('select now() = statement_timestamp() as fresh');
      seen.push({
        fresh: row?.fresh,
        type: new Headers(init.headers).get('content-type'),
        signal: init.signal instanceof AbortSignal,
      });
      return tsa.fetch(url, init);
    }) as unknown as typeof fetch;
    await anchorCheckpoints(t.db, { ...options(), fetch: watching });
    expect(seen).toHaveLength(3);
    for (const s of seen) {
      expect(s).toEqual({ fresh: true, type: 'application/timestamp-query', signal: true });
    }
  });

  it('a timeout writes nothing and counts as failed', async () => {
    const hanging = ((_url: string, init: RequestInit) =>
      new Promise((_, reject) => {
        init.signal?.addEventListener('abort', () => reject(init.signal?.reason));
      })) as unknown as typeof fetch;
    const started = Date.now();
    await expect(
      anchorCheckpoints(t.db, { ...options(), fetch: hanging, timeoutMs: 50 }),
    ).rejects.toThrow('audit: 3 of 3 checkpoints could not be anchored (0 were)');
    expect(Date.now() - started).toBeLessThan(5000);
    expect(await anchorRows()).toEqual([]);
  });

  it.each([2, 3, 4, 5])('PKIStatus %i is refused and nothing is written', async (status) => {
    const refusing = (async () =>
      new Response(sequence(sequence(integer(Uint8Array.of(status)))))) as unknown as typeof fetch;
    await expect(anchorCheckpoints(t.db, { ...options(), fetch: refusing })).rejects.toThrow(
      'audit: 3 of 3 checkpoints could not be anchored (0 were)',
    );
    expect(await anchorRows()).toEqual([]);
  });

  it('PKIStatus 1, granted with modifications, is accepted', async () => {
    const modifying = (async (url: string, init: RequestInit) => {
      const reply = new Uint8Array(await (await tsa.fetch(url, init)).arrayBuffer());
      const at = reply.findIndex((b, i) => b === 2 && reply[i + 1] === 1 && reply[i + 2] === 0);
      expect(at).toBeGreaterThan(0);
      expect(at).toBeLessThan(12);
      reply[at + 2] = 1;
      return new Response(reply);
    }) as unknown as typeof fetch;
    expect(await anchorCheckpoints(t.db, { ...options(), fetch: modifying })).toBe(3);
  });

  it('an HTTP error is a failure', async () => {
    const down = (async () => new Response('no', { status: 503 })) as unknown as typeof fetch;
    await expect(anchorCheckpoints(t.db, { ...options(), fetch: down })).rejects.toThrow(
      '3 of 3 checkpoints',
    );
    expect(await anchorRows()).toEqual([]);
  });

  it('a reply that is not DER is a failure', async () => {
    const junk = (async () => new Response(Uint8Array.of(1, 2, 3))) as unknown as typeof fetch;
    await expect(anchorCheckpoints(t.db, { ...options(), fetch: junk })).rejects.toThrow(
      '3 of 3 checkpoints',
    );
  });

  it('a token for another hash is refused', async () => {
    const swapping = (async (url: string, init: RequestInit) => {
      const [, imprint, nonce] = children(readDerExact(init.body as Uint8Array));
      const other = new Uint8Array(32).fill(7);
      const request = buildTimestampRequest(other, integerMagnitude(nonce as never));
      expect(imprint).toBeDefined();
      return tsa.fetch(url, { ...init, body: request });
    }) as unknown as typeof fetch;
    await expect(anchorCheckpoints(t.db, { ...options(), fetch: swapping })).rejects.toThrow(
      '3 of 3 checkpoints',
    );
    expect(await anchorRows()).toEqual([]);
  });

  it('a token that answers another nonce is refused', async () => {
    const swapping = (async (url: string, init: RequestInit) => {
      const [, imprint] = children(readDerExact(init.body as Uint8Array));
      const digest = children(imprint as never)[1]?.body ?? new Uint8Array();
      const request = buildTimestampRequest(digest, Uint8Array.of(0x42, 0x42, 0x42, 0x42));
      return tsa.fetch(url, { ...init, body: request });
    }) as unknown as typeof fetch;
    await expect(anchorCheckpoints(t.db, { ...options(), fetch: swapping })).rejects.toThrow(
      '3 of 3 checkpoints',
    );
    expect(await anchorRows()).toEqual([]);
  });

  it('one failing checkpoint does not stop the others, and the next run picks it up', async () => {
    let call = 0;
    const flaky = ((url: string, init: RequestInit) => {
      call += 1;
      if (call === 2) return Promise.reject(new Error('connection reset'));
      return tsa.fetch(url, init);
    }) as unknown as typeof fetch;
    await expect(anchorCheckpoints(t.db, { ...options(), fetch: flaky })).rejects.toThrow(
      'audit: 1 of 3 checkpoints could not be anchored (2 were)',
    );
    expect((await anchorRows()).map((r) => r.checkpoint_hash)).toEqual([hashOf(0), hashOf(2)]);
    expect(await anchorCheckpoints(t.db, options())).toBe(1);
    expect((await anchorRows()).map((r) => r.checkpoint_hash)).toEqual([
      hashOf(0),
      hashOf(2),
      hashOf(1),
    ]);
  });

  it('does not repeat a failure message that holds a value from the reply', async () => {
    const leaking = (async () => {
      throw new Error('secret-from-the-network');
    }) as unknown as typeof fetch;
    const error = await anchorCheckpoints(t.db, { ...options(), fetch: leaking }).catch((e) => e);
    expect(String(error.message)).not.toContain('secret');
  });
});

describe('audit_anchors', () => {
  it('refuses update, delete and truncate, and a second anchor for one checkpoint and provider', async () => {
    await anchorCheckpoints(t.db, options());
    await expect(t.exec("update audit_anchors set provider = 'x'")).rejects.toThrow(
      /audit_anchors is append-only: update refused/,
    );
    await expect(t.exec('delete from audit_anchors')).rejects.toThrow(
      /audit_anchors is append-only: delete refused/,
    );
    await expect(t.exec('truncate audit_anchors')).rejects.toThrow(
      /audit_anchors is append-only: truncate refused/,
    );
    const [row] = await anchorRows();
    await expect(
      t.exec(
        `insert into audit_anchors (checkpoint_hash, provider, token, token_hash, anchored_at)
         values ('${row?.checkpoint_hash}', 'fake', 'x', '${row?.token_hash}', now())`,
      ),
    ).rejects.toThrow(/audit_anchors_checkpoint_provider_idx|duplicate/);
    await expect(
      t.exec(
        "insert into audit_anchors (checkpoint_hash, provider, token, token_hash, anchored_at) values ('zz', 'p', 'x', 'zz', now())",
      ),
    ).rejects.toThrow(/check/);
  });

  it('applies in a named schema and still guards the table there', async () => {
    const pglite = new PGlite();
    try {
      await runMigrationSources({
        owner: createPgliteDatabase(pglite),
        schema: 'svc',
        sources,
        log: () => undefined,
      });
      const where = await pglite.query<{ table_schema: string }>(
        "select table_schema from information_schema.tables where table_name = 'audit_anchors'",
      );
      expect(where.rows.map((r) => r.table_schema)).toEqual(['svc']);
      await pglite.exec('set search_path to svc');
      await pglite.exec(
        `insert into audit_anchors (checkpoint_hash, provider, token, token_hash, anchored_at)
         values ('${'a'.repeat(64)}', 'p', 'x', '${'b'.repeat(64)}', now())`,
      );
      await expect(pglite.exec('delete from audit_anchors')).rejects.toThrow(/append-only/);
    } finally {
      await pglite.close();
    }
  });
});

describe('the verifier on real anchors', () => {
  it('passes with the authority root, and is UNCONFIRMED without it', async () => {
    await anchorCheckpoints(t.db, options());
    await exportAnchors();
    const confirmed = verify(tsa.rootsPem);
    expect(confirmed.failures).toEqual([]);
    expect(confirmed.verdict).toBe('PASS');
    expect(confirmed.lines).toContain('anchors: ok');
    const unconfirmed = verify();
    expect(unconfirmed.failures).toEqual([]);
    expect(unconfirmed.verdict).toBe('UNCONFIRMED');
  });

  it('passes a token signed with RSA', async () => {
    const rsa = await fakeTsa({ keyType: 'rsa' });
    extra.push(rsa);
    await anchorCheckpoints(t.db, { ...options(), fetch: rsa.fetch });
    await exportAnchors();
    const result = verify(rsa.rootsPem);
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe('PASS');
  });

  it('fails when the root is not the signer’s', async () => {
    await anchorCheckpoints(t.db, options());
    await exportAnchors();
    const other = await fakeTsa();
    extra.push(other);
    const result = verify(other.rootsPem);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toEqual(
      [0, 1, 2].map(
        (i) => `anchor ${hashOf(i)}: token: the signer does not chain to the trusted roots`,
      ),
    );
  });

  it('fails when the signer certificate itself is the only root given and is not the signer', async () => {
    await anchorCheckpoints(t.db, options());
    await exportAnchors();
    const other = await fakeTsa();
    extra.push(other);
    expect(verify(other.leafPem).verdict).toBe('FAIL');
  });

  it('fails a token for another checkpoint', async () => {
    await anchorCheckpoints(t.db, options());
    await exportAnchors((rows) => {
      const first = rows[0] as Record<string, unknown>;
      rows[1] = { ...first, checkpoint_hash: hashOf(1) };
    });
    const result = verify(tsa.rootsPem);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toEqual([`anchor ${hashOf(1)}: token: the token is for another hash`]);
  });

  it('fails a flipped byte in the signature, the imprint and the signer certificate', async () => {
    await anchorCheckpoints(t.db, options());
    const [row] = await anchorRows();
    const der = Buffer.from(String(row?.token), 'base64');
    const imprint = createHash('sha256')
      .update(Buffer.from(hashOf(0), 'hex'))
      .digest();
    const spots = [
      der.length - 1,
      der.indexOf(imprint) + 3,
      der.indexOf(Buffer.from('Fake TSA')) + 2,
    ];
    for (const spot of spots) {
      expect(spot).toBeGreaterThan(0);
      const flipped = Buffer.from(der);
      flipped[spot] = (flipped[spot] ?? 0) ^ 0x01;
      await exportAnchors((rows) => {
        rows.length = 1;
        rows[0] = {
          ...(rows[0] as Record<string, unknown>),
          token: flipped.toString('base64'),
          token_hash: sha256hex(flipped),
        };
      });
      const result = verify(tsa.rootsPem);
      expect(result.verdict).toBe('FAIL');
      expect(result.failures).toHaveLength(1);
      expect(result.failures[0]).toMatch(new RegExp(`^anchor ${hashOf(0)}: token: `));
    }
  });

  it('fails an edited token_hash, and a changed anchored_at', async () => {
    await anchorCheckpoints(t.db, options());
    await exportAnchors((rows) => {
      rows.length = 2;
      rows[0] = { ...(rows[0] as Record<string, unknown>), token_hash: '0'.repeat(64) };
      rows[1] = {
        ...(rows[1] as Record<string, unknown>),
        anchored_at: '2020-01-01T00:00:00.000Z',
      };
    });
    const result = verify(tsa.rootsPem);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toEqual([
      `anchor ${hashOf(0)}: token_hash does not match the token`,
      `anchor ${hashOf(1)}: anchored_at is not the token's genTime`,
    ]);
  });

  it('fails an anchor for a checkpoint that is not in the bundle', async () => {
    await anchorCheckpoints(t.db, options());
    await exportAnchors((rows) => {
      rows.length = 1;
      rows[0] = { ...(rows[0] as Record<string, unknown>), checkpoint_hash: 'c'.repeat(64) };
    });
    const result = verify(tsa.rootsPem);
    expect(result.failures).toContain(`anchor ${'c'.repeat(64)}: no such checkpoint in the bundle`);
  });

  it('fails a truncated or garbled token without throwing', async () => {
    await anchorCheckpoints(t.db, options());
    const [row] = await anchorRows();
    const der = Buffer.from(String(row?.token), 'base64');
    const broken = [
      der.subarray(0, 10),
      der.subarray(0, 100),
      der.subarray(0, der.length - 1),
      Buffer.alloc(0),
      Buffer.from([0x30, 0x80, 0, 0]),
      Buffer.concat([Buffer.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xff]), der]),
    ];
    for (const bad of broken) {
      await exportAnchors((rows) => {
        rows.length = 1;
        rows[0] = {
          ...(rows[0] as Record<string, unknown>),
          token: bad.toString('base64'),
          token_hash: sha256hex(bad),
        };
      });
      const result = verify(tsa.rootsPem);
      expect(result.verdict).toBe('FAIL');
      expect(result.failures).toHaveLength(1);
    }
  });

  it('fails the same anchor listed twice, and a token that is not base64', async () => {
    await anchorCheckpoints(t.db, options());
    await exportAnchors((rows) => {
      rows.length = 1;
      rows.push({ ...(rows[0] as Record<string, unknown>) });
    });
    expect(verify(tsa.rootsPem).failures).toEqual([
      `anchor ${hashOf(0)}: anchored twice by one provider`,
    ]);
    await exportAnchors((rows) => {
      rows.length = 1;
      rows[0] = { ...(rows[0] as Record<string, unknown>), token: '!!!' };
    });
    expect(verify(tsa.rootsPem).failures).toContain(`anchor ${hashOf(0)}: token is not base64`);
  });

  it('is an error when the roots file holds no certificate', async () => {
    await anchorCheckpoints(t.db, options());
    await exportAnchors();
    expect(() => verify('not a pem')).toThrow('the TSA roots file holds no certificate');
  });
});

describe('the verifier on forged tokens', () => {
  /** A TSTInfo for checkpoint 0 with the genTime given, signed by openssl cms. */
  async function forged(genTime: Date, usage?: string): Promise<void> {
    const imprint = createHash('sha256')
      .update(Buffer.from(hashOf(0), 'hex'))
      .digest();
    const stamp = `${genTime.toISOString().slice(0, 19).replaceAll(/[-:T]/g, '')}Z`;
    const tst = sequence(
      integer(Uint8Array.of(1)),
      oid('1.2.3.4.1'),
      sequence(sequence(oid('2.16.840.1.101.3.4.2.1'), nullValue()), octetString(imprint)),
      integer(Uint8Array.of(5)),
      encode(0x18, new TextEncoder().encode(stamp)),
    );
    const token = Buffer.from(await tsa.forge(tst, usage));
    writeFileSync(
      join(fx.dir, 'anchors.json'),
      JSON.stringify({
        anchors: [
          {
            checkpoint_hash: hashOf(0),
            provider: 'forged',
            token: token.toString('base64'),
            token_hash: sha256hex(token),
            anchored_at: new Date(
              `${stamp.slice(0, 4)}-${stamp.slice(4, 6)}-${stamp.slice(6, 8)}T${stamp.slice(8, 10)}:${stamp.slice(10, 12)}:${stamp.slice(12, 14)}Z`,
            ).toISOString(),
          },
        ],
      }),
    );
  }

  it('passes a token signed by the authority leaf (so the cases below fail for their one reason)', async () => {
    await forged(new Date());
    const result = verify(tsa.rootsPem);
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe('PASS');
  });

  it('fails a signer that may not timestamp', async () => {
    await forged(new Date(), 'critical,clientAuth');
    expect(verify(tsa.rootsPem).failures).toEqual([
      `anchor ${hashOf(0)}: token: the signer may not timestamp`,
    ]);
  });

  it.each([
    ['long before', new Date('2001-02-03T04:05:06Z')],
    ['long after', new Date('2090-02-03T04:05:06Z')],
  ])('fails a genTime %s the certificate validity', async (_name, when) => {
    await forged(when);
    expect(verify(tsa.rootsPem).failures).toEqual([
      `anchor ${hashOf(0)}: token: genTime is outside the signer certificate validity`,
    ]);
  });
});
