import { sign as edSign, generateKeyPairSync } from 'node:crypto';
import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { canonicalJsonV2 } from './canonical.js';
import {
  type Checkpoint,
  type RemoteSealer,
  SealRefusal,
  type SealRequest,
  type SigningKey,
  remoteSealer,
  seal,
  verify,
} from './checkpoint.js';
import { type Ledger, createLedger } from './ledger.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

const ada = { class: 'human', id: 'user_ada', display: 'Ada Lovelace' };
const TENANT = '11111111-1111-4111-8111-111111111111';

let t: TestDb;
let ledger: Ledger;

beforeAll(async () => {
  t = await testDb();
  ledger = createLedger({
    vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
    hashChain: true,
    checkRuntimeRole: false,
  });
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  await t.exec(`
    alter table audit_events disable trigger all;
    alter table audit_checkpoints disable trigger all;
    alter table audit_signing_keys disable trigger all;
    delete from audit_checkpoints;
    delete from audit_signing_keys;
    delete from audit_events;
    alter table audit_events enable trigger all;
    alter table audit_checkpoints enable trigger all;
    alter table audit_signing_keys enable trigger all;
  `);
});

async function write(n: number, from = 0) {
  for (let i = from; i < from + n; i++)
    await ledger.sign(t.db, {
      action: 'invoice.paid',
      tenantId: TENANT,
      actor: ada,
      context: 'standard',
      target: { type: 'invoice', id: `i_${i}` },
    });
}

/** The platform's side: the private key lives only here, never in the app's options. */
function platform() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const pub = spki.subarray(spki.length - 32).toString('hex');
  const requests: SealRequest[] = [];
  let prev: string | null = null;
  const sealer: RemoteSealer = {
    async seal(request) {
      requests.push(request);
      const body = {
        ledger: request.ledger,
        tree_size: request.seq,
        root: request.head_hash,
        prev_checkpoint: prev,
        created_at: new Date().toISOString(),
      };
      const hash = createHash('sha256')
        .update(canonicalJsonV2({ v: 1, ...body }))
        .digest('hex');
      prev = hash;
      const c: Checkpoint = {
        v: 1,
        ...body,
        checkpoint_hash: hash,
        signature: edSign(null, Buffer.from(hash, 'hex'), privateKey).toString('hex'),
        public_key: pub,
      };
      return c;
    },
  };
  const keys: SigningKey[] = [
    { public_key: pub, created_at: new Date(Date.now() - 60_000).toISOString(), retired_at: null },
  ];
  return {
    sealer,
    keys,
    requests,
    pub,
    privateHex: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex'),
  };
}

const rewrite = async (sql: string) => {
  await t.exec('alter table audit_events disable trigger all');
  await t.exec(sql);
  await t.exec('alter table audit_events enable trigger all');
};

describe('remote seal', () => {
  it('verifies a sealed ledger, sending only the name, seq and head hash', async () => {
    const p = platform();
    await write(4);
    const c = await seal(t.db, { ledger: 'app', sealer: p.sealer, keys: p.keys });
    const [tail] = await t.query('select seq, row_hash from audit_chain_tail_v2()');
    expect(p.requests).toEqual([{ ledger: 'app', seq: 4, head_hash: tail?.row_hash }]);
    expect(c?.tree_size).toBe(4);
    expect(await verify(t.db, { ledger: 'app', keys: p.keys })).toEqual({
      ok: true,
      sealed_through: 4,
      unsealed_rows: 0,
    });
    expect(await seal(t.db, { ledger: 'app', sealer: p.sealer, keys: p.keys })).toBeNull();
    expect(p.requests).toHaveLength(1);
  });

  it('names a row changed before the last seal', async () => {
    const p = platform();
    await write(5);
    await seal(t.db, { ledger: 'app', sealer: p.sealer, keys: p.keys });
    const [victim] = await t.query('select id, seq from audit_events order by id offset 2 limit 1');
    await rewrite(`update audit_events set action = 'invoice.refunded' where id = ${victim?.id}`);
    expect(await verify(t.db, { ledger: 'app', keys: p.keys })).toEqual({
      ok: false,
      reason: 'chain',
      id: Number(victim?.id),
      seq: Number(victim?.seq),
    });
  });

  it('fails a ledger rewritten from scratch, and the client refuses to seal it', async () => {
    const p = platform();
    await write(3);
    await seal(t.db, { ledger: 'app', sealer: p.sealer, keys: p.keys });
    await rewrite('delete from audit_events');
    await write(5, 100);
    expect(await verify(t.db, { ledger: 'app', keys: p.keys })).toEqual({
      ok: false,
      reason: 'head',
      seq: 3,
    });
    await expect(
      seal(t.db, { ledger: 'app', sealer: p.sealer, keys: p.keys }),
    ).rejects.toMatchObject({ name: 'SealRefusal', reason: 'not_extending' });
    expect(p.requests).toHaveLength(1);
    const c = await t.query('select count(*) as n from audit_checkpoints');
    expect(Number(c[0]?.n)).toBe(1);
  });

  it('reports rows after the last seal as unsealed, and seals them next', async () => {
    const p = platform();
    await write(3);
    await seal(t.db, { ledger: 'app', sealer: p.sealer, keys: p.keys });
    await write(2, 3);
    expect(await verify(t.db, { ledger: 'app', keys: p.keys })).toEqual({
      ok: true,
      sealed_through: 3,
      unsealed_rows: 2,
    });
    expect((await seal(t.db, { ledger: 'app', sealer: p.sealer, keys: p.keys }))?.tree_size).toBe(
      5,
    );
    expect(await verify(t.db, { ledger: 'app', keys: p.keys })).toMatchObject({ unsealed_rows: 0 });
  });

  it('reports an unsealed ledger and refuses an answer under an unknown key', async () => {
    const p = platform();
    await write(2);
    expect(await verify(t.db, { ledger: 'app', keys: p.keys })).toEqual({
      ok: false,
      reason: 'no_seal',
    });
    await expect(seal(t.db, { ledger: 'app', sealer: p.sealer, keys: [] })).rejects.toBeInstanceOf(
      SealRefusal,
    );
    expect(await t.query('select 1 from audit_checkpoints')).toHaveLength(0);
  });

  it('never holds a private key: the client is built from a url and a credential only', async () => {
    const p = platform();
    await write(2);
    let seen: { headers: Record<string, string>; body: string } | undefined;
    const sealer = remoteSealer({
      url: 'https://seal.example/seal',
      credential: 'app-credential',
      fetch: (async (_url: string, init: RequestInit) => {
        seen = { headers: init.headers as Record<string, string>, body: String(init.body) };
        const request = JSON.parse(String(init.body)) as SealRequest;
        return new Response(JSON.stringify(await p.sealer.seal(request)));
      }) as unknown as typeof fetch,
    });
    await seal(t.db, { ledger: 'app', sealer, keys: p.keys });
    expect(seen?.headers.authorization).toBe('Bearer app-credential');
    expect(JSON.stringify(Object.keys(JSON.parse(seen?.body ?? '{}')))).toBe(
      '["ledger","seq","head_hash"]',
    );
    expect(seen?.body).not.toContain(p.privateHex);
    expect(JSON.stringify(await t.query('select * from audit_checkpoints'))).not.toContain(
      p.privateHex,
    );
  });

  it('surfaces a timeout and a failed answer as errors, storing nothing', async () => {
    const p = platform();
    await write(2);
    const hang = remoteSealer({
      url: 'https://seal.example/seal',
      credential: 'c',
      timeoutMs: 20,
      fetch: ((_url: string, init: RequestInit) =>
        new Promise((_, reject) => {
          init.signal?.addEventListener('abort', () => reject(init.signal?.reason));
        })) as unknown as typeof fetch,
    });
    await expect(seal(t.db, { ledger: 'app', sealer: hang, keys: p.keys })).rejects.toThrow();
    const down = remoteSealer({
      url: 'https://seal.example/seal',
      credential: 'c',
      fetch: (async () => new Response('no', { status: 503 })) as unknown as typeof fetch,
    });
    await expect(seal(t.db, { ledger: 'app', sealer: down, keys: p.keys })).rejects.toThrow(
      'the sealer answered 503',
    );
    expect(await t.query('select 1 from audit_checkpoints')).toHaveLength(0);
  });
});
