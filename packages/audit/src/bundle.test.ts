import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { BundleRefusal, buildBundle } from './bundle.js';
import { type CheckpointSigner, sealCheckpoint } from './checkpoint.js';
import { createLedger } from './ledger.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

let t: TestDb;
const signer = ((): CheckpointSigner => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKey: spki.subarray(spki.length - 32).toString('hex'),
    sign: async (message) => new Uint8Array(nodeSign(null, message, privateKey)),
  };
})();
const ledger = createLedger({
  vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
  hashChain: true,
  checkRuntimeRole: false,
});

beforeAll(async () => {
  t = await testDb();
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  const off = ['audit_events', 'audit_checkpoints', 'audit_signing_keys'];
  for (const table of off) await t.exec(`alter table ${table} disable trigger all`);
  await t.exec(
    'delete from audit_checkpoints; delete from audit_signing_keys; delete from audit_events',
  );
  for (const table of off) await t.exec(`alter table ${table} enable trigger all`);
});

const sign = (n: number, actorId = 'user_ada') =>
  ledger.sign(t.db, {
    action: 'invoice.paid',
    tenantId: null,
    actor: { class: 'human', id: actorId, display: 'Ada' },
    context: 'standard',
    target: { type: 'invoice', id: `i_${n}` },
    after: { n },
  });
const seal = () => sealCheckpoint(t.db, { ledger: 'app', signer });

async function refusal(promise: Promise<unknown>, message: string) {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(BundleRefusal);
  expect((error as Error).message).toContain(message);
}

describe('buildBundle refuses', () => {
  it('an empty ledger and a ledger with rows but no checkpoint', async () => {
    await refusal(buildBundle(t.db, { ledger: 'app' }), 'no checkpoint');
    await sign(1);
    await refusal(buildBundle(t.db, { ledger: 'app' }), 'no checkpoint');
  });

  it("a ledger name that is not the checkpoints'", async () => {
    await sign(1);
    await seal();
    await refusal(buildBundle(t.db, { ledger: 'other' }), 'ledger name differs');
  });

  it('a range that is not on checkpoint boundaries', async () => {
    for (let n = 1; n <= 3; n++) await sign(n);
    await seal();
    for (let n = 4; n <= 5; n++) await sign(n);
    await seal();
    await refusal(buildBundle(t.db, { ledger: 'app', to: 4 }), '"to" is not the size');
    await refusal(buildBundle(t.db, { ledger: 'app', from: 2 }), '"from" is not 1');
    await refusal(buildBundle(t.db, { ledger: 'app', from: 5 }), '"from" is not 1');
    await refusal(buildBundle(t.db, { ledger: 'app', from: 4, to: 3 }), '1 <= from <= to');
    await refusal(buildBundle(t.db, { ledger: 'app', from: 0 }), '1 <= from <= to');
    await refusal(buildBundle(t.db, { ledger: 'app', to: 2.5 }), '1 <= from <= to');
    // The boundaries themselves are fine.
    const bundle = await buildBundle(t.db, { ledger: 'app', from: 4, to: 5 });
    expect(JSON.parse(bundle['manifest.json'] ?? '').range).toEqual({ from: 4, to: 5 });
  });

  it('a row that is erased but whose erasure is not sealed, and builds once it is', async () => {
    await sign(1);
    await sign(2, 'user_eve');
    await t.exec("select audit_erase_person('user_eve', 'Erased person', null)");
    await seal();
    await refusal(buildBundle(t.db, { ledger: 'app' }), 'erasure of row seq 2 is not sealed');
    await ledger.erase(t.db, { subject: 'user_eve', pseudonym: 'Erased person' });
    const bundle = await buildBundle(t.db, { ledger: 'app' });
    const second = JSON.parse((bundle['events.ndjson'] ?? '').split('\n')[1] ?? '');
    expect(second).toMatchObject({ seq: 2, content_salt: null, actor_display: 'Erased person' });
  });

  it('rows that are missing from the range, as a connection that cannot see them', async () => {
    for (let n = 1; n <= 3; n++) await sign(n);
    await seal();
    await t.exec('alter table audit_events disable trigger all');
    await t.exec('delete from audit_events where seq = 2');
    await t.exec('alter table audit_events enable trigger all');
    await refusal(buildBundle(t.db, { ledger: 'app' }), 'after seq 1 are missing');
    await t.exec('alter table audit_events disable trigger all');
    await t.exec('delete from audit_events where seq = 3');
    await t.exec('alter table audit_events enable trigger all');
    await refusal(buildBundle(t.db, { ledger: 'app', to: 3 }), 'rows end at seq 1');
  });
});

describe('buildBundle reads in pages', () => {
  it('returns every row of a range longer than one page, in seq order, one line each', async () => {
    await t.exec(`
      insert into audit_events
        (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context,
         tenant_visible, chain_version, seq, received_at, row_hash, content_hash, content_salt)
      select 'human', 'u', 'U', 'a.b', 't', 'x', 'success', 'standard', false, 2, n, now(),
             md5(n::text) || md5(n::text), md5(n::text) || md5(n::text), md5(n::text)
        from generate_series(1, 2001) n`);
    await seal();
    const bundle = await buildBundle(t.db, { ledger: 'app' });
    const lines = (bundle['events.ndjson'] ?? '').split('\n');
    expect(lines.pop()).toBe('');
    expect(lines.map((l) => JSON.parse(l).seq)).toEqual(
      Array.from({ length: 2001 }, (_, i) => i + 1),
    );
    expect(JSON.parse(bundle['manifest.json'] ?? '').event_count).toBe(2001);
  });
});
