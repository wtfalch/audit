import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type CheckpointSigner, type SigningKey, sealCheckpoint } from './checkpoint.js';
import { createLedger } from './ledger.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { verifyLedger } from './verify-ledger.js';
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

const sign = (n: number) =>
  ledger.sign(t.db, {
    action: 'invoice.paid',
    tenantId: null,
    actor: { class: 'human', id: 'user_ada', display: 'Ada' },
    context: 'standard',
    target: { type: 'invoice', id: `i_${n}` },
    after: { n },
  });
const seal = () => sealCheckpoint(t.db, { ledger: 'app', signer });
const keysOf = async (): Promise<SigningKey[]> =>
  (await t.query('select public_key, created_at, retired_at from audit_signing_keys')).map((r) => ({
    public_key: r.public_key as string,
    created_at: (r.created_at as Date).toISOString(),
    retired_at: r.retired_at === null ? null : (r.retired_at as Date).toISOString(),
  }));

describe('verifyLedger', () => {
  it('reports ok with no unsealed rows when every row is covered by a checkpoint', async () => {
    for (let n = 1; n <= 3; n++) await sign(n);
    await seal();
    const result = await verifyLedger(t.db, { ledger: 'app', keys: await keysOf() });
    expect(result).toEqual({ ok: true, unsealedSeqs: [] });
  });

  it('reports rows written after the last seal as unsealed, never as verified', async () => {
    for (let n = 1; n <= 3; n++) await sign(n);
    await seal();
    for (let n = 4; n <= 5; n++) await sign(n);
    const result = await verifyLedger(t.db, { ledger: 'app', keys: await keysOf() });
    expect(result).toEqual({ ok: true, unsealedSeqs: [4, 5] });
  });

  it('ok with no checkpoint at all, and every row reported unsealed', async () => {
    for (let n = 1; n <= 2; n++) await sign(n);
    const result = await verifyLedger(t.db, { ledger: 'app', keys: [] });
    expect(result).toEqual({ ok: true, unsealedSeqs: [1, 2] });
  });

  it('fails verification and names the row when a sealed row is changed before the last seal', async () => {
    for (let n = 1; n <= 3; n++) await sign(n);
    await seal();
    const [row] = await t.query('select id from audit_events where seq = 2');
    await t.exec('alter table audit_events disable trigger all');
    await t.exec(`update audit_events set actor_display = 'Someone else' where seq = 2`);
    await t.exec('alter table audit_events enable trigger all');
    const result = await verifyLedger(t.db, { ledger: 'app', keys: await keysOf() });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('chain');
      expect(result.id).toBe(Number(row?.id));
    }
  });

  it('fails because its head does not extend the sealed one when the ledger is rewritten from scratch', async () => {
    for (let n = 1; n <= 3; n++) await sign(n);
    await seal();
    const keys = await keysOf();
    // The whole table rewritten with different content, same seq range, same
    // checkpoint rows left standing: the checkpoint still claims a root that
    // no longer matches a single row underneath it.
    await t.exec('alter table audit_events disable trigger all');
    await t.exec('delete from audit_events');
    await t.exec('alter table audit_events enable trigger all');
    for (let n = 1; n <= 3; n++) await sign(n + 100);
    const result = await verifyLedger(t.db, { ledger: 'app', keys });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe('root');
  });

  it('fails when a checkpoint is for another ledger', async () => {
    for (let n = 1; n <= 2; n++) await sign(n);
    await sealCheckpoint(t.db, { ledger: 'other', signer });
    const result = await verifyLedger(t.db, { ledger: 'app', keys: await keysOf() });
    expect(result).toMatchObject({ ok: false, reason: 'ledger' });
  });

  it('fails when the checkpoint does not verify against the given keys', async () => {
    for (let n = 1; n <= 2; n++) await sign(n);
    await seal();
    const result = await verifyLedger(t.db, { ledger: 'app', keys: [] });
    expect(result).toMatchObject({ ok: false, reason: 'checkpoint' });
  });
});
