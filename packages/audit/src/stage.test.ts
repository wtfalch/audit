import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { anchorCheckpoints } from './anchor.js';
import { buildBundle } from './bundle.js';
import { type CheckpointSigner, sealCheckpoint } from './checkpoint.js';
import { parseEnvironment } from './environment.js';
import { type Ledger, createLedger } from './ledger.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { verifyTable } from './verify-table.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

const actor = { class: 'human', id: 'user_ada', display: 'Ada Lovelace' };

function newSigner(): CheckpointSigner & { calls: number } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const signer = {
    calls: 0,
    publicKey: spki.subarray(spki.length - 32).toString('hex'),
    sign: async (message: Uint8Array) => {
      signer.calls++;
      return new Uint8Array(nodeSign(null, message, privateKey));
    },
  };
  return signer;
}

let t: TestDb;
let ledger: Ledger;
const row = (n: number) =>
  ledger.sign(t.db, {
    action: 'invoice.paid',
    tenantId: null,
    actor,
    context: 'standard',
    target: { type: 'invoice', id: `i_${n}`, display: `Invoice ${n}` },
  });

beforeAll(async () => {
  t = await testDb();
  ledger = createLedger({
    vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
    hashChain: true,
    checkRuntimeRole: false,
  });
  // "Production": two rows, sealed. Then the database is copied to stage.
  await row(1);
  await row(2);
  await sealCheckpoint(t.db, { ledger: 'app', signer: newSigner(), environment: 'production' });
});
afterAll(async () => {
  await t.close();
});

describe('stage mode', () => {
  it('refuses to seal and never calls the signer', async () => {
    await row(3);
    const signer = newSigner();
    await expect(
      sealCheckpoint(t.db, { ledger: 'app', signer, environment: 'stage' }),
    ).rejects.toThrow(/refused in stage/);
    expect(signer.calls).toBe(0);
    const [{ n }] = (await t.query('select count(*) as n from audit_checkpoints')) as [
      { n: number },
    ];
    expect(Number(n)).toBe(1);
  });

  it('refuses to anchor and never calls the timestamp authority', async () => {
    const fetch = vi.fn();
    await expect(
      anchorCheckpoints(t.db, {
        tsaUrl: 'https://tsa.test/ts',
        provider: 'fake',
        fetch: fetch as unknown as typeof globalThis.fetch,
        environment: 'stage',
      }),
    ).rejects.toThrow(/refused in stage/);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('still verifies a production chain extended in stage', async () => {
    await row(4);
    expect(await verifyTable(t.db)).toMatchObject({ ok: true, rows: 4 });
  });

  it('labels an export made in stage', async () => {
    const files = await buildBundle(t.db, { ledger: 'app', environment: 'stage' });
    expect(JSON.parse(files['manifest.json'] ?? '{}').environment).toBe('stage');
    const prod = await buildBundle(t.db, { ledger: 'app' });
    expect(JSON.parse(prod['manifest.json'] ?? '{}').environment).toBe('production');
  });

  it('reads APP_ENVIRONMENT strictly', () => {
    expect(parseEnvironment('stage')).toBe('stage');
    expect(parseEnvironment('production')).toBe('production');
    expect(() => parseEnvironment('staging')).toThrow(/APP_ENVIRONMENT/);
    expect(() => parseEnvironment(undefined)).toThrow(/APP_ENVIRONMENT/);
  });
});
