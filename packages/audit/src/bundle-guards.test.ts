import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { verifyBundle } from './bin/verify-bundle.js';
import { buildBundle } from './bundle.js';
import { type CheckpointSigner, retireSigningKey, sealCheckpoint } from './checkpoint.js';
import { createLedger } from './ledger.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

/**
 * Bundles made by the real writer and read by the real verifier, so a field
 * the writer gets wrong, a range it cuts wrongly or a key or anchor it lists
 * wrongly shows as a failure or as a wrong list.
 */
let t: TestDb;
let scratch: string;
function newSigner(): CheckpointSigner {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKey: spki.subarray(spki.length - 32).toString('hex'),
    sign: async (message) => new Uint8Array(nodeSign(null, message, privateKey)),
  };
}
const keyA = newSigner();
const keyB = newSigner();
const ledger = createLedger({
  vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
  hashChain: true,
  checkRuntimeRole: false,
});

beforeAll(async () => {
  t = await testDb();
  scratch = mkdtempSync(join(tmpdir(), 'audit-bundle-guards-'));
});
afterAll(async () => {
  await t.close();
  rmSync(scratch, { recursive: true, force: true });
});
beforeEach(async () => {
  const off = ['audit_events', 'audit_checkpoints', 'audit_signing_keys', 'audit_anchors'];
  for (const table of off) await t.exec(`alter table ${table} disable trigger all`);
  await t.exec(
    'delete from audit_anchors; delete from audit_checkpoints; delete from audit_signing_keys; delete from audit_events',
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
const seal = (signer: CheckpointSigner) => sealCheckpoint(t.db, { ledger: 'app', signer });

/** Rows 1..6; checkpoints at 2 (key A, then retired), 4 and 6 (key B); row 2 erased and sealed. */
async function history() {
  await sign(1);
  await sign(2, 'user_eve');
  const first = await seal(keyA);
  await retireSigningKey(t.db, keyA.publicKey);
  await sign(3);
  await sign(4);
  await seal(keyB);
  await sign(5);
  await sign(6);
  const last = await seal(keyB);
  await t.exec("select audit_erase_person('user_eve', 'Erased person', null)");
  await ledger.erase(t.db, { subject: 'user_eve', pseudonym: 'Erased person' });
  return { first, last };
}

function check(files: Record<string, string>) {
  const dir = join(scratch, `b${Math.random().toString(16).slice(2)}`);
  mkdirSync(dir);
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  const manifest = JSON.parse(files['manifest.json'] ?? '{}');
  const keys = join(scratch, `k${Math.random().toString(16).slice(2)}.json`);
  writeFileSync(keys, JSON.stringify(manifest.signing_keys));
  return verifyBundle(dir, { keys });
}
const json = (files: Record<string, string>, name: string) => JSON.parse(files[name] ?? 'null');

describe('buildBundle output, read back by the verifier', () => {
  it('the whole history passes, erased row and retired key included', async () => {
    await history();
    const files = await buildBundle(t.db, { ledger: 'app' });
    const result = check(files);
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe('PASS');
    expect(json(files, 'manifest.json').signing_keys).toHaveLength(2);
  });

  it('a range that ends at an earlier checkpoint holds only those rows', async () => {
    await history();
    const files = await buildBundle(t.db, { ledger: 'app', to: 4 });
    expect(json(files, 'manifest.json')).toMatchObject({
      range: { from: 1, to: 4 },
      event_count: 4,
    });
    expect(check(files).failures).toEqual([]);
  });

  it('a range that starts after a checkpoint carries its base and its checkpoint, and only the keys they use', async () => {
    await history();
    const files = await buildBundle(t.db, { ledger: 'app', from: 5, to: 6 });
    const manifest = json(files, 'manifest.json');
    expect(manifest.base).toMatchObject({ tree_size: 4 });
    expect(manifest.base.frontier).toHaveLength(1);
    expect(
      json(files, 'checkpoints.json').checkpoints.map((c: { tree_size: number }) => c.tree_size),
    ).toEqual([4, 6]);
    // Key A signed only the checkpoint at 2, which this range does not include.
    expect(manifest.signing_keys.map((k: { public_key: string }) => k.public_key)).toEqual([
      keyB.publicKey,
    ]);
    expect(check(files).failures).toEqual([]);
  });

  it('a range from 3 to 6 holds the base at 2 and checkpoints 2, 4, 6', async () => {
    await history();
    const files = await buildBundle(t.db, { ledger: 'app', from: 3 });
    const sizes = json(files, 'checkpoints.json').checkpoints.map(
      (c: { tree_size: number }) => c.tree_size,
    );
    expect(sizes).toEqual([2, 4, 6]);
    expect(json(files, 'manifest.json').signing_keys).toHaveLength(2);
    expect(check(files).failures).toEqual([]);
  });

  it('lists only the anchors of the checkpoints it includes', async () => {
    const { first, last } = await history();
    for (const cp of [first, last]) {
      await t.exec(
        `insert into audit_anchors (checkpoint_hash, provider, token, token_hash, anchored_at)
         values ('${cp?.checkpoint_hash}', 'p', 'AA==', '${'0'.repeat(64)}', now())`,
      );
    }
    const files = await buildBundle(t.db, { ledger: 'app', from: 5, to: 6 });
    expect(
      json(files, 'anchors.json').anchors.map(
        (a: { checkpoint_hash: string }) => a.checkpoint_hash,
      ),
    ).toEqual([last?.checkpoint_hash]);
  });
});
