import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { anchorCheckpoints } from './anchor.js';
import { buildBundle } from './bundle.js';
import { sealRow } from './chain.js';
import {
  type Checkpoint,
  type CheckpointSigner,
  type SigningKey,
  proveConsistency,
  proveInclusion,
  sealCheckpoint,
  verifyCheckpoint,
  verifyConsistency,
  verifyInclusion,
} from './checkpoint.js';
import { type Ledger, createLedger } from './ledger.js';
import { auditEvents } from './tables.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { type FakeTsa, fakeTsa } from './test/tsa.js';
import { verifyTable } from './verify-table.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

/**
 * Everything together: a real chained ledger, sealed twice, anchored against
 * the fake authority, exported, and checked by the BUILT verifier as a child
 * process. Needs `dist/` (`pnpm build`, which `pnpm check` runs first); it
 * fails, not skips, when the build is missing.
 */
const bin = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'bin', 'verify-bundle.js');

const TENANT = '11111111-1111-4111-8111-111111111111';
const ada = { class: 'human', id: 'user_ada', display: 'Ada Lovelace' };
const eve = { class: 'human', id: 'user_eve', display: 'Eve Example' };

function newSigner(): CheckpointSigner {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    publicKey: spki.subarray(spki.length - 32).toString('hex'),
    sign: async (message) => new Uint8Array(nodeSign(null, message, privateKey)),
  };
}

function newLedger(): Ledger {
  return createLedger({
    vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
    hashChain: true,
    checkRuntimeRole: false,
  });
}

function signRow(ledger: Ledger, t: TestDb, n: number, actor = ada, extra = {}) {
  return ledger.sign(t.db, {
    action: 'invoice.paid',
    tenantId: n % 2 ? TENANT : null,
    actor,
    context: 'standard',
    target: { type: 'invoice', id: `i_${n}`, display: `Invoice ${n}` },
    ...extra,
  });
}

let scratch: string;
let counter = 0;
const fresh = (name: string) => join(scratch, `${name}-${counter++}`);

function run(dir: string, ...args: string[]) {
  return spawnSync('node', [bin, dir, ...args], { encoding: 'utf8' });
}

let t: TestDb;
let tsa: FakeTsa;
let ledger: Ledger;
let signer: CheckpointSigner;
let first: Checkpoint;
let second: Checkpoint;
let files: Record<string, string>;
let dir: string;
let keysFile: string;
let rootsFile: string;
let keys: SigningKey[];

function store(bundle: Record<string, string>, to: string): string {
  mkdirSync(to, { recursive: true });
  for (const [name, content] of Object.entries(bundle)) writeFileSync(join(to, name), content);
  return to;
}
const flags = () => ['--keys', keysFile, '--tsa-roots', rootsFile];

beforeAll(async () => {
  if (!existsSync(bin))
    throw new Error('dist/bin/verify-bundle.js is missing: run pnpm build first');
  scratch = mkdtempSync(join(tmpdir(), 'audit-e2e-'));
  tsa = await fakeTsa();
  t = await testDb();
  ledger = newLedger();
  signer = newSigner();

  await signRow(ledger, t, 1, ada, {
    before: { status: 'open', n: 4 },
    after: { status: 'paid', lines: [1, 2, 3] },
  });
  await signRow(ledger, t, 2, eve, { after: { status: 'paid' } });
  await signRow(ledger, t, 3);
  // Eve is erased: her row is erased and its erasure sealed before the first checkpoint.
  expect(await ledger.erase(t.db, { subject: 'user_eve', pseudonym: 'Erased person' })).toBe(1);
  first = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
  await signRow(ledger, t, 4);
  await signRow(ledger, t, 5, eve);
  second = (await sealCheckpoint(t.db, { ledger: 'app', signer })) as Checkpoint;
  expect(
    await anchorCheckpoints(t.db, {
      tsaUrl: 'https://tsa.test/ts',
      provider: 'fake',
      fetch: tsa.fetch,
    }),
  ).toBe(2);

  files = await buildBundle(t.db, { ledger: 'app' });
  dir = store(files, fresh('bundle'));
  keys = (await t.query('select public_key, created_at, retired_at from audit_signing_keys')).map(
    (r) => ({
      public_key: r.public_key as string,
      created_at: (r.created_at as Date).toISOString(),
      retired_at: null,
    }),
  );
  keysFile = join(scratch, 'keys.json');
  writeFileSync(keysFile, JSON.stringify(keys));
  rootsFile = join(scratch, 'roots.pem');
  writeFileSync(rootsFile, tsa.rootsPem);
}, 60_000);

afterAll(async () => {
  await t?.close();
  await tsa?.close();
  if (scratch) rmSync(scratch, { recursive: true, force: true });
});

describe('the exported bundle and the built verifier', () => {
  it('passes with the trusted keys and the authority root', () => {
    const result = run(dir, ...flags());
    expect(result.stdout).toContain('events: ok');
    expect(result.status).toBe(0);
  });

  it('is UNCONFIRMED (exit 3) with neither --keys nor --tsa-roots, and with only one of them', () => {
    expect(run(dir).status).toBe(3);
    expect(run(dir, '--keys', keysFile).status).toBe(3);
    expect(run(dir, '--tsa-roots', rootsFile).status).toBe(3);
  });

  it('holds the five events in seq order, the erased one sealed, and both checkpoints and anchors', () => {
    const lines = (files['events.ndjson'] ?? '')
      .trimEnd()
      .split('\n')
      .map((l) => JSON.parse(l));
    expect(lines.map((e) => e.seq)).toEqual([1, 2, 3, 4, 5]);
    expect(lines[0]).toMatchObject({
      v: 2,
      actor_display: 'Ada Lovelace',
      before: { n: 4, status: 'open' },
      after: { lines: [1, 2, 3], status: 'paid' },
    });
    expect(lines[1]).toMatchObject({
      actor_display: 'Erased person',
      content_salt: null,
      after: { erased: true },
    });
    expect(lines[1].erased_at).toMatch(/Z$/);
    expect(lines[1].erasure_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(lines[2].content_salt).toMatch(/^[0-9a-f]{32}$/);
    const manifest = JSON.parse(files['manifest.json'] ?? '');
    expect(manifest).toMatchObject({
      format: 'wtfalch-audit-evidence/1',
      ledger: 'app',
      range: { from: 1, to: 5 },
      event_count: 5,
      base: null,
    });
    expect(manifest.signing_keys.map((k: SigningKey) => k.public_key)).toEqual([signer.publicKey]);
    const cps = JSON.parse(files['checkpoints.json'] ?? '').checkpoints;
    expect(cps).toEqual([first, second]);
    const anchors = JSON.parse(files['anchors.json'] ?? '').anchors;
    expect(anchors.map((a: { checkpoint_hash: string }) => a.checkpoint_hash)).toEqual([
      first.checkpoint_hash,
      second.checkpoint_hash,
    ]);
  });

  it('agrees with verifyTable on the same rows', async () => {
    expect(await verifyTable(t.db)).toMatchObject({ ok: true, rows: 5 });
  });

  describe('a changed bundle fails (exit 1), one change at a time', () => {
    /** Copies the good bundle, lets `change` edit one file's text, verifies the copy. */
    function tampered(name: string, change: (text: string) => string) {
      const copy = store({ ...files, [name]: change(files[name] ?? '') }, fresh('tamper'));
      return run(copy, ...flags());
    }
    const flip = (char: string) => (char === '0' ? '1' : '0');

    it('one byte of an event field', () => {
      const result = tampered('events.ndjson', (text) =>
        text.replace('"action":"invoice.paid"', '"action":"invoice.paie"'),
      );
      expect(result.status).toBe(1);
      expect(result.stdout + result.stderr).toContain('seq 1');
    });

    it('one byte of before', () => {
      const result = tampered('events.ndjson', (text) =>
        text.replace('"status":"open"', '"status":"opeo"'),
      );
      expect(result.status).toBe(1);
      expect(result.stdout + result.stderr).toContain('content_hash');
    });

    it('a dropped event line', () => {
      const result = tampered('events.ndjson', (text) =>
        text
          .split('\n')
          .filter((_, i) => i !== 2)
          .join('\n'),
      );
      expect(result.status).toBe(1);
    });

    it('a checkpoint field', () => {
      const result = tampered('checkpoints.json', (text) =>
        text.replace(first.root, flip(first.root[0] ?? '0') + first.root.slice(1)),
      );
      expect(result.status).toBe(1);
    });

    it('a signature', () => {
      const result = tampered('checkpoints.json', (text) =>
        text.replace(
          second.signature,
          flip(second.signature[0] ?? '0') + second.signature.slice(1),
        ),
      );
      expect(result.status).toBe(1);
      expect(result.stdout + result.stderr).toContain(second.checkpoint_hash);
    });

    it('a token', () => {
      const token: string = JSON.parse(files['anchors.json'] ?? '').anchors[0].token;
      const middle = Math.floor(token.length / 2);
      const bent =
        token.slice(0, middle) + (token[middle] === 'A' ? 'B' : 'A') + token.slice(middle + 1);
      const result = tampered('anchors.json', (text) => text.replace(token, bent));
      expect(result.status).toBe(1);
    });

    it("the manifest's range.to", () => {
      const result = tampered('manifest.json', (text) => {
        const manifest = JSON.parse(text);
        manifest.range.to = 4;
        return JSON.stringify(manifest);
      });
      expect(result.status).toBe(1);
    });
  });

  it('passes a bundle for a range that starts after the first checkpoint, carrying its base', async () => {
    const later = await buildBundle(t.db, { ledger: 'app', from: 4, to: 5 });
    const manifest = JSON.parse(later['manifest.json'] ?? '');
    expect(manifest).toMatchObject({ range: { from: 4, to: 5 }, event_count: 2 });
    expect(manifest.base.tree_size).toBe(3);
    expect(manifest.base.frontier).toHaveLength(2); // 3 = 0b11
    expect(JSON.parse(later['checkpoints.json'] ?? '').checkpoints).toEqual([first, second]);
    expect(run(store(later, fresh('later')), ...flags()).status).toBe(0);
  });

  it('passes with --extends when the older bundle is the first checkpoint from row 1', async () => {
    const older = store(await buildBundle(t.db, { ledger: 'app', to: 3 }), fresh('older'));
    expect(run(older, ...flags()).status).toBe(0);
    const result = run(dir, ...flags(), '--extends', older);
    expect(result.stdout).toContain('extends');
    expect(result.status).toBe(0);
  });

  it('fails --extends when the older bundle is a different history', async () => {
    const other = await testDb();
    try {
      const otherLedger = newLedger();
      for (let n = 1; n <= 3; n++) await signRow(otherLedger, other, n);
      await sealCheckpoint(other.db, { ledger: 'app', signer });
      const older = store(await buildBundle(other.db, { ledger: 'app' }), fresh('other'));
      const otherKeys = join(scratch, 'other-keys.json');
      writeFileSync(otherKeys, JSON.stringify(keys));
      expect(run(older, '--keys', otherKeys).status).toBe(0);
      expect(run(dir, ...flags(), '--extends', older).status).toBe(1);
    } finally {
      await other.close();
    }
  });
});

describe('proofs on the same ledger', () => {
  it('proves every signed row into a checkpoint the keys accept', async () => {
    for (let seq = 1; seq <= 5; seq++) {
      const proof = await proveInclusion(t.db, seq);
      const row = (await t.query(`select row_hash from audit_events where seq = ${seq}`))[0];
      expect(proof.row_hash).toBe(row?.row_hash);
      expect(proof.checkpoint.checkpoint_hash).toBe(
        seq <= 3 ? first.checkpoint_hash : second.checkpoint_hash,
      );
      expect(await verifyInclusion(proof)).toBe(true);
      expect(await verifyCheckpoint(proof.checkpoint, keys)).toBe(true);
    }
  });

  it('proves the first checkpoint is a prefix of the second', async () => {
    const proof = await proveConsistency(t.db, first.tree_size, second.tree_size);
    expect(await verifyConsistency(proof, first.root, second.root)).toBe(true);
    expect(await verifyConsistency(proof, second.root, first.root)).toBe(false);
  });
});

describe('a ledger with format 1 rows first', () => {
  it('seals only the format 2 rows, bundles them and passes', async () => {
    const old = await testDb();
    try {
      for (let i = 0; i < 3; i++) {
        const [tail] = await old.query(
          'select row_hash from audit_events order by id desc limit 1',
        );
        const occurredAt = new Date(Date.UTC(2026, 8, 1, 0, 0, i));
        const sealed = await sealRow(
          {
            occurred_at: occurredAt,
            tenant_id: TENANT,
            tenant_display: null,
            actor_class: ada.class,
            actor_id: ada.id,
            actor_display: ada.display,
            action: 'invoice.paid',
            target_type: 'invoice',
            target_id: `old_${i}`,
            target_display: null,
            outcome: 'success',
            context: 'standard',
            session_id: null,
            reason: null,
            reference: null,
            request_id: null,
            ip: null,
            user_agent: null,
            tenant_visible: true,
            before: null,
            after: { n: i },
            schema_version: 1,
            subject_class: null,
            subject_id: null,
          },
          (tail?.row_hash as string | null) ?? null,
        );
        await old.db.insert(auditEvents).values({
          occurredAt,
          tenantId: TENANT,
          actorClass: ada.class,
          actorId: ada.id,
          actorDisplay: ada.display,
          action: 'invoice.paid',
          targetType: 'invoice',
          targetId: `old_${i}`,
          outcome: 'success',
          context: 'standard',
          tenantVisible: true,
          after: { n: i },
          schemaVersion: 1,
          prevHash: sealed.prev_hash,
          rowHash: sealed.row_hash,
          contentHash: sealed.content_hash,
          contentSalt: sealed.content_salt,
        });
      }
      const l = newLedger();
      for (let n = 1; n <= 2; n++) await signRow(l, old, n);
      const cp = (await sealCheckpoint(old.db, { ledger: 'app', signer })) as Checkpoint;
      expect(cp.tree_size).toBe(2);
      const bundle = await buildBundle(old.db, { ledger: 'app' });
      expect(JSON.parse(bundle['manifest.json'] ?? '')).toMatchObject({
        range: { from: 1, to: 2 },
        event_count: 2,
      });
      const v2 = store(bundle, fresh('v1first'));
      const k = join(scratch, 'v1-keys.json');
      writeFileSync(k, JSON.stringify(keys));
      expect(run(v2, '--keys', k).status).toBe(0);
      expect(await verifyTable(old.db)).toMatchObject({ ok: true, rows: 5 });
    } finally {
      await old.close();
    }
  });
});
