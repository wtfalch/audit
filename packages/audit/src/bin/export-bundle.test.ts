import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sealCheckpoint } from '../checkpoint.js';
import { createLedger } from '../ledger.js';
import { CORE, type TestDb, testDb } from '../test/db.js';
import { ledgerVocabularyFromCore } from '../vocabulary.js';

/**
 * The command end to end: the built bins. The argument checks need a build
 * (`pnpm check` builds first); the rest also needs TEST_DATABASE_URL, a real
 * Postgres, and is skipped without it, like verify-chain.test.ts.
 */
const dist = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist', 'bin');
const bin = join(dist, 'export-bundle.js');
const verifier = join(dist, 'verify-bundle.js');
const url = process.env.TEST_DATABASE_URL;

function run(...args: string[]) {
  return spawnSync('node', [bin, ...args], { encoding: 'utf8' });
}

let scratch: string;
beforeAll(() => {
  scratch = mkdtempSync(join(tmpdir(), 'audit-export-'));
});
afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

describe.skipIf(!existsSync(bin))('audit-export-bundle arguments', () => {
  const db = ['--database-url', 'postgres://nowhere.invalid/x'];
  const ok = [...db, '--ledger', 'app', '--out', join(tmpdir(), 'audit-export-never')];

  it('exits 2 on a missing, unknown or malformed argument, before connecting', () => {
    expect(run('--nope').status).toBe(2);
    expect(run(...db, '--ledger', 'app').status).toBe(2); // no --out
    expect(run(...db, '--out', 'x').status).toBe(2); // no --ledger
    expect(run('--ledger', 'app', '--out', 'x', '--database-url').status).toBe(2);
    expect(run(...ok, '--schema', '').status).toBe(2);
    expect(run(...ok, '--ledger', '').status).toBe(2);
    for (const bad of ['abc', '0', '-1', '1.5', '1e3', '0x10', '']) {
      for (const flag of ['--from', '--to']) {
        const result = run(...ok, flag, bad);
        expect(result.status).toBe(2);
        expect(result.stderr).toContain(`${flag} is not a positive integer`);
      }
    }
    const reversed = run(...ok, '--from', '5', '--to', '3');
    expect(reversed.status).toBe(2);
    expect(reversed.stderr).toContain('--from is after --to');
  });

  it('exits 2 when --out already holds a file, and leaves it alone', () => {
    const out = mkdtempSync(join(scratch, 'full-'));
    writeFileSync(join(out, 'keep.txt'), 'x');
    const result = run(...db, '--ledger', 'app', '--out', out);
    expect(result.status).toBe(2);
    expect(result.stderr).toContain('already holds files');
    expect(readdirSync(out)).toEqual(['keep.txt']);
  });

  it('exits 2 when --out sits under a file', () => {
    const file = join(scratch, 'plain-file');
    writeFileSync(file, 'x');
    expect(run(...db, '--ledger', 'app', '--out', join(file, 'sub')).status).toBe(2);
  });
});

describe.skipIf(!url || !existsSync(bin) || !existsSync(verifier))('audit-export-bundle', () => {
  let t: TestDb;
  let keysFile: string;
  const exp = (...args: string[]) =>
    run('--database-url', url ?? '', '--schema', t.schema ?? '', ...args);

  beforeAll(async () => {
    t = await testDb();
    const ledger = createLedger({
      vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
      hashChain: true,
      checkRuntimeRole: false,
    });
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const spki = publicKey.export({ format: 'der', type: 'spki' });
    const signer = {
      publicKey: spki.subarray(spki.length - 32).toString('hex'),
      sign: async (message: Uint8Array) => new Uint8Array(nodeSign(null, message, privateKey)),
    };
    for (const upTo of [3, 5]) {
      for (let n = upTo === 3 ? 1 : 4; n <= upTo; n++) {
        await ledger.sign(t.db, {
          action: 'invoice.paid',
          tenantId: null,
          actor: { class: 'human', id: 'user_ada', display: 'Ada Lovelace' },
          context: 'standard',
          target: { type: 'invoice', id: `i_${n}` },
          after: { n },
        });
      }
      await sealCheckpoint(t.db, { ledger: 'app', signer });
    }
    const keys = await t.query('select public_key, created_at, retired_at from audit_signing_keys');
    keysFile = join(scratch, 'keys.json');
    writeFileSync(keysFile, JSON.stringify(keys));
  });
  afterAll(async () => {
    await t?.close();
  });

  const verify = (dir: string) =>
    spawnSync('node', [verifier, dir, '--keys', keysFile], { encoding: 'utf8' });

  it('writes the four files, exits 0, and the verifier passes the result', () => {
    const out = join(scratch, 'whole');
    const result = exp('--ledger', 'app', '--out', out);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('5 events');
    expect(readdirSync(out).sort()).toEqual([
      'anchors.json',
      'checkpoints.json',
      'events.ndjson',
      'manifest.json',
    ]);
    expect(verify(out).status).toBe(0);
  });

  it('writes into an empty existing directory and honours --from and --to', () => {
    const out = mkdtempSync(join(scratch, 'empty-'));
    expect(exp('--ledger', 'app', '--out', out, '--from', '4', '--to', '5').status).toBe(0);
    const manifest = JSON.parse(readFileSync(join(out, 'manifest.json'), 'utf8'));
    expect(manifest.range).toEqual({ from: 4, to: 5 });
    expect(verify(out).status).toBe(0);
  });

  it('exits 1 and writes nothing when the bundle cannot be made', () => {
    for (const extra of [
      ['--ledger', 'other'],
      ['--ledger', 'app', '--to', '4'],
      ['--ledger', 'app', '--from', '2'],
    ]) {
      const out = join(scratch, `refused-${extra.join('')}`);
      const result = exp('--out', out, ...extra);
      expect(result.status).toBe(1);
      expect(existsSync(out)).toBe(false);
    }
  });

  it('exits 2 when the database cannot be reached', () => {
    const result = run(
      '--database-url',
      'postgres://127.0.0.1:1/none',
      '--ledger',
      'app',
      '--out',
      join(scratch, 'unreachable'),
    );
    expect(result.status).toBe(2);
    expect(existsSync(join(scratch, 'unreachable'))).toBe(false);
  });
});
