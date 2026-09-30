import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createLedger } from '../ledger.js';
import { CORE, type TestDb, testDb } from '../test/db.js';
import { ledgerVocabularyFromCore } from '../vocabulary.js';

/**
 * The command end to end: the built bin against a real Postgres. Needs both
 * TEST_DATABASE_URL and a build (`pnpm check` builds first), so it is skipped
 * on PGlite and on a bare `vitest run`.
 */
const bin = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'dist',
  'bin',
  'verify-chain.js',
);
const url = process.env.TEST_DATABASE_URL;

function run(...args: string[]) {
  return spawnSync('node', [bin, ...args], { encoding: 'utf8' });
}

describe.skipIf(!url || !existsSync(bin))('audit-verify-chain', () => {
  let t: TestDb;
  beforeAll(async () => {
    t = await testDb();
    const ledger = createLedger({
      vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
      hashChain: true,
      checkRuntimeRole: false,
    });
    for (let i = 0; i < 3; i++) {
      await ledger.sign(t.db, {
        action: 'invoice.paid',
        tenantId: null,
        actor: { class: 'human', id: 'user_ada', display: 'Ada Lovelace' },
        context: 'standard',
        target: { type: 'invoice', id: `i_${i}` },
      });
    }
  });
  afterAll(async () => {
    await t.close();
  });

  it('exits 0 on an intact chain and 1 on a broken one, naming the row', async () => {
    const ok = run('--database-url', url ?? '');
    expect(ok.status).toBe(0);
    expect(ok.stdout).toContain('audit chain ok: 3 rows');

    await t.exec('alter table audit_events disable trigger all');
    await t.exec(
      "update audit_events set action = 'invoice.refunded' where id = (select min(id) from audit_events)",
    );
    const broken = run('--database-url', url ?? '');
    expect(broken.status).toBe(1);
    expect(broken.stderr).toContain('audit chain BROKEN at row id');
  });

  it('exits 3 with a warning when the table has 0 rows', async () => {
    await t.exec('alter table audit_events disable trigger all');
    await t.exec('delete from audit_events');
    const empty = spawnSync('node', [bin], {
      encoding: 'utf8',
      env: { ...process.env, DATABASE_URL: url ?? '' },
    });
    expect(empty.status).toBe(3);
    expect(empty.stderr).toContain('0 rows');
  });

  it('exits 2 on bad arguments', () => {
    expect(run('--nope').status).toBe(2);
    expect(run('--database-url').status).toBe(2);
    expect(run('--database-url', url ?? '', '--head', '').status).toBe(2);
  });
});
