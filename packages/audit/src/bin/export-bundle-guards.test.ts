import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * Argument checks of the built `audit-export-bundle`, each told apart by its
 * message: the database url points nowhere, so a check that is missing would
 * still end in exit 2 a moment later, with another message.
 */
const bin = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'dist',
  'bin',
  'export-bundle.js',
);
const nowhere = 'postgres://127.0.0.1:1/x';
const out = join(tmpdir(), 'audit-export-guards-never');

function run(args: string[], env: Record<string, string | undefined> = {}) {
  const base = { ...process.env, DATABASE_URL: undefined, ...env };
  return spawnSync('node', [bin, ...args], {
    encoding: 'utf8',
    env: base as NodeJS.ProcessEnv,
  });
}

describe.skipIf(!existsSync(bin))('audit-export-bundle argument messages', () => {
  it('says which flag is missing its value when the next word is another flag', () => {
    const r = run(['--database-url', nowhere, '--ledger', '--out', out]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('--ledger needs a value');
  });

  it('names a missing --ledger, an empty --ledger, a missing --out and an empty --schema', () => {
    const base = ['--database-url', nowhere];
    expect(run([...base, '--out', out]).stderr).toContain('--ledger is required');
    expect(run([...base, '--ledger', '', '--out', out]).stderr).toContain('--ledger is required');
    expect(run([...base, '--ledger', 'app']).stderr).toContain('--out is required');
    expect(run([...base, '--ledger', 'app', '--out', out, '--schema', '']).stderr).toContain(
      '--schema is empty',
    );
  });

  it('reads the url from DATABASE_URL when --database-url is absent, and says so when neither is set', () => {
    const none = run(['--ledger', 'app', '--out', out]);
    expect(none.status).toBe(2);
    expect(none.stderr).toContain('no database url');
    const fromEnv = run(['--ledger', 'app', '--out', out], { DATABASE_URL: nowhere });
    expect(fromEnv.status).toBe(2);
    expect(fromEnv.stderr).not.toContain('no database url');
  });
});
