import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * The tested cohort, installed from a packed tarball with no peer override:
 * a plain `npm install` fails with ERESOLVE if any peer range excludes a
 * member. Needs `dist/` (`pnpm build`); packing skips `prepack` so it never
 * rebuilds `dist/` under the tests that read it. The versions are this package's own pinned devDependencies, so the
 * cohort the other tests run against is the one installed here.
 */
const pkgDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8')) as {
  version: string;
  devDependencies: Record<string, string>;
};
const COHORT = [
  '@wtfalch/authz',
  '@wtfalch/contracts',
  '@wtfalch/db',
  '@wtfalch/design',
  'drizzle-orm',
  'react',
  'react-dom',
  'zod',
] as const;

const CONSUMER = `import { core } from '@wtfalch/authz';
import { createLedger, ledgerVocabularyFromCore } from '@wtfalch/audit';

export const ledger = createLedger({
  vocabulary: ledgerVocabularyFromCore(core, { 'invoice.paid': { tenantVisible: true } }),
});
export type Page = Parameters<typeof ledger.page>[1];
`;

const run = (cwd: string, cmd: string, args: string[]) =>
  spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 240_000 });

describe('packed install of the tested cohort', () => {
  let work: string;
  let app: string;
  beforeAll(() => {
    work = mkdtempSync(join(tmpdir(), 'audit-packed-'));
    app = join(work, 'app');
    mkdirSync(app);
    const packed = run(pkgDir, 'npm', ['pack', '--ignore-scripts', '--pack-destination', work]);
    if (packed.status !== 0) throw new Error(`npm pack failed: ${packed.stderr}`);
    const tarball = join(work, `wtfalch-audit-${pkg.version}.tgz`);
    const deps: Record<string, string> = { '@wtfalch/audit': `file:${tarball}` };
    for (const name of COHORT) {
      const v = pkg.devDependencies[name];
      if (!v) throw new Error(`devDependencies has no ${name}`);
      deps[name] = v;
    }
    writeFileSync(
      join(app, 'package.json'),
      JSON.stringify({ name: 'fixture', private: true, type: 'module', dependencies: deps }),
    );
    writeFileSync(
      join(app, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: {
          target: 'es2022',
          module: 'nodenext',
          moduleResolution: 'nodenext',
          strict: true,
          noEmit: true,
          skipLibCheck: true,
          types: [],
        },
        include: ['consumer.ts'],
      }),
    );
    writeFileSync(join(app, 'consumer.ts'), CONSUMER);
  }, 300_000);
  afterAll(() => rmSync(work, { recursive: true, force: true }));

  it('pins the canonical Authz generation', () => {
    expect(pkg.devDependencies['@wtfalch/authz']).toBe('0.18.0');
  });

  it('installs with no peer override', () => {
    const r = run(app, 'npm', ['install', '--no-audit', '--no-fund']);
    expect(r.stderr).not.toMatch(/ERESOLVE|ETARGET/);
    expect(r.status).toBe(0);
    const installed = JSON.parse(
      readFileSync(join(app, 'node_modules/@wtfalch/authz/package.json'), 'utf8'),
    ) as { version: string };
    expect(installed.version).toBe('0.18.0');
    expect(readdirSync(join(app, 'node_modules/@wtfalch'))).toContain('audit');
  }, 300_000);

  it('builds a ledger from the Authz core and type-checks the consumer, with no assertions', () => {
    const r = run(app, join(pkgDir, 'node_modules/.bin/tsc'), ['-p', 'tsconfig.json']);
    expect(r.stdout + r.stderr).toBe('');
    expect(r.status).toBe(0);
    const node = run(app, 'node', [
      '--input-type=module',
      '-e',
      "import {core} from '@wtfalch/authz'; import {createLedger, ledgerVocabularyFromCore} from '@wtfalch/audit'; const l = createLedger({vocabulary: ledgerVocabularyFromCore(core)}); console.log(typeof l.sign, typeof l.page)",
    ]);
    expect(node.stderr).toBe('');
    expect(node.stdout.trim()).toBe('function function');
  });
});
