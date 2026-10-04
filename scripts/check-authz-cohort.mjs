import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * audit#43: @wtfalch/audit's own devDependencies always pin one specific
 * authz/db/contracts cohort, so `pnpm test` never proves the *range* this
 * package declares in peerDependencies actually installs together. This
 * packs the real tarball and installs it alongside the reviewed canonical
 * cohort -- @wtfalch/authz 0.18.0, @wtfalch/db 0.5.2, @wtfalch/contracts
 * 0.2.0 -- as plain dependencies, at the exact versions, in a consumer
 * outside this workspace. A peer conflict there surfaces as npm's ERESOLVE,
 * not a warning, so a plain `npm install` succeeding is the "no overrides"
 * proof the issue's acceptance criteria asks for.
 *
 * The consumer then recomposes the package's own `ResourceModule` and
 * `ResourceAccess`/`AccessResource` against that cohort's real authz types,
 * and the `AuthorizedRead` shape `@wtfalch/audit/read` declares against that
 * cohort's real contracts types, with no `as`: a type error there is the
 * resource subset moving in a way this package's source does not already
 * handle.
 */
const COHORT = {
  authz: '0.18.0',
  db: '0.5.2',
  contracts: '0.2.0',
  drizzleOrm: '0.39.3',
  zod: '4.5.4',
};

const root = fileURLToPath(new URL('..', import.meta.url));
const packageDirectory = join(root, 'packages/audit');
const scratch = await mkdtemp(join(tmpdir(), 'audit-authz-cohort-'));

function run(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
    timeout: command === 'npm' ? 300_000 : 120_000,
    killSignal: 'SIGKILL',
  });
}

async function json(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

try {
  // npm 11 returns an array of packed packages; npm 12 returns an object
  // keyed by package name (CLAUDE.md's own trap, from activity's
  // packed-consumers.mjs) -- handle both rather than assuming one.
  const report = JSON.parse(
    run(
      'npm',
      ['pack', '--ignore-scripts', '--json', '--pack-destination', scratch],
      packageDirectory,
    ),
  );
  const packed = Array.isArray(report) ? report[0] : Object.values(report)[0];
  assert(packed?.filename, `npm pack --json gave no filename; shape was ${typeof report}`);
  const tarball = join(scratch, packed.filename);

  const manifest = JSON.parse(await readFile(join(packageDirectory, 'package.json'), 'utf8'));
  assert(
    /^>=0\.16\.0 </.test(manifest.peerDependencies['@wtfalch/authz']),
    'the authz peer floor moved; update COHORT and this assertion together',
  );

  const consumer = join(scratch, 'consumer');
  await mkdir(consumer);
  await json(join(consumer, 'package.json'), {
    name: 'audit-authz-cohort-fixture',
    private: true,
    type: 'module',
    dependencies: {
      '@wtfalch/audit': `file:${tarball}`,
      '@wtfalch/authz': COHORT.authz,
      '@wtfalch/db': COHORT.db,
      '@wtfalch/contracts': COHORT.contracts,
      'drizzle-orm': COHORT.drizzleOrm,
      zod: COHORT.zod,
    },
    devDependencies: {
      '@types/node': manifest.devDependencies['@types/node'],
      typescript: manifest.devDependencies.typescript,
    },
  });

  console.log(
    `Cohort fixture: installing @wtfalch/audit ${manifest.version} with authz ${COHORT.authz}, db ${COHORT.db}, contracts ${COHORT.contracts} -- no peer overrides.`,
  );
  // No --legacy-peer-deps, no --force: a real peer conflict here is npm's
  // ERESOLVE, which fails this run rather than silently installing.
  run('npm', ['install', '--no-audit', '--no-fund'], consumer);

  console.log('Cohort fixture: composing authz/contracts types against the installed cohort.');
  const source = `
    import assert from 'node:assert/strict';
    import { readdirSync } from 'node:fs';
    import {
      auditPolicyModule,
      catalogue,
      createLedger,
      ledgerVocabularyFromCore,
      type Permission,
    } from '@wtfalch/audit';
    import { migrationsDir } from '@wtfalch/audit/migrations-dir';
    import type { AuthorizedRead } from '@wtfalch/audit/read';
    import {
      type AccessResource,
      type ResourceAccess,
      type ResourceGrant,
      type ResourceModule,
      core,
      defineResourceCatalogue,
      resourceAccess,
    } from '@wtfalch/authz';

    // The exported auditPolicyModule still satisfies this cohort's ResourceModule,
    // and recomposing it still names the one permission the package ships.
    const recomposed = defineResourceCatalogue([auditPolicyModule satisfies ResourceModule]);
    assert.deepEqual(Object.keys(recomposed), Object.keys(catalogue));

    const permission: Permission = 'audit:read';
    const principal = { class: 'human' as const, id: 'tester' };
    const grant: ResourceGrant = {
      id: permission,
      applicationId: 'cohort-fixture',
      platformId: 'wtfalch',
      boundary: { kind: 'platform' },
      permission,
      recipient: { kind: 'principal', principal },
      scope: { kind: 'organisation' },
      relation: 'any',
    };
    const restrictions = {
      kind: 'customer' as const,
      state: 'active' as const,
      ceiling: Object.keys(catalogue),
      selfDenied: [],
      denied: [],
      support: null,
    };
    const access: ResourceAccess = resourceAccess({
      applicationId: 'cohort-fixture',
      platformId: 'wtfalch',
      principal,
      catalogue,
      organisations: [{ id: 'tenant_a', restrictions }],
      platformRestrictions: { ...restrictions, kind: 'operator' },
      teams: [],
      memberships: [],
      now: Date.now(),
      grants: [grant],
    });
    const resource: AccessResource = {
      id: 'tenant_a',
      type: 'audit.event',
      applicationId: 'cohort-fixture',
      platformId: 'wtfalch',
      organisationId: 'tenant_a',
      teamId: null,
    };
    assert.equal(access.allows(permission, resource), true, 'audit:read unexpectedly denied');

    // read.ts's AuthorizedRead -- the shared resource policy a cross-app
    // read handler is built on -- takes this cohort's real ResourceAccess
    // with no cast.
    const authorized: AuthorizedRead = { tenantId: 'tenant_a', access };
    assert.equal(authorized.access.allows(permission, resource), true);

    // ledgerVocabularyFromCore takes this cohort's real authz core with no cast.
    const vocabulary = ledgerVocabularyFromCore(core);
    assert(Object.keys(vocabulary.events).length > 0, 'core produced an empty vocabulary');

    const ledger = createLedger({ vocabulary });
    assert.equal(typeof ledger.sign, 'function');
    assert.equal(typeof ledger.page, 'function');

    // Migration behaviour: the packed tarball still ships the SQL this cohort applies at boot.
    const migrations = readdirSync(migrationsDir).filter((name) => name.endsWith('.sql'));
    assert(migrations.length > 0, 'packed @wtfalch/audit shipped no migrations');

    console.log(
      \`Cohort fixture ok: \${migrations.length} migration(s), \${Object.keys(catalogue).length} permission(s).\`,
    );
  `;
  await writeFile(join(consumer, 'cohort.mts'), source);
  await json(join(consumer, 'tsconfig.json'), {
    compilerOptions: {
      target: 'ES2022',
      module: 'NodeNext',
      moduleResolution: 'NodeNext',
      strict: true,
      exactOptionalPropertyTypes: true,
      noUncheckedIndexedAccess: true,
      skipLibCheck: true,
      types: ['node'],
      lib: ['ES2022'],
      outDir: 'out',
    },
    include: ['cohort.mts'],
  });
  // `as const` narrows a literal and carries no generation-masking risk;
  // an `as SomeType` upcast is what this guards against.
  assert(!/\bas (?!const\b)[A-Za-z]/.test(source), 'the fixture must not cast across a type');
  const require = (await import('node:module')).createRequire(join(consumer, 'package.json'));
  const tsc = join(dirname(require.resolve('typescript/package.json')), 'bin/tsc');
  run(process.execPath, [tsc, '-p', 'tsconfig.json'], consumer);
  process.stdout.write(run(process.execPath, ['out/cohort.mjs'], consumer));
} finally {
  await rm(scratch, { recursive: true, force: true });
}
