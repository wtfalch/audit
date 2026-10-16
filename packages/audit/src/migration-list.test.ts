import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { migrations } from './migration-list.js';
import { APPEND_ONLY, MIGRATION_FILES } from './test/db.js';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, '..', 'dist');

describe('the migration list', () => {
  it('is every migration file, in file order, with the file text and a stable id', () => {
    expect(migrations.map((m) => m.id)).toEqual(
      MIGRATION_FILES.map((name) => `audit-${name.slice(0, -4)}`),
    );
    expect(migrations[0]?.id).toBe('audit-0001_audit');
    for (const [i, name] of MIGRATION_FILES.entries()) {
      expect(migrations[i]?.sql).toBe(readFileSync(join(here, 'migrations', name), 'utf8'));
    }
    expect(readdirSync(join(here, 'migrations')).filter((n) => n.endsWith('.sql'))).toHaveLength(
      migrations.length,
    );
  });

  it('keeps the ids foundry has applied: these nine never change or move', () => {
    expect(migrations.slice(0, 9).map((m) => m.id)).toEqual([
      'audit-0001_audit',
      'audit-0002_display',
      'audit-0003_erase_email_guard',
      'audit-0004_chain',
      'audit-0005_rls',
      'audit-0006_force_rls',
      'audit-0007_chain_v2',
      'audit-0008_checkpoints',
      'audit-0009_anchors',
    ]);
  });

  it('names every table the migrations create in the README appendOnly list', () => {
    const created = migrations
      .flatMap((m) => [...m.sql.matchAll(/^create table (?:if not exists )?(\w+)/gim)])
      .map((match) => match[1])
      .sort();
    expect(created).toEqual([...APPEND_ONLY].sort());
    const readme = readFileSync(join(here, '..', 'README.md'), 'utf8');
    const section = readme.slice(readme.indexOf('## Cloudflare Workers'));
    const listed = /appendOnly: \[([^\]]*)\]/.exec(section)?.[1];
    expect(
      (listed ?? '')
        .split(',')
        .map((n) => n.trim().replaceAll("'", ''))
        .sort(),
    ).toEqual(created);
  });

  it('has unique ids', () => {
    expect(new Set(migrations.map((m) => m.id)).size).toBe(migrations.length);
  });

  it('is built with no import, so a Worker bundles it as data', () => {
    const built = readFileSync(join(dist, 'migration-list.js'), 'utf8');
    expect(built).not.toMatch(/^\s*import\s/m);
    expect(built).not.toContain('node:');
  });

  it('is what audit-migrations-json writes, as the JSON a release asset holds', () => {
    const out = join(mkdtempSync(join(tmpdir(), 'audit-mj-')), 'migrations.json');
    const bin = join(dist, 'bin', 'migrations-json.js');
    execFileSync('node', [bin, out], { stdio: 'pipe' });
    expect(JSON.parse(readFileSync(out, 'utf8'))).toEqual(migrations);
    const printed = execFileSync('node', [bin], { stdio: 'pipe' }).toString();
    expect(JSON.parse(printed)).toEqual(migrations);
  });
});
