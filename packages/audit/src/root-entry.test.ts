import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { MIGRATION_FILES } from './test/db.js';

/**
 * `@wtfalch/contracts` is an optional peer (ADR 0001): a host that never
 * mounts `ledgerReadHandler` must be able to import `@wtfalch/audit`
 * without it installed. The root entry crashing on that import, because
 * `read.ts`'s top-level `@wtfalch/contracts` import was re-exported from
 * `index.ts`, is exactly the bug this test exists to catch (audit#33) --
 * it walks the *built* root entry's relative-import graph (a static
 * re-export elsewhere in the tree would not show up on `index.ts` alone)
 * and fails if any file in it names `@wtfalch/contracts`. Requires `dist/`
 * to exist, which `pnpm check`'s `build` step always runs before `test`.
 */
const here = dirname(fileURLToPath(import.meta.url));
const distRoot = join(here, '..', 'dist');

const importSpecifierPattern = /(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g;

function importSpecifiersOf(file: string): string[] {
  const source = readFileSync(file, 'utf8');
  const specifiers: string[] = [];
  for (const match of source.matchAll(importSpecifierPattern)) {
    const specifier = match[1];
    if (specifier !== undefined) specifiers.push(specifier);
  }
  return specifiers;
}

describe('the root entry point', () => {
  it('never reaches @wtfalch/contracts, so importing it needs no optional peer installed', () => {
    const visited = new Set<string>();
    const stack = [join(distRoot, 'index.js')];

    while (stack.length > 0) {
      // biome-ignore lint/style/noNonNullAssertion: stack.length checked above
      const file = stack.pop()!;
      if (visited.has(file)) continue;
      visited.add(file);

      for (const specifier of importSpecifiersOf(file)) {
        expect(specifier).not.toBe('@wtfalch/contracts');
        if (specifier.startsWith('.')) {
          stack.push(resolve(dirname(file), specifier));
        }
      }
    }

    // A walk that silently visited nothing (a bad path, an empty file)
    // would pass the loop above having proved nothing.
    expect(visited.size).toBeGreaterThan(5);
  });
});

describe('the migrations-dir subpath', () => {
  const entry = join(distRoot, 'migrations-dir.js');

  it('imports node:url only, and the root entry never exports it', async () => {
    expect(importSpecifiersOf(entry)).toEqual(['node:url']);
    const main = await import(join(distRoot, 'index.js'));
    expect(main.migrationsDir).toBeUndefined();
  });

  it('points at a built directory holding every migration in src', async () => {
    const { migrationsDir } = await import(entry);
    expect(readdirSync(migrationsDir).sort()).toEqual(MIGRATION_FILES);
  });
});
