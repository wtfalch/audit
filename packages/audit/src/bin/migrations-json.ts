#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { migrations } from '../migration-list.js';

/**
 * `audit-migrations-json [file]`: this package's migrations as the ordered
 * `[{ id, sql }]` JSON a release asset `migrations.json` holds. Prints to
 * stdout without a file. An app that merges several packages' lists imports
 * `migrations` from `@wtfalch/audit/migration-list` instead.
 */
const json = `${JSON.stringify(migrations, null, 2)}\n`;
const target = process.argv[2];
if (target === undefined) process.stdout.write(json);
else {
  writeFileSync(resolve(process.cwd(), target), json);
  console.log(`audit: wrote ${migrations.length} migrations to ${target}`);
}
