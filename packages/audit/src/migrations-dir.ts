import { fileURLToPath } from 'node:url';

/**
 * Absolute path of the directory holding this package's numbered `.sql`
 * migrations. The host passes it to `runMigrationSources` as
 * `{ name: 'audit', dir: migrationsDir }`.
 *
 * Its own subpath (`@wtfalch/audit/migrations-dir`) and no other imports: a
 * migration image imports this without the Drizzle and authz the main entry
 * pulls in, and a bundler never meets this file's `import.meta.url` through
 * the main entry.
 */
export const migrationsDir = fileURLToPath(new URL('./migrations/', import.meta.url));
