import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PGlite } from '@electric-sql/pglite';
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite';
import { drizzle as drizzlePostgres } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import type { Handle } from '../ledger.js';
import { tables } from '../tables.js';

const here = dirname(fileURLToPath(import.meta.url));
export const MIGRATIONS = join(here, '..', 'migrations');
/** Every migration this package ships, in file order — what a host that copied them all has. */
export const MIGRATION_FILES = readdirSync(MIGRATIONS)
  .filter((name) => name.endsWith('.sql'))
  .sort();
export const MIGRATION_SQL = MIGRATION_FILES.map((name) =>
  readFileSync(join(MIGRATIONS, name), 'utf8'),
).join('\n');

export interface TestDb {
  db: Handle;
  exec(text: string): Promise<void>;
  query(text: string): Promise<Record<string, unknown>[]>;
  close(): Promise<void>;
  real: boolean;
}

/**
 * A fresh database with the ledger's migration applied. PGlite in memory by
 * default; with TEST_DATABASE_URL, a real Postgres whose public schema is
 * dropped first, so never point it at anything that matters.
 */
export async function testDb(): Promise<TestDb> {
  const url = process.env.TEST_DATABASE_URL;
  if (url) {
    const client = postgres(url, { prepare: false, max: 4 });
    await client.unsafe('drop schema public cascade; create schema public;');
    await client.unsafe(MIGRATION_SQL);
    return {
      db: drizzlePostgres(client, { schema: tables }) as unknown as Handle,
      exec: (text) => client.unsafe(text).then(() => undefined),
      query: async (text) => [...(await client.unsafe(text))] as Record<string, unknown>[],
      close: () => client.end(),
      real: true,
    };
  }
  const client = new PGlite();
  await client.exec(MIGRATION_SQL);
  return {
    db: drizzlePglite(client, { schema: tables }) as unknown as Handle,
    exec: (text) => client.exec(text).then(() => undefined),
    query: async (text) => (await client.query(text)).rows as Record<string, unknown>[],
    close: () => client.close(),
    real: false,
  };
}

/** `@wtfalch/authz`'s core words, copied as a fixture so this package's tests import nothing from it. */
export const CORE = {
  events: [
    'membership.created',
    'membership.role_changed',
    'membership.ended',
    'role.created',
    'role.updated',
    'role.deleted',
    'invitation.sent',
    'invitation.accepted',
    'invitation.revoked',
    'invitation.expired',
    'tenant.created',
    'tenant.state_changed',
    'tenant.settings_changed',
    'tenant.ceiling_changed',
    'tenant.attach_proposed',
    'tenant.attach_declined',
    'tenant.parent_attached',
    'tenant.parent_detached',
    'tenant.exported',
    'break_glass.started',
    'break_glass.ended',
    'credential.minted',
    'credential.revoked',
    'owner.installed',
    'operator.bootstrapped',
    'person.erased',
  ],
  tenantVisible: [
    'membership.created',
    'membership.role_changed',
    'membership.ended',
    'role.created',
    'role.updated',
    'role.deleted',
    'invitation.sent',
    'invitation.accepted',
    'invitation.revoked',
    'invitation.expired',
    'tenant.state_changed',
    'tenant.settings_changed',
    'tenant.ceiling_changed',
    'tenant.attach_proposed',
    'tenant.attach_declined',
    'tenant.parent_attached',
    'tenant.parent_detached',
    'tenant.exported',
    'break_glass.started',
    'break_glass.ended',
    'credential.minted',
    'credential.revoked',
    'owner.installed',
  ],
  actorClasses: ['human', 'api_key', 'agent', 'service'],
  contexts: ['standard', 'operator', 'break_glass'],
  outcomes: ['success', 'denied', 'error'],
  breakGlass: { reasonCodes: ['customer_support', 'incident', 'review', 'migration', 'other'] },
} as const;
