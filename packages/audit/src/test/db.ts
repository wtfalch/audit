import { randomUUID } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { withDrizzle } from '@wtfalch/db/drizzle';
import { runMigrationSources } from '@wtfalch/db/migrate';
import { createPgliteDatabase } from '@wtfalch/db/pglite';
import { createDatabase } from '@wtfalch/db/postgres';
import type { DatabaseOwner } from '@wtfalch/db/postgres';
import { ensureRuntimeRole } from '@wtfalch/db/runtime-role';
import { drizzle } from 'drizzle-orm/pglite';
import type { Handle } from '../ledger.js';
import { migrationsDir } from '../migrations-dir.js';
import { tables } from '../tables.js';

/** Every migration this package ships, in file order — what a host that copied them all has. */
export const MIGRATION_FILES = readdirSync(migrationsDir)
  .filter((name) => name.endsWith('.sql'))
  .sort();
export const MIGRATION_SQL = MIGRATION_FILES.map((name) =>
  readFileSync(join(migrationsDir, name), 'utf8'),
).join('\n');

export const sources = [{ name: 'audit', dir: migrationsDir }];

/** What a host passes to `ensureRuntimeRole`, as the README documents it. */
export const APPEND_ONLY = ['audit_events'];
export const grantsIn = (schema: string) => [
  `${schema}.audit_erase_person(text, text, text)`,
  `${schema}.audit_seal_erasure(bigint, text)`,
  `${schema}.audit_chain_tail()`,
  `${schema}.audit_chain_tail_v2()`,
  `${schema}.audit_chain_leaves(bigint, integer)`,
  `${schema}.audit_pending_erasures()`,
];

export interface TestDb {
  db: Handle;
  exec(text: string): Promise<void>;
  query(text: string): Promise<Record<string, unknown>[]>;
  close(): Promise<void>;
  real: boolean;
  /** The schema the real tier migrated into; undefined on PGlite, which stays in `public`. */
  schema: string | undefined;
}

/** PGlite in memory with this package's migrations applied through `runMigrationSources`, in `public`. */
export async function migratedPglite(): Promise<PGlite> {
  const client = new PGlite();
  await runMigrationSources({
    owner: createPgliteDatabase(client),
    sources,
    log: () => undefined,
  });
  return client;
}

async function ownerQuery(url: string, text: string): Promise<void> {
  const owner = createDatabase({ url: () => url, max: 1, applicationName: 'audit-test' });
  try {
    await owner.database.query(text);
  } finally {
    await owner.close({ timeoutMs: 5000 });
  }
}

/**
 * A fresh database with the ledger's migrations applied, through
 * `@wtfalch/db`'s `runMigrationSources`. PGlite in memory by default. With
 * TEST_DATABASE_URL, a real Postgres: a uniquely named schema is created,
 * migrated and handed back scoped to that schema, and dropped on close, or
 * at once if setup fails; `public` is never touched.
 */
export async function testDb(): Promise<TestDb> {
  const url = process.env.TEST_DATABASE_URL;
  if (url) {
    const schema = `audit_test_${randomUUID().replaceAll('-', '')}`;
    try {
      await runMigrationSources({ url, schema, sources, log: () => undefined });
    } catch (error) {
      await ownerQuery(url, `drop schema if exists "${schema}" cascade`).catch(() => undefined);
      throw error;
    }
    const owner = createDatabase({
      url: () => url,
      searchPath: [schema, 'public'],
      max: 4,
      applicationName: 'audit-test',
    });
    return {
      db: withDrizzle(owner, { schema: tables }).orm,
      exec: (text) => owner.database.query(text).then(() => undefined),
      query: (text) => owner.database.query<Record<string, unknown>>(text),
      async close() {
        await owner.database.query(`drop schema "${schema}" cascade`);
        await owner.close({ timeoutMs: 5000 });
      },
      real: true,
      schema,
    };
  }
  const client = await migratedPglite();
  return {
    db: drizzle(client, { schema: tables }),
    exec: (text) => client.exec(text).then(() => undefined),
    query: async (text) => (await client.query(text)).rows as Record<string, unknown>[],
    close: () => client.close(),
    real: false,
    schema: undefined,
  };
}

/** A URL for the same database as `url`, logging in as `role`. */
export function urlFor(url: string, role: string, password: string): string {
  const next = new URL(url);
  next.username = role;
  next.password = password;
  return next.toString();
}

export interface RuntimeRoleDb {
  schema: string;
  role: string;
  /** The migrating connection, `search_path` on the schema. */
  owner: DatabaseOwner;
  /** The runtime role's own login, `search_path` on the schema: no `set role`. */
  runtime: DatabaseOwner;
  ownerDb: Handle;
  runtimeDb: Handle;
  close(): Promise<void>;
}

/**
 * Real Postgres only. A uniquely named schema migrated by the superuser in
 * TEST_DATABASE_URL, and a fresh non-owner runtime role made by
 * `ensureRuntimeRole` with what the README tells a host to pass. `appendOnly`
 * and `settings` can be overridden to build the wrong role on purpose. The
 * schema and the role are dropped on close, or at once if setup fails.
 */
export async function withRuntimeRole(
  url: string,
  options: { appendOnly?: string[]; settings?: Record<string, string> } = {},
): Promise<RuntimeRoleDb> {
  const id = randomUUID().replaceAll('-', '');
  const schema = `audit_test_${id}`;
  const role = `audit_rt_${id.slice(0, 16)}`;
  const runtimeUrl = urlFor(url, role, 'rt');
  const opened: DatabaseOwner[] = [];
  const cleanup = async () => {
    await Promise.all(opened.map((c) => c.close({ timeoutMs: 5000 }).catch(() => undefined)));
    await ownerQuery(url, `drop schema if exists "${schema}" cascade`).catch(() => undefined);
    await ownerQuery(url, `drop owned by "${role}"`).catch(() => undefined);
    await ownerQuery(url, `drop role if exists "${role}"`).catch(() => undefined);
  };
  try {
    await runMigrationSources({ url, schema, sources, log: () => undefined });
    await ensureRuntimeRole({
      ownerUrl: url,
      runtimeUrl,
      schemas: [schema],
      appendOnly: options.appendOnly ?? APPEND_ONLY,
      grants: grantsIn(schema),
      settings: options.settings,
      log: () => undefined,
    });
    const connect = (target: string, max: number) => {
      const connection = createDatabase({
        url: () => target,
        searchPath: [schema, 'public'],
        max,
        applicationName: 'audit-test',
      });
      opened.push(connection);
      return connection;
    };
    const owner = connect(url, 2);
    const runtime = connect(runtimeUrl, 2);
    return {
      schema,
      role,
      owner,
      runtime,
      ownerDb: withDrizzle(owner, { schema: tables }).orm,
      runtimeDb: withDrizzle(runtime, { schema: tables }).orm,
      close: cleanup,
    };
  } catch (error) {
    await cleanup();
    throw error;
  }
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
