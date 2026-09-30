#!/usr/bin/env node
import type { Handle } from '../ledger.js';
import { verifyTable } from '../verify-table.js';

/**
 * `audit-verify-chain --database-url <url> [--after-id <n>] [--head <hash>]`
 *
 * Runs `verifyChain` over the whole `audit_events` table and exits 0 when
 * the chain holds, 1 when it does not (naming the first bad row), 2 when it
 * could not run (bad arguments, no connection). The URL may also come from
 * `DATABASE_URL`. Connect as the table's owner or an admin, not the runtime
 * role: row-level security hides other tenants' rows from that role.
 *
 * `postgres` is an optional peer; this is the only file that imports it.
 */
const USAGE =
  'usage: audit-verify-chain --database-url <url> [--after-id <n>] [--head <hash>]\n' +
  '  --database-url  Postgres url (or set DATABASE_URL); an owner/admin role\n' +
  '  --after-id      skip rows up to this id (rows from before hashChain was on)\n' +
  '  --head          the row_hash the newest row must have, kept outside the database';

function parse(argv: readonly string[]) {
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (flag === undefined || !['--database-url', '--after-id', '--head'].includes(flag)) {
      throw new Error(`unknown argument ${flag}`);
    }
    if (value === undefined || value.startsWith('--')) throw new Error(`${flag} needs a value`);
    values[flag] = value;
    i += 1;
  }
  const url = values['--database-url'] ?? process.env.DATABASE_URL;
  if (!url) throw new Error('no database url: pass --database-url or set DATABASE_URL');
  const afterRaw = values['--after-id'];
  const afterId = afterRaw === undefined ? undefined : Number(afterRaw);
  if (afterId !== undefined && !Number.isInteger(afterId))
    throw new Error('--after-id is not an integer');
  return { url, afterId, head: values['--head'] };
}

async function main(): Promise<number> {
  let args: ReturnType<typeof parse>;
  try {
    args = parse(process.argv.slice(2));
  } catch (error) {
    console.error(`${error instanceof Error ? error.message : error}\n${USAGE}`);
    return 2;
  }
  const { default: postgres } = await import('postgres').catch(() => {
    throw new Error('audit-verify-chain needs the "postgres" package installed');
  });
  const { drizzle } = await import('drizzle-orm/postgres-js');
  const client = postgres(args.url, { max: 1, prepare: false });
  try {
    const result = await verifyTable(drizzle(client) as unknown as Handle, {
      afterId: args.afterId,
      head: args.head,
    });
    if (result.ok) {
      console.log(`audit chain ok: ${result.rows} rows, head ${result.head ?? 'none'}`);
      return 0;
    }
    console.error(`audit chain BROKEN at row id ${result.id}: ${result.reason}`);
    return 1;
  } finally {
    await client.end();
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 2;
  },
);
