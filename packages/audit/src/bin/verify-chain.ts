#!/usr/bin/env node
import { verifyTable } from '../verify-table.js';

/**
 * `audit-verify-chain --database-url <url> [--schema <name>] [--after-id <n>] [--head <hash>]`
 *
 * Runs `verifyChain` over the whole `audit_events` table and exits 0 when
 * the chain holds, 1 when it does not (naming the first bad row), 2 when it
 * could not run (bad arguments, no connection), 3 when the table read 0 rows
 * (nothing was verified: an empty ledger, or a role that row-level security
 * hides every row from). The URL may also come from
 * `DATABASE_URL`. Connect as the table's owner or an admin, not the runtime
 * role: row-level security hides other tenants' rows from that role.
 * `--schema` names the schema the host migrated into (its `search_path`).
 *
 * `@wtfalch/db` is an optional peer; this is the only file that imports it,
 * and the one place this package opens a connection: an operator tool, not
 * the library.
 */
const USAGE =
  'usage: audit-verify-chain --database-url <url> [--schema <name>] [--after-id <n>] [--head <hash>]\n' +
  '  --database-url  Postgres url (or set DATABASE_URL); an owner/admin role\n' +
  "  --schema        the schema audit_events lives in (default: the connection's own search_path)\n" +
  '  --after-id      skip rows up to this id (rows from before hashChain was on)\n' +
  '  --head          the row_hash the newest row must have, kept outside the database';

function parse(argv: readonly string[]) {
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (
      flag === undefined ||
      !['--database-url', '--schema', '--after-id', '--head'].includes(flag)
    ) {
      throw new Error(`unknown argument ${flag}`);
    }
    if (value === undefined || value.startsWith('--')) throw new Error(`${flag} needs a value`);
    values[flag] = value;
    i += 1;
  }
  const url = values['--database-url'] ?? process.env.DATABASE_URL;
  if (!url) throw new Error('no database url: pass --database-url or set DATABASE_URL');
  const schema = values['--schema'];
  if (schema === '') throw new Error('--schema is empty');
  const afterRaw = values['--after-id'];
  const afterId = afterRaw === undefined ? undefined : Number(afterRaw);
  if (afterId !== undefined && !Number.isInteger(afterId))
    throw new Error('--after-id is not an integer');
  const head = values['--head'];
  if (head === '') throw new Error('--head is empty');
  return { url, schema, afterId, head };
}

async function main(): Promise<number> {
  let args: ReturnType<typeof parse>;
  try {
    args = parse(process.argv.slice(2));
  } catch (error) {
    console.error(`${error instanceof Error ? error.message : error}\n${USAGE}`);
    return 2;
  }
  const { createDatabase } = await import('@wtfalch/db/postgres').catch(() => {
    throw new Error('audit-verify-chain needs the "@wtfalch/db" package installed');
  });
  const { withDrizzle } = await import('@wtfalch/db/drizzle');
  const { url } = args;
  const connection = createDatabase({
    url: () => url,
    max: 1,
    applicationName: 'audit-verify-chain',
    ...(args.schema === undefined ? {} : { searchPath: [args.schema, 'public'] }),
  });
  try {
    const result = await verifyTable(withDrizzle(connection, { schema: {} }).orm, {
      afterId: args.afterId,
      head: args.head,
    });
    if (result.ok && result.rows === 0) {
      console.error(
        'warning: audit chain has 0 rows, nothing was verified. Is this an owner/admin connection? The runtime role reads no rows under row-level security.',
      );
      return 3;
    }
    if (result.ok) {
      console.log(`audit chain ok: ${result.rows} rows, head ${result.head ?? 'none'}`);
      return 0;
    }
    console.error(`audit chain BROKEN at row id ${result.id}: ${result.reason}`);
    return 1;
  } finally {
    await connection.close({ timeoutMs: 5000 });
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
