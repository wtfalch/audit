#!/usr/bin/env node
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { BundleRefusal, buildBundle } from '../bundle.js';

/**
 * `audit-export-bundle --database-url <url> [--schema <name>] --ledger <name> --out <dir> [--from <seq>] [--to <seq>]`
 *
 * Writes an evidence bundle (`bundle.ts`) into `--out`, a directory that does
 * not exist yet or is empty, and exits 0. Exits 1 when the bundle cannot be
 * made from this ledger (no checkpoint, a range off checkpoint boundaries, a
 * row erased but not sealed yet, a ledger name that is not the checkpoints'),
 * 2 when it could not run (bad arguments, no connection, `--out` not empty).
 * The URL may also come from `DATABASE_URL`. Connect as the table's owner or
 * an admin, not the runtime role: row-level security hides other tenants'
 * rows from that role. `--schema` names the schema the host migrated into.
 *
 * Everything is built in memory before the first file is written. If a write
 * fails, the files this run wrote are removed and the exit code is 2;
 * `manifest.json` is written last, so a bundle left half written (the
 * process killed) has no manifest and `audit-verify-bundle` rejects it.
 *
 * `@wtfalch/db` is an optional peer; this is the only file besides
 * verify-chain.ts that imports it.
 */
const USAGE =
  'usage: audit-export-bundle --database-url <url> [--schema <name>] --ledger <name> --out <dir> [--from <seq>] [--to <seq>]\n' +
  '  --database-url  Postgres url (or set DATABASE_URL); an owner/admin role\n' +
  "  --schema        the schema audit_events lives in (default: the connection's own search_path)\n" +
  '  --ledger        the ledger name given to sealCheckpoint\n' +
  '  --out           the directory to write the bundle into; new or empty\n' +
  '  --from          first seq: 1 (default) or one more than a checkpoint size\n' +
  '  --to            last seq: a checkpoint size (default the newest checkpoint)';

const FLAGS = ['--database-url', '--schema', '--ledger', '--out', '--from', '--to'];

function seqOf(flag: string, raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const n = Number(raw);
  if (!/^[0-9]+$/.test(raw) || !Number.isSafeInteger(n) || n < 1)
    throw new Error(`${flag} is not a positive integer`);
  return n;
}

function parse(argv: readonly string[]) {
  const values: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (flag === undefined || !FLAGS.includes(flag)) throw new Error(`unknown argument ${flag}`);
    if (value === undefined || value.startsWith('--')) throw new Error(`${flag} needs a value`);
    values[flag] = value;
    i += 1;
  }
  const url = values['--database-url'] ?? process.env.DATABASE_URL;
  if (!url) throw new Error('no database url: pass --database-url or set DATABASE_URL');
  const schema = values['--schema'];
  if (schema === '') throw new Error('--schema is empty');
  const ledger = values['--ledger'];
  if (!ledger) throw new Error('--ledger is required');
  const out = values['--out'];
  if (!out) throw new Error('--out is required');
  const from = seqOf('--from', values['--from']);
  const to = seqOf('--to', values['--to']);
  if (from !== undefined && to !== undefined && from > to) throw new Error('--from is after --to');
  return { url, schema, ledger, out, from, to };
}

/** Throws unless `dir` is missing or holds nothing. */
function assertEmptyOut(dir: string): void {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw new Error('--out cannot be read as a directory');
  }
  if (names.length > 0) throw new Error('--out already holds files');
}

async function main(): Promise<number> {
  let args: ReturnType<typeof parse>;
  try {
    args = parse(process.argv.slice(2));
    assertEmptyOut(args.out);
  } catch (error) {
    console.error(`${error instanceof Error ? error.message : error}\n${USAGE}`);
    return 2;
  }
  const { createDatabase } = await import('@wtfalch/db/postgres').catch(() => {
    throw new Error('audit-export-bundle needs the "@wtfalch/db" package installed');
  });
  const { withDrizzle } = await import('@wtfalch/db/drizzle');
  const { url } = args;
  const connection = createDatabase({
    url: () => url,
    max: 1,
    applicationName: 'audit-export-bundle',
    ...(args.schema === undefined ? {} : { searchPath: [args.schema, 'public'] }),
  });
  let files: Record<string, string>;
  try {
    files = await buildBundle(withDrizzle(connection, { schema: {} }).orm, {
      ledger: args.ledger,
      from: args.from,
      to: args.to,
    });
  } catch (error) {
    if (error instanceof BundleRefusal) {
      console.error(error.message);
      return 1;
    }
    throw error;
  } finally {
    await connection.close({ timeoutMs: 5000 });
  }
  // manifest.json last: a bundle cut short has none, and the verifier refuses it.
  const names = Object.keys(files).sort((a, b) =>
    a === 'manifest.json' ? 1 : b === 'manifest.json' ? -1 : 0,
  );
  const written: string[] = [];
  try {
    mkdirSync(args.out, { recursive: true });
    for (const name of names) {
      writeFileSync(join(args.out, name), files[name] ?? '', { flag: 'wx' });
      written.push(name);
    }
  } catch (_error) {
    for (const name of written) rmSync(join(args.out, name), { force: true });
    console.error(
      'audit-export-bundle: writing the bundle failed; the files it wrote were removed',
    );
    return 2;
  }
  const events = (files['events.ndjson'] ?? '').split('\n').length - 1;
  console.log(`audit bundle written: ${events} events, ${names.length} files in ${args.out}`);
  return 0;
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
