import { asc, gt } from 'drizzle-orm';
import { verifyChain } from './chain.js';
import type { ChainVerifyResult } from './chain.js';
import type { Handle } from './ledger.js';
import { auditEvents } from './tables.js';

export type TableVerifyResult =
  | { readonly ok: true; readonly rows: number; readonly head: string | null }
  | {
      readonly ok: false;
      /** The `audit_events.id` of the first row that failed. */
      readonly id: number;
      readonly reason: Extract<ChainVerifyResult, { ok: false }>['reason'];
    };

export interface VerifyTableOptions {
  /** Start after this row id (exclusive), for a table whose early rows predate `hashChain` and are `'unsealed'`. The first row checked is not linked back to anything. */
  readonly afterId?: number;
  /** The `row_hash` the newest row must have, from an anchor kept outside the database. Without it, rows deleted off the end are undetectable. */
  readonly head?: string;
  /** Rows read per query; the chain is verified page by page, carrying the last `row_hash` forward. Default 5,000. */
  readonly pageSize?: number;
}

/**
 * `verifyChain` over a whole live table: reads `audit_events` by `id`
 * ascending in pages and verifies each page linked to the one before, so a
 * large ledger never has to fit in memory. The handle must see every row,
 * so it is an owner or admin connection, not the tenant-scoped runtime role
 * (row-level security would hide the other tenants' rows and the chain would
 * look broken). Reports the first bad row's id, not a position in a page.
 */
export async function verifyTable(
  handle: Handle,
  options: VerifyTableOptions = {},
): Promise<TableVerifyResult> {
  const pageSize = Math.max(1, options.pageSize ?? 5000);
  let lastId = options.afterId ?? 0;
  let previous: string | undefined;
  let count = 0;
  for (;;) {
    const page = await handle
      .select()
      .from(auditEvents)
      .where(gt(auditEvents.id, lastId))
      .orderBy(asc(auditEvents.id))
      .limit(pageSize);
    if (page.length === 0) break;
    const result = await verifyChain(page, previous === undefined ? {} : { origin: previous });
    if (!result.ok)
      return { ok: false, id: page[result.index]?.id ?? lastId, reason: result.reason };
    const last = page[page.length - 1];
    if (!last) break;
    lastId = last.id;
    previous = last.rowHash ?? undefined;
    count += page.length;
    if (page.length < pageSize) break;
  }
  const head = previous ?? null;
  if (options.head !== undefined && head !== options.head) {
    return { ok: false, id: lastId, reason: 'head' };
  }
  return { ok: true, rows: count, head };
}
