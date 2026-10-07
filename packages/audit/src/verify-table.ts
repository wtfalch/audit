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
  /** Start after this row id (exclusive), for a table whose early rows predate `hashChain` and are `'unsealed'`. The first row checked is not linked back to anything. Without it the first row must have no `prev_hash`, so deleted early rows are caught. */
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
  let previousSeq: number | undefined = options.afterId === undefined ? 0 : undefined;
  let count = 0;
  for (;;) {
    const page = await handle
      .select()
      .from(auditEvents)
      .where(gt(auditEvents.id, lastId))
      .orderBy(asc(auditEvents.id))
      .limit(pageSize);
    if (page.length === 0) break;
    // A whole-table run anchors the front with origin null, so deleting the earliest rows breaks the link. With afterId the start is a window, so the first row is not linked back.
    const origin =
      previous !== undefined ? previous : options.afterId === undefined ? null : undefined;
    const result = await verifyChain(page, {
      ...(origin === undefined ? {} : { origin }),
      ...(previousSeq === undefined ? {} : { seqOrigin: previousSeq }),
    });
    if (!result.ok)
      return { ok: false, id: page[result.index]?.id ?? lastId, reason: result.reason };
    const last = page[page.length - 1];
    if (!last) break;
    lastId = last.id;
    previous = last.rowHash ?? undefined;
    for (const row of page) if (row.seq !== null) previousSeq = row.seq;
    count += page.length;
    if (page.length < pageSize) break;
  }
  const head = previous ?? null;
  if (options.head !== undefined && head !== options.head) {
    return { ok: false, id: lastId, reason: 'head' };
  }
  return { ok: true, rows: count, head };
}
