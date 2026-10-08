import { and, asc, eq, gt, inArray, lte } from 'drizzle-orm';
import { auditAnchors } from './anchor-tables.js';
import { canonicalJsonV2 } from './canonical.js';
import { auditCheckpoints, auditSigningKeys } from './checkpoint-tables.js';
import { listCheckpoints } from './checkpoint.js';
import type { Handle } from './ledger.js';
import { type AuditEventRow, auditEvents } from './tables.js';

/**
 * Evidence bundles (`wtfalch-audit-evidence/1`), a directory of four files
 * that `audit-verify-bundle` checks offline: `manifest.json`,
 * `events.ndjson`, `checkpoints.json` and `anchors.json`. `buildBundle` returns
 * them as file name -> content; writing them out is the caller's job
 * (`audit-export-bundle`). The verifier is strict about text, so every
 * timestamp here is `Date#toISOString()` and every event line is
 * `canonicalJsonV2` output.
 */

export const BUNDLE_FORMAT = 'wtfalch-audit-evidence/1';

/** Rows read per query. */
const EVENT_PAGE = 1000;

/** `buildBundle` refused: the request or the data is not one a bundle can be made from. Nothing was returned. */
export class BundleRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BundleRefusal';
  }
}

export interface BuildBundleOptions {
  /** The ledger's name, as given to `sealCheckpoint`. */
  readonly ledger: string;
  /** First `seq`: 1, or one more than a checkpoint's `tree_size`. Default 1. */
  readonly from?: number;
  /** Last `seq`: a checkpoint's `tree_size`. Default the newest checkpoint's. */
  readonly to?: number;
}

const iso = (date: Date): string => date.toISOString();

/** The row as the verifier's event line holds it. Key order does not matter: the line is canonical. */
function eventOf(row: AuditEventRow): Record<string, unknown> {
  return {
    v: 2,
    seq: row.seq,
    received_at: row.receivedAt === null ? null : iso(row.receivedAt),
    occurred_at: iso(row.occurredAt),
    tenant_id: row.tenantId,
    tenant_display: row.tenantDisplay,
    actor_class: row.actorClass,
    actor_id: row.actorId,
    action: row.action,
    target_type: row.targetType,
    target_id: row.targetId,
    outcome: row.outcome,
    context: row.context,
    session_id: row.sessionId,
    reason: row.reason,
    reference: row.reference,
    request_id: row.requestId,
    ip: row.ip,
    user_agent: row.userAgent,
    tenant_visible: row.tenantVisible,
    schema_version: row.schemaVersion,
    subject_class: row.subjectClass,
    subject_id: row.subjectId,
    prev_hash: row.prevHash,
    content_hash: row.contentHash,
    actor_display: row.actorDisplay,
    target_display: row.targetDisplay,
    before: row.before,
    after: row.after,
    row_hash: row.rowHash,
    content_salt: row.contentSalt,
    erased_at: row.erasedAt === null ? null : iso(row.erasedAt),
    erasure_hash: row.erasureHash,
  };
}

/**
 * Builds the bundle for rows `from..to` of the ledger. The handle must see
 * every row and every table, like `verifyTable`'s: an owner or admin
 * connection, not the tenant-scoped runtime role. Throws `BundleRefusal` and
 * returns nothing when the range is not on checkpoint boundaries, when there
 * is no checkpoint, when `ledger` is not the checkpoints' ledger, when a row
 * in the range is not a sealed format 2 row, or when a row is erased but its
 * erasure is not sealed yet (run `ledger.erase()` again to seal it).
 * Reads the rows in pages; the files are built in memory.
 */
export async function buildBundle(
  handle: Handle,
  options: BuildBundleOptions,
): Promise<Record<string, string>> {
  const all = await listCheckpoints(handle);
  const newest = all[all.length - 1];
  if (!newest) throw new BundleRefusal('audit: there is no checkpoint to build a bundle from');
  if (all.some((c) => c.ledger !== options.ledger)) {
    throw new BundleRefusal("audit: the ledger name differs from the checkpoints'");
  }
  const from = options.from ?? 1;
  const to = options.to ?? newest.tree_size;
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 1 || to < from) {
    throw new BundleRefusal('audit: the range must be integers with 1 <= from <= to');
  }
  if (!all.some((c) => c.tree_size === to)) {
    throw new BundleRefusal('audit: "to" is not the size of a checkpoint');
  }
  if (from > 1 && !all.some((c) => c.tree_size === from - 1)) {
    throw new BundleRefusal(
      'audit: "from" is not 1 and not one more than the size of a checkpoint',
    );
  }

  const included = all.filter(
    (c) => c.tree_size === from - 1 || (c.tree_size >= from && c.tree_size <= to),
  );
  let base: { tree_size: number; frontier: string[] } | null = null;
  if (from > 1) {
    const [row] = await handle
      .select()
      .from(auditCheckpoints)
      .where(eq(auditCheckpoints.treeSize, from - 1));
    if (!row) throw new BundleRefusal('audit: the checkpoint before "from" is missing');
    base = { tree_size: row.treeSize, frontier: [...row.frontier] };
  }

  const lines: string[] = [];
  let last = from - 1;
  for (;;) {
    const page = await handle
      .select()
      .from(auditEvents)
      .where(and(gt(auditEvents.seq, last), lte(auditEvents.seq, to)))
      .orderBy(asc(auditEvents.seq))
      .limit(EVENT_PAGE);
    for (const row of page) {
      if (row.chainVersion !== 2 || row.seq !== last + 1 || row.rowHash === null) {
        throw new BundleRefusal(
          `audit: the rows after seq ${last} are missing or not sealed in format 2 (is this connection allowed to see every row?)`,
        );
      }
      if (row.erasedAt !== null && row.contentSalt !== null) {
        throw new BundleRefusal(
          `audit: the erasure of row seq ${row.seq} is not sealed yet; run erase() again, then build the bundle`,
        );
      }
      lines.push(`${canonicalJsonV2(eventOf(row))}\n`);
      last = row.seq;
    }
    if (page.length < EVENT_PAGE) break;
  }
  if (last !== to) {
    throw new BundleRefusal(
      `audit: the rows end at seq ${last}, before the range end ${to} (is this connection allowed to see every row?)`,
    );
  }

  const keyIds = [...new Set(included.map((c) => c.public_key))];
  const keys = await handle
    .select()
    .from(auditSigningKeys)
    .where(inArray(auditSigningKeys.publicKey, keyIds))
    .orderBy(asc(auditSigningKeys.createdAt), asc(auditSigningKeys.publicKey));
  const anchors = await handle
    .select()
    .from(auditAnchors)
    .where(
      inArray(
        auditAnchors.checkpointHash,
        included.map((c) => c.checkpoint_hash),
      ),
    )
    .orderBy(asc(auditAnchors.id));

  const manifest = {
    format: BUNDLE_FORMAT,
    generated_at: iso(new Date()),
    ledger: options.ledger,
    range: { from, to },
    event_count: lines.length,
    signing_keys: keys.map((k) => ({
      public_key: k.publicKey,
      created_at: iso(k.createdAt),
      retired_at: k.retiredAt === null ? null : iso(k.retiredAt),
    })),
    base,
  };
  return {
    'manifest.json': `${JSON.stringify(manifest, null, 2)}\n`,
    'events.ndjson': lines.join(''),
    'checkpoints.json': `${JSON.stringify({ checkpoints: included }, null, 2)}\n`,
    'anchors.json': `${JSON.stringify(
      {
        anchors: anchors.map((a) => ({
          checkpoint_hash: a.checkpointHash,
          provider: a.provider,
          token: a.token,
          token_hash: a.tokenHash,
          anchored_at: iso(a.anchoredAt),
        })),
      },
      null,
      2,
    )}\n`,
  };
}
