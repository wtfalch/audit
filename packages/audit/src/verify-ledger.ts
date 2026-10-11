import { asc, gt, isNotNull } from 'drizzle-orm';
import {
  type Checkpoint,
  type SigningKey,
  listCheckpoints,
  proveInclusion,
  verifyCheckpoint,
} from './checkpoint.js';
import type { Handle } from './ledger.js';
import { auditEvents } from './tables.js';
import { type TableVerifyResult, verifyTable } from './verify-table.js';

/**
 * The `verify()` a host runs beside `seal()` (`checkpoint.ts`): does this
 * ledger's whole hash chain still hold, do its checkpoints still verify
 * against the keys the host trusts, and do the rows each checkpoint covers
 * still hash to the root that checkpoint signed? A checkpoint's root is
 * trusted once at seal time (`sealCheckpoint` folds forward from the
 * previous checkpoint's stored frontier without ever rereading it) -- this
 * is the place that rereads it, so a ledger rewritten from scratch after
 * being sealed is caught here even when every row still chains to the one
 * before it.
 */

export interface VerifyLedgerOptions {
  /** The ledger name the checkpoints must all carry. */
  readonly ledger: string;
  /** The signing keys the host trusts; never the keys read back off `audit_signing_keys` alone. */
  readonly keys: readonly SigningKey[];
}

export type VerifyLedgerResult =
  | {
      readonly ok: true;
      /** `seq` of every row written after the last checkpoint: not yet sealed, and never reported as verified. Empty when every row is covered. */
      readonly unsealedSeqs: readonly number[];
    }
  | {
      readonly ok: false;
      readonly reason: 'ledger' | 'checkpoint' | 'root' | 'chain';
      /** `audit_events.id`, when `reason` is `'chain'`: the row that fails. */
      readonly id?: number;
      readonly checkpoint?: Checkpoint;
      readonly detail: string;
    };

/**
 * Verifies a ledger end to end: the chain (`verifyTable`), then every
 * checkpoint against `options.keys` and the rows it claims to cover
 * (`verifyCheckpoint` plus a reread of the root, through `proveInclusion`),
 * oldest first. The handle must see every row and every checkpoint, like
 * `verifyTable`'s: an owner or admin connection, not the tenant-scoped
 * runtime role.
 */
export async function verifyLedger(
  handle: Handle,
  options: VerifyLedgerOptions,
): Promise<VerifyLedgerResult> {
  const checkpoints = await listCheckpoints(handle);
  for (const checkpoint of checkpoints) {
    if (checkpoint.ledger !== options.ledger) {
      return {
        ok: false,
        reason: 'ledger',
        checkpoint,
        detail: `a checkpoint at tree_size ${checkpoint.tree_size} is for ledger "${checkpoint.ledger}", not "${options.ledger}"`,
      };
    }
    if (!(await verifyCheckpoint(checkpoint, options.keys))) {
      return {
        ok: false,
        reason: 'checkpoint',
        checkpoint,
        detail: `the checkpoint at tree_size ${checkpoint.tree_size} does not verify against the given keys`,
      };
    }
    try {
      await proveInclusion(handle, checkpoint.tree_size);
    } catch (_error) {
      return {
        ok: false,
        reason: 'root',
        checkpoint,
        detail: `the rows up to seq ${checkpoint.tree_size} no longer hash to the root sealed there; this ledger's head does not extend the one that checkpoint sealed`,
      };
    }
  }

  const chainResult: TableVerifyResult = await verifyTable(handle);
  if (!chainResult.ok) {
    return {
      ok: false,
      reason: 'chain',
      id: chainResult.id,
      detail: `row id ${chainResult.id} fails verification: ${chainResult.reason}`,
    };
  }

  const last = checkpoints[checkpoints.length - 1];
  const unsealed = await handle
    .select({ seq: auditEvents.seq })
    .from(auditEvents)
    .where(last ? gt(auditEvents.seq, last.tree_size) : isNotNull(auditEvents.seq))
    .orderBy(asc(auditEvents.seq));
  const unsealedSeqs = unsealed.map((row) => row.seq).filter((seq): seq is number => seq !== null);
  return { ok: true, unsealedSeqs };
}
