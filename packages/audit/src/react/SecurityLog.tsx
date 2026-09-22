'use client';

/**
 * The security-log reader every stamped company was hand-rolling from raw
 * rows: `app-template/src/lib/authz/audit.ts` built `SecurityLogEntry`,
 * `SecurityLogPage` and their rendering from scratch, once per app.
 * `docs/plans/reporting.md` called this "rows for a security-log page on
 * `@wtfalch/design`"; this is that.
 *
 * **Prose is the host's, the row is the package's.** Every action name here
 * is the host's own vocabulary (`membership.role_changed`, `invoice.paid`),
 * and only the host knows how to say it as a sentence a reader can act on.
 * `ActivityLine` (`@wtfalch/design`) draws that line already -- its own
 * `sentence` prop is required, with no default -- and this respects it: no
 * default here either.
 *
 * **Keyset, not counted.** `ledger.page()` returns a keyset cursor
 * (`next: { occurredAt, id } | null`), never a total: an append-only table
 * this large does not offer one cheaply, and erasure never shrinks the row
 * count. `@wtfalch/design`'s `Pagination` is built for a server that counts
 * (a position, a limit, a total); a keyset log only ever answers "is there
 * more", so this ships a plain "Load more" instead of forcing that mismatch
 * onto a control it does not fit.
 */

import {
  type ActivityActor,
  type ActivityEvent,
  ActivityLine,
  Button,
  Empty,
} from '@wtfalch/design';
import type { ReactNode } from 'react';
import type { AuditEventRow } from '../tables.js';

/**
 * How one row's actor becomes the disc `ActivityLine` draws. Overridable: a
 * host's `actor_class` values are its own closed set (the vocabulary it
 * passed to `createLedger`), not this package's, so the default below only
 * recognises the classes `CORE` ships and treats everything else as an
 * agent rather than guessing.
 */
export type SecurityLogActorFor = (row: AuditEventRow) => ActivityActor;

const defaultActorFor: SecurityLogActorFor = (row) => {
  if (row.actorClass === 'api_key') return { kind: 'key', label: row.actorDisplay };
  if (row.actorClass === 'human')
    return { kind: 'person', name: row.actorDisplay, address: row.actorId };
  return { kind: 'agent', label: row.actorDisplay };
};

/**
 * How one row's outcome becomes `ActivityLine`'s fixed three
 * (`success` / `blocked` / `refused`). A host's `outcome` column is its own
 * closed set too; the default reads only `'success'` as success and marks
 * everything else `'refused'`, and a host that wants `'error'` rows drawn as
 * `'blocked'` instead passes its own function.
 */
export type SecurityLogOutcomeFor = (row: AuditEventRow) => ActivityEvent['outcome'];

const defaultOutcomeFor: SecurityLogOutcomeFor = (row) =>
  row.outcome === 'success' ? 'success' : 'refused';

/** What `ledger.page()` returns: newest first, keyset on `(occurred_at, id)`. */
export interface SecurityLogPage {
  readonly items: readonly AuditEventRow[];
  readonly next: { readonly occurredAt: Date; readonly id: number } | null;
}

export interface SecurityLogProps {
  readonly page: SecurityLogPage;
  /** The row, in prose: "Marcus Yuen invited jordan.malik as a Member." See
   *  the module docblock for why this has no default. */
  readonly sentence: (row: AuditEventRow) => ReactNode;
  readonly actor?: SecurityLogActorFor;
  readonly outcome?: SecurityLogOutcomeFor;
  /**
   * Called with `page.next` when "Load more" is pressed. Omitted, no
   * control renders: a host wiring its own scroll trigger or its own
   * button reads `page.next` directly instead.
   */
  readonly onLoadMore?: (cursor: { readonly occurredAt: Date; readonly id: number }) => void;
  /** Disables "Load more" while a page is in flight. */
  readonly loading?: boolean;
  readonly emptyLabel?: string;
  readonly className?: string;
}

/** The tenant's own security log, or an operator's: rows on `ActivityLine`, and a "Load more" over the keyset cursor. Mounts wherever the host already reads `ledger.page()`. */
export function SecurityLog({
  page,
  sentence,
  actor = defaultActorFor,
  outcome = defaultOutcomeFor,
  onLoadMore,
  loading = false,
  emptyLabel = 'Nothing here yet.',
  className,
}: SecurityLogProps) {
  if (page.items.length === 0) {
    return <Empty className={className}>{emptyLabel}</Empty>;
  }

  const next = page.next;

  return (
    <div className={className}>
      <ol className="m-0 list-none p-0">
        {page.items.map((row) => (
          <li key={row.id}>
            <ActivityLine
              actor={actor(row)}
              sentence={sentence(row)}
              event={{ name: row.action, id: row.id, outcome: outcome(row) }}
              at={row.occurredAt}
            />
          </li>
        ))}
      </ol>
      {next && onLoadMore ? (
        <Button
          kind="ghost"
          size="sm"
          busy={loading}
          disabled={loading}
          onClick={() => onLoadMore(next)}
        >
          Load more
        </Button>
      ) : null}
    </div>
  );
}
