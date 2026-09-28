import type { LedgerReadPage, LedgerReadRow } from './read.js';

/** One app whose `GET /v1/audit` Boule fans out to: files, ai, integrations, cms, ... */
export interface LedgerSource {
  /** How a merged row names where it came from, and the key `cursors`/the result's `nextCursors` are keyed by. */
  readonly name: string;
  /** Origin only, no path: `https://files.example.com`. `fetchLedgerPage` appends `/v1/audit`. */
  readonly baseUrl: string;
  /** The keys-issued bearer secret this source's `authorize` port recognises for this tenant. */
  readonly credential: string;
}

export interface FetchLedgerPageOptions {
  readonly tenant: string;
  readonly cursor?: string;
  readonly limit?: number;
  /** Defaults to the global `fetch`; a test passes a fake. */
  readonly fetchImpl?: typeof fetch;
}

/** Thrown by `fetchLedgerPage` when a source answers a non-2xx status. `code` is the wire error's `code` field, or `'unavailable'` when the body does not parse as one. */
export class LedgerReadError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'LedgerReadError';
  }
}

/** One page from one source's `ledgerReadHandler`, over plain `fetch`. Never merges -- `fetchMergedLedgerPage` does that across several sources. */
export async function fetchLedgerPage(
  source: LedgerSource,
  options: FetchLedgerPageOptions,
): Promise<LedgerReadPage> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const url = new URL('/v1/audit', source.baseUrl);
  url.searchParams.set('tenant', options.tenant);
  if (options.cursor) url.searchParams.set('cursor', options.cursor);
  if (options.limit !== undefined) url.searchParams.set('limit', String(options.limit));

  const response = await fetchImpl(url, {
    headers: { authorization: `Bearer ${source.credential}` },
  });
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    const error =
      typeof body === 'object' && body !== null && 'error' in body
        ? (body as { error?: { code?: unknown; message?: unknown } }).error
        : undefined;
    const code = typeof error?.code === 'string' ? error.code : 'unavailable';
    const message = typeof error?.message === 'string' ? error.message : 'request failed';
    throw new LedgerReadError(response.status, code, message);
  }
  return (await response.json()) as LedgerReadPage;
}

export interface MergedLedgerRow extends LedgerReadRow {
  /** The `LedgerSource.name` this row came from. */
  readonly source: string;
}

export interface MergedLedgerPage {
  /** Every source's rows for this round, newest first. */
  readonly items: readonly MergedLedgerRow[];
  /** Each source's own next-page cursor, `null` where that source has no more. Pass the whole map back as `cursors` to page every source forward together. */
  readonly nextCursors: Readonly<Record<string, string | null>>;
  /** A source that failed this round, by name, with why. Its rows from earlier rounds are unaffected; this round just has fewer of them. */
  readonly errors: Readonly<Record<string, string>>;
}

export interface FetchMergedLedgerPageOptions {
  readonly tenant: string;
  readonly sources: readonly LedgerSource[];
  /** This source's cursor from a previous `nextCursors`, or omitted to start it from page one. */
  readonly cursors?: Readonly<Record<string, string | undefined>>;
  /** Applied per source, not to the merged total: each source is asked for up to `limit` rows before the merge trims to it. */
  readonly limit?: number;
  readonly fetchImpl?: typeof fetch;
}

/**
 * One page from each of several apps' `ledgerReadHandler`, fetched in
 * parallel and merged by `occurredAt` descending -- what Boule shows as one
 * company-wide security log over ledgers that stay per app (audit#29).
 *
 * Each source keeps its own keyset cursor: there is no single cursor that
 * orders every source's rows together, so `nextCursors` hands back one per
 * source rather than pretending there is a global next page. A source that
 * fails does not fail the call -- it is missing from `items` for this round
 * and named in `errors`, so one app being down does not blank the whole log.
 */
export async function fetchMergedLedgerPage(
  options: FetchMergedLedgerPageOptions,
): Promise<MergedLedgerPage> {
  const { tenant, sources, cursors = {}, limit, fetchImpl } = options;

  const results = await Promise.all(
    sources.map(async (source) => {
      try {
        const page = await fetchLedgerPage(source, {
          tenant,
          cursor: cursors[source.name],
          limit,
          fetchImpl,
        });
        return { source, page, error: null as string | null };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { source, page: null as LedgerReadPage | null, error: message };
      }
    }),
  );

  const items: MergedLedgerRow[] = [];
  const nextCursors: Record<string, string | null> = {};
  const errors: Record<string, string> = {};
  for (const { source, page, error } of results) {
    if (error !== null || !page) {
      errors[source.name] = error ?? 'request failed';
      continue;
    }
    for (const row of page.items) items.push({ ...row, source: source.name });
    nextCursors[source.name] = page.nextCursor;
  }

  items.sort((a, b) => {
    if (a.occurredAt !== b.occurredAt) return a.occurredAt < b.occurredAt ? 1 : -1;
    return b.id - a.id;
  });

  return { items, nextCursors, errors };
}
