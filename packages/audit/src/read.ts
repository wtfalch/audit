import { ServiceError, serviceErrorResponse } from '@wtfalch/contracts';
import type { PageCursor } from '@wtfalch/contracts';
import type { Handle, Ledger, Page } from './ledger.js';
import { scopeAuditTenant } from './ledger.js';
import type { AuditEventRow } from './tables.js';

/**
 * `GET /v1/audit`'s row, a deliberate subset of `AuditEventRow`: what a
 * cross-app reader (Boule fanning out to files, ai, integrations, ...)
 * needs to render one line of a security log, and nothing an app's own
 * `before`/`after` payload, request metadata (`ip`, `userAgent`,
 * `sessionId`, `requestId`) or hash-chain internals would leak across an
 * app boundary that `tenantVisible` alone does not gate. A host that wants
 * those stays on `ledger.page()` directly, inside its own trusted base.
 */
export interface LedgerReadRow {
  readonly id: number;
  readonly occurredAt: string;
  readonly tenantId: string | null;
  readonly actorClass: string;
  readonly actorId: string;
  readonly actorDisplay: string;
  readonly action: string;
  readonly targetType: string;
  readonly targetId: string;
  readonly targetDisplay: string | null;
  readonly tenantDisplay: string | null;
  readonly outcome: string;
  readonly context: string;
  readonly reason: string | null;
  readonly reference: string | null;
  readonly subjectClass: string | null;
  readonly subjectId: string | null;
}

/**
 * The estate's list-page convention (`@wtfalch/contracts` ADR 0008): a
 * request's `cursor` + `limit`, a response's `nextCursor`, typed as
 * `PageCursor` (`string | null`).
 */
export interface LedgerReadPage {
  readonly items: readonly LedgerReadRow[];
  readonly nextCursor: PageCursor;
}

/**
 * What a host's `authorize` resolves a request's credential to: the one
 * tenant it is scoped to. `null` means the request carries no credential
 * this host recognises, or one this endpoint refuses outright -- the
 * handler answers `unauthorized` either way, never learning why.
 */
export interface AuthorizedRead {
  readonly tenantId: string;
}

/**
 * The port this handler is built against, not a dependency: the host
 * supplies a function that turns a `Request` into the one tenant its
 * credential is scoped to, or `null`. A host wires this from
 * `@wtfalch/keys/issued`'s `check()` -- see this package's README, "Reading
 * across apps" -- but `@wtfalch/audit` itself imports nothing from `keys`:
 * the port is the whole contract.
 */
export type Authorize = (
  request: Request,
) => Promise<AuthorizedRead | null> | AuthorizedRead | null;

export interface LedgerReadHandlerOptions {
  readonly ledger: Pick<Ledger, 'page'>;
  /** The connection `page()` reads on. A transaction is opened per request to scope it with `scopeAuditTenant`; a plain pooled handle works too. */
  readonly handle: Handle;
  readonly authorize: Authorize;
  /** Default 50, same as `ledger.page()`'s own default. */
  readonly defaultLimit?: number;
}

function toReadRow(row: AuditEventRow): LedgerReadRow {
  return {
    id: row.id,
    occurredAt: row.occurredAt.toISOString(),
    tenantId: row.tenantId,
    actorClass: row.actorClass,
    actorId: row.actorId,
    actorDisplay: row.actorDisplay,
    action: row.action,
    targetType: row.targetType,
    targetId: row.targetId,
    targetDisplay: row.targetDisplay,
    tenantDisplay: row.tenantDisplay,
    outcome: row.outcome,
    context: row.context,
    reason: row.reason,
    reference: row.reference,
    subjectClass: row.subjectClass,
    subjectId: row.subjectId,
  };
}

/** The wire cursor: base64url JSON of `Page['next']`. Opaque to a caller on purpose -- only this module's encode/decode agree on the shape inside. */
function encodeCursor(next: Page['next']): PageCursor {
  if (!next) return null;
  const json = JSON.stringify({ occurredAt: next.occurredAt.toISOString(), id: next.id });
  return Buffer.from(json, 'utf8').toString('base64url');
}

/** `null` on anything that is not exactly a well-formed cursor: malformed base64, malformed JSON, or the wrong shape. The caller answers `conflict`. */
function decodeCursor(cursor: string): { occurredAt: Date; id: number } | null {
  try {
    const json = Buffer.from(cursor, 'base64url').toString('utf8');
    const parsed: unknown = JSON.parse(json);
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      typeof (parsed as { occurredAt?: unknown }).occurredAt !== 'string' ||
      typeof (parsed as { id?: unknown }).id !== 'number'
    ) {
      return null;
    }
    const { occurredAt, id } = parsed as { occurredAt: string; id: number };
    const at = new Date(occurredAt);
    if (Number.isNaN(at.getTime()) || !Number.isInteger(id)) return null;
    return { occurredAt: at, id };
  } catch {
    return null;
  }
}

/**
 * A fetch-shaped handler for `GET /v1/audit?tenant=&cursor=&limit=`: only
 * `tenantVisible` rows for the one tenant the caller's credential is scoped
 * to, as `LedgerReadRow`, paged with the estate's `cursor`/`limit` in,
 * `nextCursor` out convention. A host mounts it directly (a Next.js route
 * handler, a Worker's `fetch`) -- this package still answers no HTTP of its
 * own; the host is what listens.
 *
 * Every read runs inside a transaction scoped with `scopeAuditTenant`, so
 * row-level security backs the tenant filter even if a future change to
 * this function's own `tenantId` condition slipped.
 *
 * Refusals: no credential or an unrecognised one is `unauthorized` (401); a
 * credential scoped to a different tenant than the `tenant` query parameter
 * is `forbidden` (403), never silently substituted; a missing `tenant` or a
 * malformed `limit` is `invalid_request` (400); a `cursor` that fails to
 * decode is `conflict` (409), meaning "restart from the first page"
 * (`@wtfalch/contracts` ADR 0008).
 */
export function ledgerReadHandler(
  options: LedgerReadHandlerOptions,
): (request: Request) => Promise<Response> {
  const { ledger, handle, authorize, defaultLimit = 50 } = options;

  return async (request: Request): Promise<Response> => {
    const auth = await authorize(request);
    if (!auth) {
      return serviceErrorResponse(new ServiceError('unauthorized', 'no valid credential'));
    }

    const url = new URL(request.url);
    const tenant = url.searchParams.get('tenant');
    if (!tenant) {
      return serviceErrorResponse(
        new ServiceError('invalid_request', 'the "tenant" query parameter is required'),
      );
    }
    if (auth.tenantId !== tenant) {
      return serviceErrorResponse(
        new ServiceError('forbidden', 'this credential is not scoped to the requested tenant'),
      );
    }

    const limitParam = url.searchParams.get('limit');
    let limit = defaultLimit;
    if (limitParam !== null) {
      if (!/^\d+$/.test(limitParam)) {
        return serviceErrorResponse(
          new ServiceError(
            'invalid_request',
            'the "limit" query parameter must be a positive integer',
          ),
        );
      }
      limit = Number(limitParam);
    }

    let after: { occurredAt: Date; id: number } | undefined;
    const cursorParam = url.searchParams.get('cursor');
    if (cursorParam !== null) {
      const decoded = decodeCursor(cursorParam);
      if (!decoded) {
        return serviceErrorResponse(
          new ServiceError(
            'conflict',
            'the cursor is invalid or expired; restart from the first page',
          ),
        );
      }
      after = decoded;
    }

    const page = await handle.transaction(async (tx) => {
      await scopeAuditTenant(tx, tenant);
      return ledger.page(tx, { tenantId: tenant, tenantVisibleOnly: true, limit, after });
    });

    const body: LedgerReadPage = {
      items: page.items.map(toReadRow),
      nextCursor: encodeCursor(page.next),
    };
    return Response.json(body, { status: 200, headers: { 'cache-control': 'no-store' } });
  };
}
