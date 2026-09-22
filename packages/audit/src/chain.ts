import type { AuditEventRow } from './tables.js';

/**
 * Hash chaining, opt in (`LedgerOptions.hashChain`). Ports
 * `@wtfalch/authz`'s `audit-chain.ts` design -- sorted-key canonical JSON,
 * `globalThis.crypto.subtle` SHA-256, `prev_hash` chaining, a salted
 * `content_hash` over the row's erasable fields so `audit_erase_person`
 * keeps working without breaking the chain -- onto `audit_events`'s actual
 * columns, which is not `authzEvents`: no `credential_chain`, and
 * `target_display` beside `actor_display` as erasable content (0.4.0).
 *
 * `sealRow` is called from `ledger.sign()` (snake_case `AuditRow`, what
 * `sign()` already builds before insert); `verifyChain` is called by a host
 * holding what `ledger.page()`/`exportRows()` return (camelCase
 * `AuditEventRow`). Both funnel through the same `rowHashPayload`/
 * `contentPayload` builders below, which always key their canonical JSON
 * snake_case -- a `row_hash` sealed from one shape and recomputed from the
 * other would silently never match otherwise.
 */

/**
 * Every field a row's hash chain is taken over or salted with, snake_case
 * regardless of the caller's own shape. Exactly what `sign()` already has
 * in hand as `row: AuditRow` before it adds the chain fields and inserts --
 * `AuditRow`'s own `target_display`/`tenant_display` are `.nullish()`
 * (`string | null | undefined`), so `sign()` narrows both to `?? null`
 * before calling `sealRow`, same as it already does building the insert.
 */
export interface SealInput {
  readonly occurred_at: string | Date;
  readonly tenant_id: string | null;
  readonly tenant_display: string | null;
  readonly actor_class: string;
  readonly actor_id: string;
  readonly actor_display: string;
  readonly action: string;
  readonly target_type: string;
  readonly target_id: string;
  readonly target_display: string | null;
  readonly outcome: string;
  readonly context: string;
  readonly session_id: string | null;
  readonly reason: string | null;
  readonly reference: string | null;
  readonly request_id: string | null;
  readonly ip: string | null;
  readonly user_agent: string | null;
  readonly tenant_visible: boolean;
  readonly before: unknown;
  readonly after: unknown;
  readonly schema_version: number;
  readonly subject_class: string | null;
  readonly subject_id: string | null;
}

/** The four columns `sealRow` computes, ready to merge into the insert. */
export interface SealedChain {
  readonly prev_hash: string | null;
  readonly row_hash: string;
  readonly content_hash: string;
  readonly content_salt: string;
}

/**
 * Deterministic JSON: object keys sorted at every depth, no inserted
 * whitespace, arrays kept in their given order. Every value this module
 * hashes comes from `rowHashPayload`/`contentPayload`, both of which
 * already reject anything `schema.ts`'s `isJsonValue` would -- `before`/
 * `after` were validated at `sign()` time and never change after (erasure
 * replaces them wholesale, and reseals nothing) -- so this never needs to
 * refuse a value the way authz's copy does.
 */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(obj[key])}`).join(',')}}`;
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  globalThis.crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/** The row's erasable content, salted: what `audit_erase_person` is allowed to replace. */
function contentPayload(row: SealInput): unknown {
  return {
    actor_display: row.actor_display,
    target_display: row.target_display,
    before: row.before,
    after: row.after,
  };
}

/**
 * What `erasure_hash` commits to: this row's `row_hash` (so an `erased_at`
 * cannot be lifted onto a different row) and `erased_at` itself (unsalted
 * -- the fact and instant of erasure stay checkable forever, unlike the
 * content `content_salt` protects).
 */
function erasurePayload(rowHash: string, erasedAt: string | Date): unknown {
  return { row_hash: rowHash, erased_at: new Date(erasedAt).toISOString() };
}

/**
 * Every key `row_hash` covers: every `SealInput` field except the ones
 * erasure is allowed to change (`actor_display`, `target_display`,
 * `before`, `after`), plus `prev_hash` and `content_hash` -- so `row_hash`
 * also pins the row's position in the chain and its (possibly erased)
 * content commitment. `id` is excluded: it is not known before insert.
 */
function rowHashPayload(row: SealInput, prevHash: string | null, contentHash: string) {
  return {
    occurred_at: new Date(row.occurred_at).toISOString(),
    tenant_id: row.tenant_id,
    tenant_display: row.tenant_display,
    actor_class: row.actor_class,
    actor_id: row.actor_id,
    action: row.action,
    target_type: row.target_type,
    target_id: row.target_id,
    outcome: row.outcome,
    context: row.context,
    session_id: row.session_id,
    reason: row.reason,
    reference: row.reference,
    request_id: row.request_id,
    ip: row.ip,
    user_agent: row.user_agent,
    tenant_visible: row.tenant_visible,
    schema_version: row.schema_version,
    subject_class: row.subject_class,
    subject_id: row.subject_id,
    prev_hash: prevHash,
    content_hash: contentHash,
  };
}

/**
 * Seal one row before it is inserted: a fresh random `content_salt`,
 * `content_hash` over the salted erasable content, `row_hash` over
 * everything else (including `content_hash` and `prevHash`), and
 * `prev_hash` set to `prevHash` -- the chain's current tail's `row_hash`,
 * or `null` for the chain's first row. Called from inside `sign()`'s
 * advisory-locked transaction, which is what makes `prevHash` safe to trust:
 * see `ledger.ts`.
 */
export async function sealRow(row: SealInput, prevHash: string | null): Promise<SealedChain> {
  const contentSalt = randomHex(16);
  const contentHash = await sha256Hex(contentSalt + canonicalJson(contentPayload(row)));
  const rowHash = await sha256Hex(canonicalJson(rowHashPayload(row, prevHash, contentHash)));
  return {
    prev_hash: prevHash,
    row_hash: rowHash,
    content_hash: contentHash,
    content_salt: contentSalt,
  };
}

/** `sealRow`'s companion for a row already read back with `ledger.page()`/`exportRows()`: the camelCase shape mapped onto the same snake_case payloads `sealRow` hashed. */
function fromEventRow(row: AuditEventRow): SealInput {
  return {
    occurred_at: row.occurredAt,
    tenant_id: row.tenantId,
    tenant_display: row.tenantDisplay,
    actor_class: row.actorClass,
    actor_id: row.actorId,
    actor_display: row.actorDisplay,
    action: row.action,
    target_type: row.targetType,
    target_id: row.targetId,
    target_display: row.targetDisplay,
    outcome: row.outcome,
    context: row.context,
    session_id: row.sessionId,
    reason: row.reason,
    reference: row.reference,
    request_id: row.requestId,
    ip: row.ip,
    user_agent: row.userAgent,
    tenant_visible: row.tenantVisible,
    before: row.before,
    after: row.after,
    schema_version: row.schemaVersion,
    subject_class: row.subjectClass,
    subject_id: row.subjectId,
  };
}

export type ChainVerifyResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      /** Position in `rows` sorted by `id` ascending, not in the array as given. */
      readonly index: number;
      readonly reason: 'unsealed' | 'row_hash' | 'link' | 'content' | 'erasure' | 'head';
    };

/**
 * Verify a run of rows, any order: sorted here by `id` ascending, the true
 * chain order, before anything else. Not `occurredAt` -- `sign()` reads it
 * (`Date.now()`, or the caller's own) *before* the advisory lock that
 * serializes the insert, so two rows chained under real concurrency can
 * carry it out of insertion order; `id` cannot, since it is assigned while
 * the lock is held. `ledger.exportRows()`'s and `ledger.page()`'s own
 * ordering (`occurred_at, id`) is unaffected -- that pairing exists for
 * paging, not for this -- so either's rows pass in as they come back, in
 * any order, newest first or oldest first.
 *
 * Per row: it must carry both `rowHash` and `contentHash` (`'unsealed'` --
 * true of every row from before `hashChain` was turned on, or before
 * 0.5.0); its `rowHash` must recompute (`'row_hash'`); it must link to the
 * previous row, or to `options.origin` if this is the first row and
 * `options.origin` was given (`'link'`); and then, if `contentSalt` is
 * non-null, the row has not been erased, so `erasedAt`/`erasureHash` must
 * both be absent and `contentHash` must recompute (`'content'`/
 * `'erasure'`); otherwise both must be present and `erasureHash` must
 * recompute from this row's `rowHash` and `erasedAt` (`'erasure'`).
 *
 * A row with `contentSalt` null has been erased: its content can no
 * longer be checked -- that is the point -- so a further edit to
 * `actorDisplay`/`targetDisplay`/`before`/`after` after erasure still
 * verifies `ok`. Cross-check an erased row's `erasedAt` against a
 * corresponding `person.erased` event before trusting *why*.
 *
 * `options.origin`, when given (including `null`), anchors the front of
 * the chain: the first row's `prevHash` must equal it. `options.head`,
 * when given, is compared against the last row's `rowHash` once every row
 * has otherwise verified (`'head'`) -- without one, rows deleted off the
 * tail of a window are undetectable from the window alone.
 */
export async function verifyChain(
  rows: readonly AuditEventRow[],
  options: { head?: string; origin?: string | null } = {},
): Promise<ChainVerifyResult> {
  const ordered = [...rows].sort((a, b) => a.id - b.id);
  let previousRowHash: string | null = options.origin ?? null;
  for (let index = 0; index < ordered.length; index++) {
    const row = ordered[index];
    if (!row) continue;
    const rowHash = row.rowHash;
    const contentHash = row.contentHash;
    if (rowHash === null || contentHash === null) return { ok: false, index, reason: 'unsealed' };
    const recomputedRowHash = await sha256Hex(
      canonicalJson(rowHashPayload(fromEventRow(row), row.prevHash, contentHash)),
    );
    if (recomputedRowHash !== rowHash) return { ok: false, index, reason: 'row_hash' };
    const checkLink = index > 0 || options.origin !== undefined;
    if (checkLink && (row.prevHash ?? null) !== previousRowHash) {
      return { ok: false, index, reason: 'link' };
    }
    const contentSalt = row.contentSalt;
    const erasedAt = row.erasedAt;
    const erasureHash = row.erasureHash;
    if (contentSalt !== null) {
      if (erasedAt !== null || erasureHash !== null) return { ok: false, index, reason: 'erasure' };
      const recomputedContentHash = await sha256Hex(
        contentSalt + canonicalJson(contentPayload(fromEventRow(row))),
      );
      if (recomputedContentHash !== contentHash) return { ok: false, index, reason: 'content' };
    } else {
      if (erasedAt === null || erasureHash === null) return { ok: false, index, reason: 'erasure' };
      const expectedErasureHash = await sha256Hex(canonicalJson(erasurePayload(rowHash, erasedAt)));
      if (expectedErasureHash !== erasureHash) return { ok: false, index, reason: 'erasure' };
    }
    previousRowHash = rowHash;
  }
  if (options.head !== undefined && previousRowHash !== options.head) {
    return { ok: false, index: ordered.length - 1, reason: 'head' };
  }
  return { ok: true };
}

/**
 * What `ledger.erase()`'s pending-erasure sweep sets on a chain-sealed row
 * `audit_erase_person` has since erased: `erasure_hash` over this row's
 * (unchanged) `row_hash` and its `erased_at`, binding the fact and instant
 * of the erasure to the row forever, even after `content_salt` -- nulled in
 * the same UPDATE -- makes `content_hash` unreproducible.
 */
export async function computeErasureHash(rowHash: string, erasedAt: Date): Promise<string> {
  return sha256Hex(canonicalJson(erasurePayload(rowHash, erasedAt)));
}
