import { and, asc, desc, eq, lt, or, sql } from 'drizzle-orm';
import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core';
import { type AuditRow, rowSchema } from './schema.js';
import { type AuditEventRow, auditEvents } from './tables.js';
import type { LedgerVocabulary } from './vocabulary.js';

/**
 * The host's drizzle handle or a transaction open on it. postgres-js in the
 * apps, PGlite in this package's own tests; the queries use nothing
 * driver-specific.
 */
// biome-ignore lint/suspicious/noExplicitAny: the host's schema is the host's; this package indexes none of it.
export type Handle = PgDatabase<PgQueryResultHKT, any, any>;

/** Who did it. The host's trusted base fills this from the access it resolved; nothing else may. */
export interface Actor {
  readonly class: string;
  readonly id: string;
  readonly display: string;
}

/** What a caller of the signer supplies for one row. Everything else is filled in here. */
export interface SignInput {
  readonly action: string;
  readonly tenantId: string | null;
  readonly actor: Actor;
  readonly context: string;
  readonly target: { readonly type: string; readonly id: string };
  readonly outcome?: string;
  readonly sessionId?: string | null;
  readonly reason?: string | null;
  readonly reference?: string | null;
  readonly request?: {
    readonly id?: string | null;
    readonly ip?: string | null;
    readonly userAgent?: string | null;
  };
  /** Defaults to the vocabulary's decision for this event. A host may override for a single row and should rarely need to. */
  readonly tenantVisible?: boolean;
  readonly before?: unknown;
  readonly after?: unknown;
  /** The principal the event is about, when it is not the actor. */
  readonly subject?: { readonly class: string; readonly id: string } | null;
  readonly occurredAt?: Date;
}

export interface PageOptions {
  /** One tenant's rows; `null` for rows with no tenant; omit for every tenant. */
  readonly tenantId?: string | null;
  /** Only rows the tenant's own log may show. A tenant-facing reader passes `true` and never lets a caller choose. */
  readonly tenantVisibleOnly?: boolean;
  readonly actorId?: string;
  readonly subjectId?: string;
  readonly action?: string;
  readonly requestId?: string;
  readonly after?: { readonly occurredAt: Date; readonly id: number };
  readonly limit?: number;
}

export interface Page {
  readonly items: readonly AuditEventRow[];
  readonly next: { readonly occurredAt: Date; readonly id: number } | null;
}

export interface EraseInput {
  readonly subject: string;
  readonly pseudonym: string;
  /** The person's address, so rows whose payloads name them and nothing else are swept too. */
  readonly email?: string | null;
}

/**
 * What `createLedger` returns. **`sign` is the signer.** A host constructs the
 * ledger exactly once inside its trusted base, keeps `sign` there, and hands
 * each service that wants auditing a writer already bound to the actor it
 * resolved and the event names it may use. Nothing here checks a permission
 * or reads a session: the guarantee that a row's actor is real is the host's,
 * and it holds only while the signer stays private.
 */
export interface Ledger {
  readonly vocabulary: LedgerVocabulary;
  readonly tables: { readonly events: typeof auditEvents };
  /** Validates against the vocabulary and inserts, on the handle given: a transaction when the row must commit with the change it records. */
  sign(handle: Handle, input: SignInput): Promise<void>;
  /** Newest first, keyset on `(occurred_at, id)`. Applies no permission; the host gates and decides `tenantVisibleOnly`. */
  page(handle: Handle, options?: PageOptions): Promise<Page>;
  /** The one sanctioned write: `audit_erase_person`. Returns how many rows it touched. Call inside the host's erasure transaction. */
  erase(handle: Handle, input: EraseInput): Promise<number>;
  /** One tenant's rows, oldest first, for a tenant's export. Deterministic order; no secrets are in this table to omit. */
  exportRows(handle: Handle, tenantId: string): Promise<readonly AuditEventRow[]>;
}

export function createLedger(options: { vocabulary: LedgerVocabulary }): Ledger {
  const { vocabulary } = options;
  const schema = rowSchema(vocabulary);

  async function sign(handle: Handle, input: SignInput): Promise<void> {
    const meta = vocabulary.events[input.action];
    if (!meta) {
      throw new Error(`audit: "${input.action}" is not an event this ledger's vocabulary declares`);
    }
    const occurredAt = input.occurredAt ?? new Date();
    const row: AuditRow = schema.parse({
      occurred_at: occurredAt.toISOString(),
      tenant_id: input.tenantId,
      actor_class: input.actor.class,
      actor_id: input.actor.id,
      actor_display: input.actor.display,
      action: input.action,
      target_type: input.target.type,
      target_id: input.target.id,
      outcome: input.outcome ?? vocabulary.outcomes[0],
      context: input.context,
      session_id: input.sessionId ?? null,
      reason: input.reason ?? null,
      reference: input.reference ?? null,
      request_id: input.request?.id ?? null,
      ip: input.request?.ip ?? null,
      user_agent: input.request?.userAgent ?? null,
      tenant_visible: input.tenantVisible ?? meta.tenantVisible,
      before: input.before ?? null,
      after: input.after ?? null,
      erased_at: null,
      schema_version: 1,
      subject_class: input.subject?.class ?? null,
      subject_id: input.subject?.id ?? null,
    });
    await handle.insert(auditEvents).values({
      occurredAt,
      tenantId: row.tenant_id,
      actorClass: row.actor_class,
      actorId: row.actor_id,
      actorDisplay: row.actor_display,
      action: row.action,
      targetType: row.target_type,
      targetId: row.target_id,
      outcome: row.outcome,
      context: row.context,
      sessionId: row.session_id,
      reason: row.reason,
      reference: row.reference,
      requestId: row.request_id,
      ip: row.ip,
      userAgent: row.user_agent,
      tenantVisible: row.tenant_visible,
      before: row.before,
      after: row.after,
      schemaVersion: row.schema_version,
      subjectClass: row.subject_class,
      subjectId: row.subject_id,
    });
  }

  async function page(handle: Handle, options: PageOptions = {}): Promise<Page> {
    const limit = Math.max(1, Math.min(options.limit ?? 50, 200));
    const conditions = [];
    if (options.tenantId === null) conditions.push(sql`${auditEvents.tenantId} is null`);
    else if (options.tenantId !== undefined)
      conditions.push(eq(auditEvents.tenantId, options.tenantId));
    if (options.tenantVisibleOnly) conditions.push(eq(auditEvents.tenantVisible, true));
    if (options.actorId) conditions.push(eq(auditEvents.actorId, options.actorId));
    if (options.subjectId) conditions.push(eq(auditEvents.subjectId, options.subjectId));
    if (options.action) conditions.push(eq(auditEvents.action, options.action));
    if (options.requestId) conditions.push(eq(auditEvents.requestId, options.requestId));
    if (options.after) {
      const { occurredAt, id } = options.after;
      const keyset = or(
        lt(auditEvents.occurredAt, occurredAt),
        and(eq(auditEvents.occurredAt, occurredAt), lt(auditEvents.id, id)),
      );
      if (keyset) conditions.push(keyset);
    }
    const rows = await handle
      .select()
      .from(auditEvents)
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(auditEvents.occurredAt), desc(auditEvents.id))
      .limit(limit + 1);
    const items = rows.slice(0, limit);
    const last = items.at(-1);
    return {
      items,
      next: rows.length > limit && last ? { occurredAt: last.occurredAt, id: last.id } : null,
    };
  }

  async function erase(handle: Handle, input: EraseInput): Promise<number> {
    const result = await handle.execute(
      sql`select audit_erase_person(${input.subject}, ${input.pseudonym}, ${input.email ?? null}) as n`,
    );
    const rows = Array.isArray(result)
      ? (result as { n: unknown }[])
      : ((result as { rows?: { n: unknown }[] }).rows ?? []);
    return Number(rows[0]?.n ?? 0);
  }

  async function exportRows(handle: Handle, tenantId: string): Promise<readonly AuditEventRow[]> {
    return handle
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.tenantId, tenantId))
      .orderBy(asc(auditEvents.occurredAt), asc(auditEvents.id));
  }

  return { vocabulary, tables: { events: auditEvents }, sign, page, erase, exportRows };
}
