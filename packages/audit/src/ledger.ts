import { and, asc, desc, eq, gte, like, lt, lte, or, sql } from 'drizzle-orm';
import type { PgDatabase, PgQueryResultHKT } from 'drizzle-orm/pg-core';
import { type AuditRow, rowSchema } from './schema.js';
import { type AuditEventRow, type AuditTable, auditEvents as auditEvents_ } from './tables.js';
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
  /**
   * `display` is what the target was CALLED when this happened, written into
   * the row beside its id so the row still reads after the target is gone. A
   * caller that holds the object passes it; one that does not omits it and the
   * row keeps the id alone.
   */
  readonly target: { readonly type: string; readonly id: string; readonly display?: string | null };
  /** What the tenant was called when this happened, for the same reason. */
  readonly tenantDisplay?: string | null;
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
  /**
   * Values for the host's own columns, by the drizzle key the host's table
   * declares them under (`{ teamId }`), written beside the ledger's. Never a
   * ledger column: those are validated above and refused here.
   */
  readonly extra?: Readonly<Record<string, unknown>>;
}

export interface PageOptions {
  /** One tenant's rows; `null` for rows with no tenant; omit for every tenant. */
  readonly tenantId?: string | null;
  /** Only rows the tenant's own log may show. A tenant-facing reader passes `true` and never lets a caller choose. */
  readonly tenantVisibleOnly?: boolean;
  readonly actorId?: string;
  readonly subjectId?: string;
  readonly action?: string;
  /**
   * Rows whose action starts with this prefix, e.g. `'membership.'` for
   * every membership event. Combine with `action` only if you mean both to
   * apply at once; almost always you want one or the other, not both. `%`
   * and `_` are escaped, so they match themselves rather than acting as SQL
   * wildcards.
   */
  readonly actionPrefix?: string;
  readonly requestId?: string;
  /** Rows at or after this instant. */
  readonly occurredFrom?: Date;
  /** Rows at or before this instant. */
  readonly occurredTo?: Date;
  readonly after?: { readonly occurredAt: Date; readonly id: number };
  readonly limit?: number;
}

export interface Page {
  readonly items: readonly AuditEventRow[];
  readonly next: { readonly occurredAt: Date; readonly id: number } | null;
}

/**
 * What an embedding service hands a bound writer for one row. The namespace
 * is fixed when the host binds the writer, so `action` must sit in it; the
 * actor is whoever the service resolved (a forum's `who`, a mail admin's
 * principal), never chosen by the ledger. Everything else is optional and
 * defaults as `SignInput` does.
 */
export interface WriterEvent {
  readonly action: string;
  readonly actor: { readonly id: string; readonly display: string; readonly class?: string };
  readonly target: { readonly type: string; readonly id: string };
  readonly tenantId?: string | null;
  readonly outcome?: string;
  readonly reason?: string | null;
  readonly reference?: string | null;
  readonly before?: unknown;
  readonly after?: unknown;
  readonly subject?: { readonly class: string; readonly id: string } | null;
  readonly request?: SignInput['request'];
  readonly extra?: SignInput['extra'];
}

/**
 * A writer the host bound to one namespace. `handle` is the caller's
 * transaction when the row must commit with the change it records;
 * otherwise the handle the host bound.
 */
export type AuditWriter = (event: WriterEvent, handle?: Handle) => Promise<void>;

export interface WriterOptions {
  /** The namespace the writer may sign in: `thread` admits `thread.pinned` and refuses `tenant.created`. */
  readonly namespace: string;
  /** The handle used when the caller passes none. */
  readonly handle: Handle;
  /** The context every row carries. Defaults to the vocabulary's first context. */
  readonly context?: string;
  /** The actor class when the event names none. Defaults to the vocabulary's first actor class. */
  readonly actorClass?: string;
  /** The tenant when the event names none. Defaults to null: a row on the estate log. */
  readonly tenantId?: string | null;
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
export interface LedgerOptions {
  readonly vocabulary: LedgerVocabulary;
  /** The host's own table over `AUDIT_COLUMNS`, when it has columns beside the ledger's. Defaults to the package's `auditEvents`. */
  readonly table?: AuditTable;
  /** What `schema_version` every row carries. Defaults to 1; a host whose shared audit words are versioned passes theirs. */
  readonly schemaVersion?: number;
}

export interface Ledger {
  readonly vocabulary: LedgerVocabulary;
  readonly tables: { readonly events: AuditTable };
  /** Validates against the vocabulary and inserts, on the handle given: a transaction when the row must commit with the change it records. */
  sign(handle: Handle, input: SignInput): Promise<void>;
  /** Newest first, keyset on `(occurred_at, id)`. Applies no permission; the host gates and decides `tenantVisibleOnly`. */
  page(handle: Handle, options?: PageOptions): Promise<Page>;
  /** The one sanctioned write: `audit_erase_person`. Returns how many rows it touched. Call inside the host's erasure transaction. */
  erase(handle: Handle, input: EraseInput): Promise<number>;
  /** One tenant's rows, oldest first, for a tenant's export. Deterministic order; no secrets are in this table to omit. */
  exportRows(handle: Handle, tenantId: string): Promise<readonly AuditEventRow[]>;
  /**
   * A writer for one embedding service, bound to one namespace. This is what
   * a host hands to `createThreads({ audit })` or a postmaster: it can write
   * that namespace's events and nothing else, and it never sees `sign`.
   */
  writer(options: WriterOptions): AuditWriter;
}

const LEDGER_KEYS = new Set(Object.keys(auditEvents_));

export function createLedger(options: LedgerOptions): Ledger {
  const { vocabulary, table: auditEvents = auditEvents_, schemaVersion = 1 } = options;
  const schema = rowSchema(vocabulary, { schemaVersion });

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
      target_display: input.target.display ?? null,
      tenant_display: input.tenantDisplay ?? null,
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
      schema_version: schemaVersion,
      subject_class: input.subject?.class ?? null,
      subject_id: input.subject?.id ?? null,
    });
    const extra = input.extra ?? {};
    for (const key of Object.keys(extra)) {
      if (LEDGER_KEYS.has(key))
        throw new Error(`audit: "${key}" is a ledger column, not a host column`);
      if (!(key in auditEvents))
        throw new Error(`audit: the ledger's table has no column "${key}"`);
    }
    await handle.insert(auditEvents).values({
      ...(extra as Record<string, never>),
      occurredAt,
      tenantId: row.tenant_id,
      actorClass: row.actor_class,
      actorId: row.actor_id,
      actorDisplay: row.actor_display,
      action: row.action,
      targetType: row.target_type,
      targetId: row.target_id,
      targetDisplay: row.target_display,
      tenantDisplay: row.tenant_display,
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
    if (options.actionPrefix) {
      const escaped = options.actionPrefix.replace(/[\\%_]/g, (c) => `\\${c}`);
      conditions.push(like(auditEvents.action, `${escaped}%`));
    }
    if (options.requestId) conditions.push(eq(auditEvents.requestId, options.requestId));
    if (options.occurredFrom) conditions.push(gte(auditEvents.occurredAt, options.occurredFrom));
    if (options.occurredTo) conditions.push(lte(auditEvents.occurredAt, options.occurredTo));
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
    if (input.email === '') {
      throw new Error(
        'audit: erase: an empty email matches every row; omit email or pass the address',
      );
    }
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

  function writer(options: WriterOptions): AuditWriter {
    const { namespace } = options;
    if (!/^[a-z][a-z0-9_]*$/.test(namespace)) {
      throw new Error(`audit: "${namespace}" is not a namespace`);
    }
    const context = options.context ?? vocabulary.contexts[0];
    const actorClass = options.actorClass ?? vocabulary.actorClasses[0];
    if (context === undefined || actorClass === undefined) {
      throw new Error('audit: the vocabulary has no context or actor class to default to');
    }
    return async (event, handle) => {
      if (!event.action.startsWith(`${namespace}.`)) {
        throw new Error(
          `audit: "${event.action}" is outside the namespace "${namespace}" this writer is bound to`,
        );
      }
      await sign(handle ?? options.handle, {
        action: event.action,
        tenantId: event.tenantId === undefined ? (options.tenantId ?? null) : event.tenantId,
        actor: {
          class: event.actor.class ?? actorClass,
          id: event.actor.id,
          display: event.actor.display,
        },
        context,
        target: event.target,
        outcome: event.outcome,
        reason: event.reason,
        reference: event.reference,
        before: event.before,
        after: event.after,
        subject: event.subject,
        request: event.request,
        extra: event.extra,
      });
    };
  }

  return { vocabulary, tables: { events: auditEvents }, sign, page, erase, exportRows, writer };
}
