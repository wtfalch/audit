import { sql } from 'drizzle-orm';
import {
  type ExtraConfigColumn,
  bigint,
  boolean,
  index,
  jsonb,
  pgTable,
  smallint,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';

/**
 * The ledger, mirrored from `migrations/0001_audit.sql`, which is the source
 * of truth: the SQL carries the CHECKs, the append-only triggers, the partial
 * indexes and the erasure function that drizzle-kit does not generate. A host
 * re-exports this from its own schema module so its drizzle instance and its
 * types know it.
 */
/**
 * The ledger's columns, as drizzle builders, so a host that needs a column
 * of its own beside them (a team, a region) declares
 * `pgTable('audit_events', { ...AUDIT_COLUMNS, teamId: uuid('team_id') }, …)`
 * and hands that table to `createLedger`. The package's own `auditEvents`
 * is the same call with nothing added.
 */
export const AUDIT_COLUMNS = {
  id: bigint('id', { mode: 'number' }).generatedAlwaysAsIdentity().primaryKey(),
  occurredAt: timestamp('occurred_at', { withTimezone: true }).notNull().default(sql`now()`),
  tenantId: uuid('tenant_id'),
  actorClass: text('actor_class').notNull(),
  actorId: text('actor_id').notNull(),
  actorDisplay: text('actor_display').notNull(),
  action: text('action').notNull(),
  targetType: text('target_type').notNull(),
  targetId: text('target_id').notNull(),
  // What the target and the tenant were CALLED when the row was written. Null
  // on a row written before 0.4.0, and on one whose writer has no name to give.
  targetDisplay: text('target_display'),
  tenantDisplay: text('tenant_display'),
  outcome: text('outcome').notNull(),
  context: text('context').notNull(),
  sessionId: text('session_id'),
  reason: text('reason'),
  reference: text('reference'),
  requestId: text('request_id'),
  ip: text('ip'),
  userAgent: text('user_agent'),
  tenantVisible: boolean('tenant_visible').notNull(),
  before: jsonb('before'),
  after: jsonb('after'),
  erasedAt: timestamp('erased_at', { withTimezone: true }),
  schemaVersion: smallint('schema_version').notNull().default(1),
  subjectClass: text('subject_class'),
  subjectId: text('subject_id'),
  // The hash chain, opt in (LedgerOptions.hashChain). Null on every row a
  // ledger with chaining off ever writes, and forever on a row written
  // before 0.5.0 -- see chain.ts and migrations/0004_chain.sql.
  prevHash: text('prev_hash'),
  rowHash: text('row_hash'),
  contentHash: text('content_hash'),
  contentSalt: text('content_salt'),
  erasureHash: text('erasure_hash'),
};

/** The indexes every ledger table carries, for a host declaring its own table over `AUDIT_COLUMNS`. */
export function auditIndexes(t: { [K in keyof typeof AUDIT_COLUMNS]: ExtraConfigColumn }) {
  return [
    index('audit_events_tenant_time_idx').on(t.tenantId, t.occurredAt.desc(), t.id.desc()),
    index('audit_events_actor_time_idx').on(t.actorId, t.occurredAt.desc()),
    index('audit_events_action_time_idx').on(t.action, t.occurredAt.desc()),
    index('audit_events_subject_time_idx')
      .on(t.subjectClass, t.subjectId, t.occurredAt.desc(), t.id.desc())
      .where(sql`${t.subjectId} is not null`),
    index('audit_events_request_idx')
      .on(t.requestId, t.occurredAt.desc())
      .where(sql`${t.requestId} is not null`),
    index('audit_events_chain_pending_idx')
      .on(t.id)
      .where(
        sql`${t.rowHash} is not null and ${t.erasedAt} is not null and ${t.erasureHash} is null`,
      ),
  ];
}

/**
 * The ledger, mirrored from `migrations/0001_audit.sql`, which is the source
 * of truth: the SQL carries the CHECKs, the append-only triggers, the partial
 * indexes and the erasure function that drizzle-kit does not generate. A host
 * re-exports this from its own schema module so its drizzle instance and its
 * types know it, or declares a wider table over `AUDIT_COLUMNS`.
 */
export const auditEvents = pgTable('audit_events', AUDIT_COLUMNS, (t) => auditIndexes(t));

/** The package's table, or a host's declared over `AUDIT_COLUMNS` with more columns; structurally either. */
export type AuditTable = typeof auditEvents;
export type AuditEventRow = typeof auditEvents.$inferSelect;
export type AuditEventInsert = typeof auditEvents.$inferInsert;
export const tables = { events: auditEvents };
