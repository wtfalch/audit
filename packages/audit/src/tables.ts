import { sql } from 'drizzle-orm';
import {
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
export const auditEvents = pgTable(
  'audit_events',
  {
    id: bigint('id', { mode: 'number' }).generatedAlwaysAsIdentity().primaryKey(),
    occurredAt: timestamp('occurred_at', { withTimezone: true }).notNull().default(sql`now()`),
    tenantId: uuid('tenant_id'),
    actorClass: text('actor_class').notNull(),
    actorId: text('actor_id').notNull(),
    actorDisplay: text('actor_display').notNull(),
    action: text('action').notNull(),
    targetType: text('target_type').notNull(),
    targetId: text('target_id').notNull(),
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
  },
  (t) => [
    index('audit_events_tenant_time_idx').on(t.tenantId, t.occurredAt.desc(), t.id.desc()),
    index('audit_events_actor_time_idx').on(t.actorId, t.occurredAt.desc()),
    index('audit_events_action_time_idx').on(t.action, t.occurredAt.desc()),
    index('audit_events_subject_time_idx')
      .on(t.subjectClass, t.subjectId, t.occurredAt.desc(), t.id.desc())
      .where(sql`${t.subjectId} is not null`),
    index('audit_events_request_idx')
      .on(t.requestId, t.occurredAt.desc())
      .where(sql`${t.requestId} is not null`),
  ],
);

export type AuditEventRow = typeof auditEvents.$inferSelect;
export type AuditEventInsert = typeof auditEvents.$inferInsert;
export const tables = { events: auditEvents };
