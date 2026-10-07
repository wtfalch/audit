import { bigint, pgTable, text, timestamp, uniqueIndex } from 'drizzle-orm/pg-core';

/**
 * The anchors, mirrored from `migrations/0009_anchors.sql`, which is the
 * source of truth: the SQL carries the CHECKs and the append-only triggers.
 * One row per checkpoint and timestamp authority: the DER `TimeStampToken`
 * (base64), its hash, and the time the authority put in it.
 */
export const auditAnchors = pgTable(
  'audit_anchors',
  {
    id: bigint('id', { mode: 'number' }).generatedAlwaysAsIdentity().primaryKey(),
    checkpointHash: text('checkpoint_hash').notNull(),
    provider: text('provider').notNull(),
    token: text('token').notNull(),
    tokenHash: text('token_hash').notNull(),
    anchoredAt: timestamp('anchored_at', { withTimezone: true }).notNull(),
  },
  (t) => [uniqueIndex('audit_anchors_checkpoint_provider_idx').on(t.checkpointHash, t.provider)],
);

export type AuditAnchorRow = typeof auditAnchors.$inferSelect;
