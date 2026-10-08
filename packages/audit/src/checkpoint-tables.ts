import { bigint, jsonb, pgTable, smallint, text, timestamp } from 'drizzle-orm/pg-core';

/**
 * Mirrored from `migrations/0008_checkpoints.sql`, which is the source of
 * truth: the SQL carries the CHECKs, the append-only triggers and the
 * retirement function that drizzle-kit does not generate.
 */
export const auditSigningKeys = pgTable('audit_signing_keys', {
  /** The raw 32-byte Ed25519 public key, 64 hex. */
  publicKey: text('public_key').primaryKey(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull(),
  retiredAt: timestamp('retired_at', { withTimezone: true }),
});

export const auditCheckpoints = pgTable('audit_checkpoints', {
  id: bigint('id', { mode: 'number' }).generatedAlwaysAsIdentity().primaryKey(),
  v: smallint('v').notNull(),
  ledger: text('ledger').notNull(),
  treeSize: bigint('tree_size', { mode: 'number' }).notNull().unique(),
  root: text('root').notNull(),
  prevCheckpoint: text('prev_checkpoint'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull(),
  checkpointHash: text('checkpoint_hash').notNull().unique(),
  signature: text('signature').notNull(),
  publicKey: text('public_key')
    .notNull()
    .references(() => auditSigningKeys.publicKey),
  /** The roots of the tree's complete subtrees, largest first, as hex. */
  frontier: jsonb('frontier').$type<string[]>().notNull(),
});

export type AuditCheckpointRow = typeof auditCheckpoints.$inferSelect;
export type AuditSigningKeyRow = typeof auditSigningKeys.$inferSelect;
