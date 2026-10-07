import type { TestDb } from './db.js';

/**
 * A stand-in for `audit_checkpoints` (migration 0008, task B), with exactly
 * its columns, so the anchoring tests run before 0008 is merged. The
 * integration step deletes this file once 0008 is present and the tests make
 * real checkpoints.
 */
export async function createCheckpointsStandin(t: TestDb): Promise<void> {
  await t.exec(`
    create table if not exists audit_checkpoints (
      id bigint generated always as identity primary key,
      v smallint not null,
      ledger text not null,
      tree_size bigint not null unique,
      root text not null,
      prev_checkpoint text,
      created_at timestamptz not null,
      checkpoint_hash text not null unique,
      signature text not null,
      public_key text not null,
      frontier jsonb not null
    )`);
}

/** One row in the stand-in, with the hashes and the signature as the caller made them. */
export async function insertStandinCheckpoint(
  t: TestDb,
  cp: {
    tree_size: number;
    root: string;
    prev_checkpoint: string | null;
    created_at: string;
    checkpoint_hash: string;
    signature: string;
    public_key: string;
  },
): Promise<void> {
  await t.exec(`
    insert into audit_checkpoints
      (v, ledger, tree_size, root, prev_checkpoint, created_at, checkpoint_hash, signature, public_key, frontier)
    values (1, 'test-ledger', ${cp.tree_size}, '${cp.root}',
      ${cp.prev_checkpoint === null ? 'null' : `'${cp.prev_checkpoint}'`},
      '${cp.created_at}', '${cp.checkpoint_hash}', '${cp.signature}', '${cp.public_key}', '[]')`);
}
