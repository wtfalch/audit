import { rowHashOf } from './rfc6962.js';

/**
 * TEMP: a stand-in for migration 0007 (row format 2), which another builder
 * owns. It adds the `seq` column to `audit_events` if missing and creates
 * `audit_chain_leaves` exactly as the contract (C2) states. Integration
 * deletes this file once 0007 is in the migration set, and the tests that
 * call it switch to signing real rows.
 */
export async function installChainV2Standin(exec: (text: string) => Promise<void>) {
  await exec(`
    alter table audit_events add column if not exists seq bigint unique;
    create or replace function audit_chain_leaves(after_seq bigint, max_rows int)
    returns table (seq bigint, row_hash text)
    language sql
    stable
    security definer
    set search_path from current
    as $$
      select e.seq, e.row_hash
        from audit_events e
       where e.seq > after_seq
       order by e.seq
       limit max_rows
    $$;
    revoke all on function audit_chain_leaves(bigint, int) from public;
  `);
}

/** Inserts one event per `seq` in `from..to` with a deterministic 64-hex `row_hash`. */
export async function insertLeaves(
  exec: (text: string) => Promise<void>,
  from: number,
  to: number,
) {
  for (let seq = from; seq <= to; seq++) {
    await exec(`
      insert into audit_events
        (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context,
         tenant_visible, seq, row_hash)
      values ('human', 'u', 'U', 'a.b', 't', 'x', 'success', 'standard', false, ${seq}, '${rowHashOf(seq - 1)}')
    `);
  }
}
