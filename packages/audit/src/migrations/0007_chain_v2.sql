-- @wtfalch/audit: chain rows in format 2.
--
-- Mirrors src/chain.ts and src/tables.ts. Every statement is idempotent, and
-- every row written before this applies keeps null in the three new columns:
-- nothing here rewrites, locks for long or reads an existing row, so it is
-- safe on a live table (the unique index is built over nulls only).
--
--   chain_version  -- 2 on a format 2 row, null on a format 1 row.
--   seq            -- 1 on the first format 2 row, then dense. Unique.
--   received_at    -- the database clock when the row was sealed, truncated
--                     to milliseconds so a hash recomputes from a JS Date.
--
-- A format 2 row's row_hash covers seq and received_at (src/chain.ts,
-- sealRowV2). The three columns are all null or all set to a version of 2.
--
-- The guard below is 0004's, with the three columns added to the frozen
-- list. audit_chain_tail_v2() and audit_chain_leaves() are security
-- definer for the reason audit_chain_tail() is (0005): under a tenant scope
-- row-level security hides every other tenant's rows, and the chain is one
-- chain across all of them.

alter table audit_events add column if not exists chain_version smallint;
alter table audit_events add column if not exists seq bigint;
alter table audit_events add column if not exists received_at timestamptz;

do $$ begin
  alter table audit_events
    add constraint audit_events_chain_v2_check
    check (
      (chain_version is null and seq is null and received_at is null)
      or (chain_version = 2 and seq is not null and received_at is not null)
    );
exception when duplicate_object then null; end $$;

create unique index if not exists audit_events_seq_idx on audit_events (seq);

-- 0004's guard with chain_version, seq and received_at frozen.
create or replace function audit_events_guard() returns trigger
language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'audit_events is append-only: delete refused';
  elsif tg_op = 'TRUNCATE' then
    raise exception 'audit_events is append-only: truncate refused';
  elsif tg_op = 'UPDATE' then
    if new.id is distinct from old.id
      or new.occurred_at is distinct from old.occurred_at
      or new.tenant_id is distinct from old.tenant_id
      or new.tenant_display is distinct from old.tenant_display
      or new.actor_class is distinct from old.actor_class
      or new.actor_id is distinct from old.actor_id
      or new.action is distinct from old.action
      or new.target_type is distinct from old.target_type
      or new.target_id is distinct from old.target_id
      or new.outcome is distinct from old.outcome
      or new.context is distinct from old.context
      or new.session_id is distinct from old.session_id
      or new.reason is distinct from old.reason
      or new.reference is distinct from old.reference
      or new.request_id is distinct from old.request_id
      or new.ip is distinct from old.ip
      or new.user_agent is distinct from old.user_agent
      or new.tenant_visible is distinct from old.tenant_visible
      or new.schema_version is distinct from old.schema_version
      or new.subject_class is distinct from old.subject_class
      or new.subject_id is distinct from old.subject_id
      or new.prev_hash is distinct from old.prev_hash
      or new.row_hash is distinct from old.row_hash
      or new.content_hash is distinct from old.content_hash
      or new.chain_version is distinct from old.chain_version
      or new.seq is distinct from old.seq
      or new.received_at is distinct from old.received_at
    then
      raise exception 'audit_events is append-only: only actor_display, target_display, before, after, erased_at, content_salt and erasure_hash may change';
    end if;
  end if;
  return new;
end
$$;

-- The chain's tail for a format 2 seal: the highest seq (null before the
-- first format 2 row), the newest row's row_hash by id (of either format,
-- null on an empty or unsealed table), and the database clock to stamp the
-- new row with. Volatile, not stable: the clock moves inside a statement.
create or replace function audit_chain_tail_v2()
returns table (seq bigint, row_hash text, received_at timestamptz)
language sql
security definer
set search_path from current
as $$
  select
    (select max(e.seq) from audit_events e),
    (select e.row_hash from audit_events e order by e.id desc limit 1),
    date_trunc('milliseconds', clock_timestamp())
$$;
revoke all on function audit_chain_tail_v2() from public;

-- The leaves of the chain after a seq, in seq order: what a checkpoint
-- hashes. Seqs and hashes only.
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
