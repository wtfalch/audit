-- @wtfalch/audit: hash chaining, opt in.
--
-- Mirrors src/chain.ts and src/tables.ts. Every statement is idempotent.
-- Applied by the host's own migrate script after the host copies this file
-- into its drizzle/ directory as the next number (audit-migrations); never
-- edited there.
--
-- Nothing here forces chaining. Five nullable columns, computed and
-- verified entirely in TypeScript (src/chain.ts), the same design
-- `@wtfalch/authz`'s audit-chain.ts already shipped: no pgcrypto, no
-- trigger, because PGlite -- this package's own default test database --
-- has no pgcrypto, and a trigger cannot see the previous row's hash without
-- a race between concurrent inserts that only a lock (below) closes.
--
--   prev_hash     -- the previous row's row_hash, in whatever order rows
--                     were sealed at write time. null for the chain's first
--                     row, and forever on a row nothing ever sealed.
--   row_hash      -- sha256 over this row's own fields (chain.ts's
--                     ROW_HASH_KEYS) plus prev_hash and content_hash. Never
--                     changes once set; the append-only guard below still
--                     refuses to.
--   content_hash  -- sha256 over the row's erasable content (actor_display,
--                     target_display, before, after), salted.
--   content_salt  -- the salt content_hash was taken over. Set at seal
--                     time, nulled by erasure: once it is gone nobody --
--                     including this package -- can reproduce content_hash
--                     from a guessed payload, which is what erasure means
--                     here. Unlike row_hash, an erasure IS allowed to null
--                     this, so the guard's allowed list grows to include it.
--   erasure_hash  -- set only once content_salt is nulled: sha256 over
--                     { row_hash, erased_at }, so the fact and the instant
--                     of erasure stay checkable forever even though the
--                     erased content no longer is.
--
-- A row written before this migration applies has row_hash null forever --
-- nothing recorded its hash at write time, so computing one now would only
-- hash what the row happens to contain today, proving nothing about
-- whether it changed since. verifyChain reports it 'unsealed', not
-- verified, the same stance 0002's target_display took on the rows before
-- it and worker_log_chain took on the rows before T255.
--
-- audit_seal_erasure(row_id, erasure_hash_value): the runtime role has no
-- UPDATE on audit_events at all (0001's revoke), so ledger.erase()'s
-- pending-erasure sweep -- setting content_salt to null and erasure_hash
-- once a chain-sealed row has been erased -- needs its own security
-- definer door back in, the same shape as audit_erase_person's.

alter table audit_events add column if not exists prev_hash text;
alter table audit_events add column if not exists row_hash text;
alter table audit_events add column if not exists content_hash text;
alter table audit_events add column if not exists content_salt text;
alter table audit_events add column if not exists erasure_hash text;

do $$ begin
  alter table audit_events
    add constraint audit_events_prev_hash_check
    check (prev_hash is null or prev_hash ~ '^[0-9a-f]{64}$');
exception when duplicate_object then null; end $$;

do $$ begin
  alter table audit_events
    add constraint audit_events_row_hash_check
    check (row_hash is null or row_hash ~ '^[0-9a-f]{64}$');
exception when duplicate_object then null; end $$;

do $$ begin
  alter table audit_events
    add constraint audit_events_content_hash_check
    check (content_hash is null or content_hash ~ '^[0-9a-f]{64}$');
exception when duplicate_object then null; end $$;

do $$ begin
  alter table audit_events
    add constraint audit_events_erasure_hash_check
    check (erasure_hash is null or erasure_hash ~ '^[0-9a-f]{64}$');
exception when duplicate_object then null; end $$;

-- A chain-sealed row not yet erased, so ledger.erase()'s pending-erasure
-- sweep finds it in an index scan rather than a table scan. Empty on a
-- host that never turns chaining on.
create index if not exists audit_events_chain_pending_idx
  on audit_events (id)
  where row_hash is not null and erased_at is not null and erasure_hash is null;

-- 0002's guard, with content_salt and erasure_hash added to the columns an
-- update may change: erasure nulls the first and sets the second, on a row
-- that was already erased by the same audit_erase_person call this
-- migration does not touch. prev_hash, row_hash and content_hash are
-- absent from the list on purpose -- once set, never.
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
    then
      raise exception 'audit_events is append-only: only actor_display, target_display, before, after, erased_at, content_salt and erasure_hash may change';
    end if;
  end if;
  return new;
end
$$;

-- 0001's revoke took update off the runtime role entirely, on purpose:
-- audit_erase_person (security definer) is the one door back in. This is
-- the second one, for exactly one thing: chain-sealing a row
-- audit_erase_person already erased. It never computes a hash itself --
-- the caller does, in TypeScript (chain.ts's computeErasureHash), the same
-- design choice audit_erase_person's own absence of a hash column made
-- before this file existed -- it only writes the value it is given, and
-- only onto a row that is erased, chain-sealed, and not already sealed.
create or replace function audit_seal_erasure(row_id bigint, erasure_hash_value text)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  update audit_events
     set content_salt = null,
         erasure_hash = erasure_hash_value
   where id = row_id
     and row_hash is not null
     and erased_at is not null
     and erasure_hash is null;
end
$$;
revoke all on function audit_seal_erasure(bigint, text) from public;

do $$
declare
  rt text := current_database() || '_rt';
begin
  if exists (select 1 from pg_roles where rolname = rt) then
    execute format('grant execute on function audit_seal_erasure(bigint, text) to %I', rt);
  end if;
end
$$;
