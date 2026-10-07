-- @wtfalch/audit: signed Merkle checkpoints.
--
-- Mirrors src/checkpoint-tables.ts and src/checkpoint.ts. Every statement is
-- idempotent. Applied by the host's own migrate script after the host copies
-- this file into its drizzle/ directory as the next number (audit-migrations);
-- never edited there. Two new tables and one new function; audit_events is not
-- touched, so it is safe at container start on a live database.
--
--   audit_signing_keys  -- the Ed25519 public keys that signed a checkpoint:
--                          64 hex, the raw 32 bytes. Inserted by
--                          sealCheckpoint the first time a key signs. The only
--                          update is retired_at, once, and only through
--                          audit_retire_signing_key.
--   audit_checkpoints   -- one row per seal: the cumulative Merkle tree over
--                          leaves 1..tree_size, its root, the link to the
--                          previous checkpoint, the signature, and the
--                          frontier (the roots of the tree's complete
--                          subtrees, largest first) the next seal extends.
--
-- The database holds keys as a convenience. A verifier trusts the keys it is
-- handed, not these rows. Both tables are append-only by trigger, and a host
-- lists both in `appendOnly`, so the runtime role can insert and read and
-- nothing else.

create table if not exists audit_signing_keys (
  public_key  text primary key,
  created_at  timestamptz not null,
  retired_at  timestamptz,
  constraint audit_signing_keys_public_key_check check (public_key ~ '^[0-9a-f]{64}$'),
  constraint audit_signing_keys_window_check check (retired_at is null or retired_at >= created_at)
);

create table if not exists audit_checkpoints (
  id               bigint generated always as identity primary key,
  v                smallint not null,
  ledger           text not null,
  tree_size        bigint not null unique,
  root             text not null,
  prev_checkpoint  text,
  created_at       timestamptz not null,
  checkpoint_hash  text not null unique,
  signature        text not null,
  public_key       text not null references audit_signing_keys (public_key),
  frontier         jsonb not null,
  constraint audit_checkpoints_v_check check (v = 1),
  constraint audit_checkpoints_ledger_check check (length(ledger) between 1 and 256),
  constraint audit_checkpoints_tree_size_check check (tree_size >= 1),
  constraint audit_checkpoints_root_check check (root ~ '^[0-9a-f]{64}$'),
  constraint audit_checkpoints_prev_check
    check (prev_checkpoint is null or prev_checkpoint ~ '^[0-9a-f]{64}$'),
  constraint audit_checkpoints_hash_check check (checkpoint_hash ~ '^[0-9a-f]{64}$'),
  constraint audit_checkpoints_signature_check check (signature ~ '^[0-9a-f]{128}$'),
  constraint audit_checkpoints_frontier_check check (jsonb_typeof(frontier) = 'array')
);

-- The walls for a role that is not the host's runtime role (which has no
-- update, delete or truncate at all): the owner's own mistakes at a psql prompt.
create or replace function audit_checkpoints_guard() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_checkpoints is append-only: % refused', lower(tg_op);
end
$$;
drop trigger if exists audit_checkpoints_no_update on audit_checkpoints;
create trigger audit_checkpoints_no_update
  before update on audit_checkpoints
  for each row execute function audit_checkpoints_guard();
drop trigger if exists audit_checkpoints_no_delete on audit_checkpoints;
create trigger audit_checkpoints_no_delete
  before delete on audit_checkpoints
  for each row execute function audit_checkpoints_guard();
drop trigger if exists audit_checkpoints_no_truncate on audit_checkpoints;
create trigger audit_checkpoints_no_truncate
  before truncate on audit_checkpoints
  for each statement execute function audit_checkpoints_guard();

-- A key row may change once: retired_at from null to a time. Nothing else.
create or replace function audit_signing_keys_guard() returns trigger
language plpgsql as $$
begin
  if tg_op = 'UPDATE' then
    if old.retired_at is null
      and new.retired_at is not null
      and new.public_key is not distinct from old.public_key
      and new.created_at is not distinct from old.created_at
    then
      return new;
    end if;
    raise exception 'audit_signing_keys is append-only: only retired_at may be set, once';
  end if;
  raise exception 'audit_signing_keys is append-only: % refused', lower(tg_op);
end
$$;
drop trigger if exists audit_signing_keys_guarded_update on audit_signing_keys;
create trigger audit_signing_keys_guarded_update
  before update on audit_signing_keys
  for each row execute function audit_signing_keys_guard();
drop trigger if exists audit_signing_keys_no_delete on audit_signing_keys;
create trigger audit_signing_keys_no_delete
  before delete on audit_signing_keys
  for each row execute function audit_signing_keys_guard();
drop trigger if exists audit_signing_keys_no_truncate on audit_signing_keys;
create trigger audit_signing_keys_no_truncate
  before truncate on audit_signing_keys
  for each statement execute function audit_signing_keys_guard();

-- The runtime role has no UPDATE on audit_signing_keys, so retiring a key
-- needs its own security definer door, the same shape as audit_seal_erasure.
-- It writes the database clock, truncated to milliseconds so a checkpoint's
-- millisecond timestamp compares cleanly. It fails on a key that is unknown
-- or already retired.
create or replace function audit_retire_signing_key(key text)
returns void
language plpgsql
security definer
set search_path from current
as $$
begin
  update audit_signing_keys
     set retired_at = greatest(created_at, date_trunc('milliseconds', clock_timestamp()))
   where public_key = key
     and retired_at is null;
  if not found then
    raise exception 'audit_signing_keys: key is unknown or already retired';
  end if;
end
$$;
revoke all on function audit_retire_signing_key(text) from public;
