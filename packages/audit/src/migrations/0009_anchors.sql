-- @wtfalch/audit: anchors, opt in.
--
-- Mirrors src/anchor-tables.ts. Every statement is idempotent. Applied by
-- the host's own migrate script after the host copies this file into its
-- drizzle/ directory as the next number (audit-migrations); never edited
-- there.
--
-- An anchor is an outside timestamp authority's RFC 3161 token over one
-- checkpoint: proof that the checkpoint existed by the time in the token.
-- The package never trusts the token on read; the offline verifier checks
-- its signature against roots the auditor supplies.
--
--   checkpoint_hash -- the checkpoint the token covers. No foreign key, so
--                       this file applies on its own: a checkpoint is never
--                       deleted anyway (audit_checkpoints is append-only).
--   provider        -- a name the host gives the authority, so a second
--                       authority can anchor the same checkpoint.
--   token           -- base64 of the DER TimeStampToken.
--   token_hash      -- sha256 of those DER bytes, hex.
--   anchored_at     -- the genTime inside the token, not the local clock.
--
-- A host lists `audit_anchors` in `appendOnly` for ensureRuntimeRole, like
-- audit_events: insert and read only. The guard below stops the owner's own
-- mistakes at a psql prompt, the same as audit_events_guard in 0001.

create table if not exists audit_anchors (
  id bigint generated always as identity primary key,
  checkpoint_hash text not null check (checkpoint_hash ~ '^[0-9a-f]{64}$'),
  provider text not null check (length(provider) between 1 and 200),
  token text not null,
  token_hash text not null check (token_hash ~ '^[0-9a-f]{64}$'),
  anchored_at timestamptz not null
);

create unique index if not exists audit_anchors_checkpoint_provider_idx
  on audit_anchors (checkpoint_hash, provider);

create or replace function audit_anchors_guard() returns trigger
language plpgsql as $$
begin
  raise exception 'audit_anchors is append-only: % refused', lower(tg_op);
end
$$;
drop trigger if exists audit_anchors_no_update on audit_anchors;
create trigger audit_anchors_no_update
  before update on audit_anchors
  for each row execute function audit_anchors_guard();
drop trigger if exists audit_anchors_no_delete on audit_anchors;
create trigger audit_anchors_no_delete
  before delete on audit_anchors
  for each row execute function audit_anchors_guard();
drop trigger if exists audit_anchors_no_truncate on audit_anchors;
create trigger audit_anchors_no_truncate
  before truncate on audit_anchors
  for each statement execute function audit_anchors_guard();
