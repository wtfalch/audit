-- @wtfalch/audit: the append-only audit ledger. Mirrors src/tables.ts.
--
-- Every statement is idempotent. Applied by the host's own migrate script
-- after the host copies this file into its drizzle/ directory as the next
-- number (audit-migrations); never edited there.
--
-- What this file enforces is the ledger's SHAPE and its WALLS: bounded
-- columns, JSON under 64 KB, the pairs that must appear together, the
-- break-glass rule that a session row carries its session, reason and
-- reference, and the three triggers plus the runtime-role revoke that make
-- "append-only" true for a role that is not a superuser. The CLOSED SETS
-- (which event names, actor classes, contexts, outcomes and reason codes a
-- host admits) are the host's own vocabulary: enforced in TypeScript by the
-- ledger at write time, and in the database by the host's own CHECKs when it
-- has them (wtfalch/app-template's 0003 and 0007 do). A host with only this
-- file gets the shape and the walls.
--
-- Estate-shaped: the DO block assumes a runtime role named <database>_rt that
-- owns nothing and serves the app. Without it, the tables and the function
-- exist and no revoke takes effect.
--
-- No foreign keys, on purpose: the trail outlives the tenant, the person and
-- the credential it describes. `tenant_id` is a uuid because the estate's
-- tenants are; a host with other ids alters the column in its own migration.

create table if not exists audit_events (
  id              bigint generated always as identity primary key,
  occurred_at     timestamptz not null default now(),
  tenant_id       uuid,
  actor_class     text not null,
  actor_id        text not null,
  actor_display   text not null,
  action          text not null,
  target_type     text not null,
  target_id       text not null,
  outcome         text not null,
  context         text not null,
  session_id      text,
  reason          text,
  reference       text,
  request_id      text,
  ip              text,
  user_agent      text,
  tenant_visible  boolean not null,
  before          jsonb,
  after           jsonb,
  -- Set by audit_erase_person. The row and actor_id survive; who that was
  -- does not, once this is set.
  erased_at       timestamptz,
  schema_version  smallint not null default 1,
  -- The principal the event was ABOUT, when that is not the actor: an
  -- invitation's invitee, a membership's holder. What lets "events affecting
  -- me" be answered without guessing from payloads.
  subject_class   text,
  subject_id      text,
  constraint audit_events_actor_class_check check (length(actor_class) between 1 and 64),
  constraint audit_events_actor_id_check check (length(actor_id) between 1 and 256),
  constraint audit_events_actor_display_check check (length(actor_display) between 1 and 256),
  constraint audit_events_action_shape_check check (action ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'),
  constraint audit_events_target_type_check check (length(target_type) between 1 and 64),
  constraint audit_events_target_id_check check (length(target_id) between 1 and 256),
  constraint audit_events_outcome_check check (length(outcome) between 1 and 32),
  constraint audit_events_context_check check (length(context) between 1 and 32),
  constraint audit_events_session_id_check check (session_id is null or length(session_id) <= 256),
  constraint audit_events_reason_check check (reason is null or length(reason) <= 512),
  constraint audit_events_reference_check check (reference is null or length(reference) <= 512),
  constraint audit_events_request_id_check check (request_id is null or length(request_id) <= 128),
  constraint audit_events_ip_check check (ip is null or length(ip) <= 64),
  constraint audit_events_user_agent_check check (user_agent is null or length(user_agent) <= 1024),
  constraint audit_events_before_check check (before is null or octet_length(before::text) <= 65536),
  constraint audit_events_after_check check (after is null or octet_length(after::text) <= 65536),
  -- A support-session row names its session, its reason and its reference.
  -- Which reasons are admissible is the host's closed set.
  constraint audit_events_break_glass_shape_check check (
    context <> 'break_glass'
    or (session_id is not null and reason is not null and reference is not null)
  ),
  constraint audit_events_subject_pair_check check ((subject_id is null) = (subject_class is null)),
  constraint audit_events_subject_class_check check (subject_class is null or length(subject_class) between 1 and 64),
  constraint audit_events_subject_id_check check (subject_id is null or length(subject_id) between 1 and 256)
);

-- (occurred_at, id) is the ordering; every reader pages on it.
create index if not exists audit_events_tenant_time_idx
  on audit_events (tenant_id, occurred_at desc, id desc);
create index if not exists audit_events_actor_time_idx
  on audit_events (actor_id, occurred_at desc);
create index if not exists audit_events_action_time_idx
  on audit_events (action, occurred_at desc);
create index if not exists audit_events_subject_time_idx
  on audit_events (subject_class, subject_id, occurred_at desc, id desc) where subject_id is not null;
create index if not exists audit_events_request_idx
  on audit_events (request_id, occurred_at desc) where request_id is not null;

-- The second wall. The first is the revoke below, which stops the server; this
-- stops the owner's own mistakes at a psql prompt. An UPDATE may change only
-- the four columns erasure touches, and DELETE and TRUNCATE are refused
-- outright. audit_erase_person passes through this trigger, not around it.
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
    then
      raise exception 'audit_events is append-only: only actor_display, before, after and erased_at may change';
    end if;
  end if;
  return new;
end
$$;
drop trigger if exists audit_events_guarded_update on audit_events;
create trigger audit_events_guarded_update
  before update on audit_events
  for each row execute function audit_events_guard();
drop trigger if exists audit_events_no_delete on audit_events;
create trigger audit_events_no_delete
  before delete on audit_events
  for each row execute function audit_events_guard();
drop trigger if exists audit_events_no_truncate on audit_events;
create trigger audit_events_no_truncate
  before truncate on audit_events
  for each statement execute function audit_events_guard();

-- The one sanctioned write. Rows the person wrote (actor_id), rows written
-- about them (subject_id), and rows whose payload carries their address:
-- actor_display becomes the pseudonym on their own rows, before and after
-- are replaced wholesale on every matched row, erased_at is set. actor_id
-- and subject_id stay, so "somebody with this id did this" survives and
-- "who that was" does not. Row counts never change. Ledger-only: a host's
-- own tables (a profile, an invitation) are the host's to clean, in the same
-- transaction, and its final `person.erased` row is written after this.
create or replace function audit_erase_person(subject text, pseudonym text, subject_email text)
returns integer
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  touched integer;
begin
  if subject is null or length(subject) = 0 then
    raise exception 'audit_erase_person: a subject id is required';
  end if;
  if pseudonym is null or length(pseudonym) = 0 or length(pseudonym) > 256 then
    raise exception 'audit_erase_person: a pseudonym of 1 to 256 characters is required';
  end if;
  update audit_events
     set actor_display = case when actor_id = subject then pseudonym else actor_display end,
         before = case when before is null then null else '{"erased":true}'::jsonb end,
         after = case when after is null then null else '{"erased":true}'::jsonb end,
         erased_at = now()
   where erased_at is null
     and (
       actor_id = subject
       or subject_id = subject
       or (
         subject_email is not null
         and length(subject_email) > 0
         and (
           lower(coalesce(before::text, '')) like '%' || lower(subject_email) || '%'
           or lower(coalesce(after::text, '')) like '%' || lower(subject_email) || '%'
         )
       )
     );
  get diagnostics touched = row_count;
  return touched;
end
$$;
revoke all on function audit_erase_person(text, text, text) from public;

do $$
declare
  rt text := current_database() || '_rt';
begin
  if exists (select 1 from pg_roles where rolname = rt) then
    execute format('revoke update, delete, truncate on audit_events from %I', rt);
    execute format('grant execute on function audit_erase_person(text, text, text) to %I', rt);
  end if;
end
$$;
