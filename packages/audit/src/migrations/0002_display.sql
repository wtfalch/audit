-- @wtfalch/audit 0.4.0: what the target and the tenant were CALLED.
--
-- Mirrors src/tables.ts. Every statement is idempotent. Applied by the host's
-- own migrate script after the host copies this file into its drizzle/
-- directory as the next number (audit-migrations); never edited there.
--
-- WHY THE NAME LIVES ON THE ROW
-- -----------------------------
-- A reader of the trail wants to know what happened to WHAT. Looking the name
-- up when the page renders answers that exactly until it matters: the file was
-- deleted, the organisation was closed, the key was revoked -- and those are
-- the rows a trail exists for. So the name is written with the row and never
-- read from anywhere else afterwards.
--
-- Both columns are nullable and stay nullable: every row written before this
-- migration has no name, and a writer that holds only an id is not made to
-- invent one. A reader shows the id when the name is null.
--
-- These are NOT a rename of target_id or tenant_id. The ids stay the identity;
-- the names are what they were called at the time, and a later rename does not
-- reach back.
--
-- ERASURE
-- -------
-- A target can be a person: an invitation's invitee, a membership's holder.
-- Its name is then personal data sitting in a row that outlives the account,
-- so audit_erase_person pseudonymises target_display exactly as it already
-- pseudonymises actor_display: on the rows it already erases, and only where
-- target_id is the subject. Which rows those are is unchanged on purpose. A
-- row whose target is a person is expected to carry subject_id, which is what
-- the match already looks at; a row that sets neither subject_id nor an email
-- in its payload was already outside erasure's reach before this file, and
-- widening the match here would erase rows 0001 deliberately did not.
-- tenant_display names an organisation, not a person, and is left alone; it is
-- therefore added to the guard's immutable list, so nothing can edit it after
-- the fact the way a correction would.

alter table audit_events add column if not exists target_display text;
alter table audit_events add column if not exists tenant_display text;

do $$ begin
  alter table audit_events
    add constraint audit_events_target_display_check
    check (target_display is null or length(target_display) between 1 and 256);
exception when duplicate_object then null; end $$;

do $$ begin
  alter table audit_events
    add constraint audit_events_tenant_display_check
    check (tenant_display is null or length(tenant_display) between 1 and 256);
exception when duplicate_object then null; end $$;

-- 0001's guard, with tenant_display added to the columns an update may not
-- change. target_display is absent from the list for the same reason
-- actor_display is: erasure rewrites it.
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
    then
      raise exception 'audit_events is append-only: only actor_display, target_display, before, after and erased_at may change';
    end if;
  end if;
  return new;
end
$$;

-- 0001's erasure function, extended to the target's name. Everything else is
-- unchanged: same subject match, same pseudonym bounds, same return.
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
         target_display = case when target_id = subject then pseudonym else target_display end,
         before = case when before is null then null else '{"erased":true}'::jsonb end,
         after = case when after is null then null else '{"erased":true}'::jsonb end,
         erased_at = now()
   where erased_at is null
     and (
       actor_id = subject
       or subject_id = subject
       or (
         subject_email is not null
         and (before::text like '%' || subject_email || '%' or after::text like '%' || subject_email || '%')
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
