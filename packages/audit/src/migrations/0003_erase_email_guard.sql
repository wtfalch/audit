-- @wtfalch/audit: restore audit_erase_person's empty-email guard.
--
-- Mirrors src/ledger.ts's erase(). Every statement is idempotent. Applied by
-- the host's own migrate script after the host copies this file into its
-- drizzle/ directory as the next number (audit-migrations); never edited
-- there.
--
-- REGRESSION
-- ----------
-- 0002_display.sql's audit_erase_person dropped two things 0001_audit.sql
-- had: the `length(subject_email) > 0` guard and the lower() case-fold on
-- both the column and the match value. Without the length guard, an empty
-- string reaches the SQL LIKE match as `like '%%'`, which matches every
-- row's before/after text -- on every tenant, not just the subject's. This
-- file cannot edit 0002 (shipped migrations don't change); it re-defines
-- the function, which `create or replace` makes safe to apply on top.
--
-- Everything else about the function is unchanged from 0002: same subject
-- and subject_id match, same pseudonym bounds, same target_display and
-- actor_display pseudonymisation, same return.

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
