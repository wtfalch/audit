-- @wtfalch/audit: force row-level security on audit_events.
--
-- 0005_rls.sql left the table's owner exempt from RLS on purpose, so its
-- SECURITY DEFINER functions (audit_erase_person, audit_seal_erasure,
-- audit_chain_tail, audit_pending_erasures) could see and touch every
-- tenant's rows without complication. That same exemption meant a host
-- that misconfigured its runtime connection as the owner -- not
-- the runtime role -- got no tenant isolation at all, silently: read.ts's own
-- doc comment claimed RLS backed the tenant filter "even if" a predicate
-- slipped, which was false for exactly that connection.
--
-- FORCE makes RLS apply to the owner too, and to anything that runs with
-- the owner's privileges (a SECURITY DEFINER function included). None of
-- the four functions above ever calls scopeAuditTenant, so their reads
-- keep hitting 0005's existing unscoped branch (audit_events_read's
-- `else true`) exactly as before -- FORCE does not change what an
-- unscoped connection sees, only who "unscoped" now includes. What FORCE
-- does newly require is an UPDATE policy: audit_erase_person and
-- audit_seal_erasure both run `update audit_events ...` as the owner, and
-- with FORCE on and no UPDATE policy, that update would be refused by
-- default. The runtime role never reaches this policy either way -- the
-- host's `appendOnly` already took UPDATE off it entirely -- so opening it for an
-- unscoped connection costs that role nothing.

alter table audit_events force row level security;

drop policy if exists audit_events_update on audit_events;
create policy audit_events_update on audit_events
  for update
  using (
    case
      when coalesce(current_setting('audit.tenant_id', true), '') <> '' then false
      else true
    end
  )
  with check (true);
