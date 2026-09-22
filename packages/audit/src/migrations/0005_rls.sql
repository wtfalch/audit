-- @wtfalch/audit: row-level security on audit_events.
--
-- Mirrors src/ledger.ts (scopeAuditTenant). Every statement is idempotent.
-- Applied by the host's own migrate script after the host copies this file
-- into its drizzle/ directory as the next number (audit-migrations); never
-- edited there.
--
-- Until this file, tenant isolation was only the `tenantId` a caller
-- remembered to pass to ledger.page(). One missed predicate showed a
-- customer another company's trail. With RLS on, the database holds the
-- line for every role that is not the table's owner -- the runtime role
-- <database>_rt, and any read-only role a host adds:
--
--   audit.tenant_id       -- set per transaction by the host
--                            (scopeAuditTenant, or
--                            set_config('audit.tenant_id', $1, true)).
--                            While set, a SELECT sees that tenant's rows and
--                            nothing else -- not another tenant's, and not
--                            the estate's own tenant_id-null rows.
--   audit.require_tenant  -- 'on' makes an unscoped SELECT see nothing
--                            instead of everything. Set it on a role, once:
--                              alter role <database>_rt set audit.require_tenant = 'on';
--                            That is the setting that survives a forgotten
--                            scope. It is not set here because an operator
--                            surface reads across tenants on purpose, and
--                            which role does that is the host's decision.
--
-- Unset and not required, a SELECT sees every row, exactly as before this
-- file: applying it changes nothing for a host until the host scopes.
--
-- INSERT is not restricted: a request scoped to one tenant may still record
-- an estate-level (tenant_id null) event, and the ledger's own vocabulary
-- checks already decide what may be written. UPDATE and DELETE have no
-- policy, so they stay refused for the runtime role -- which 0001's revoke
-- already did.
--
-- Not FORCE: the owner, and the security definer functions it owns
-- (audit_erase_person, audit_seal_erasure, and the two below), bypass RLS.
-- Erasure is by subject, across tenants, by design.

alter table audit_events enable row level security;

drop policy if exists audit_events_read on audit_events;
create policy audit_events_read on audit_events
  for select
  using (
    case
      when coalesce(current_setting('audit.tenant_id', true), '') <> ''
        then tenant_id is not null
         and tenant_id = current_setting('audit.tenant_id', true)::uuid
      when coalesce(current_setting('audit.require_tenant', true), '') = 'on'
        then false
      else true
    end
  );

drop policy if exists audit_events_append on audit_events;
create policy audit_events_append on audit_events
  for insert
  with check (true);

-- The hash chain is one chain across every tenant. Under a tenant scope the
-- runtime role can no longer see the true tail, so ledger.sign() with
-- hashChain on would chain onto that tenant's last row and fork the chain.
-- This reads the tail as the owner. It returns a hash, never content.
create or replace function audit_chain_tail()
returns text
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select row_hash from audit_events order by id desc limit 1
$$;
revoke all on function audit_chain_tail() from public;

-- The same for ledger.erase()'s pending-erasure sweep, which must find
-- every tenant's pending rows, scoped or not. Ids, hashes and erasure
-- instants only.
create or replace function audit_pending_erasures()
returns table (id bigint, row_hash text, erased_at timestamptz)
language sql
stable
security definer
set search_path = pg_catalog, public
as $$
  select e.id, e.row_hash, e.erased_at
    from audit_events e
   where e.row_hash is not null
     and e.erased_at is not null
     and e.erasure_hash is null
   order by e.id
$$;
revoke all on function audit_pending_erasures() from public;

do $$
declare
  rt text := current_database() || '_rt';
begin
  if exists (select 1 from pg_roles where rolname = rt) then
    execute format('grant execute on function audit_chain_tail() to %I', rt);
    execute format('grant execute on function audit_pending_erasures() to %I', rt);
  end if;
end
$$;
