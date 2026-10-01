# 0002 — `audit:read` gates every read, and RLS is forced on the owner too

## Context

The estate-wide review (estate DECISIONS.md, 2026-09-28) found that
`ledgerReadHandler` checked only which tenant a credential was scoped to,
never whether it held any permission at all: any credential scoped to a
tenant could read that tenant's whole security log. Separately,
`migrations/0005_rls.sql` left the table's owner exempt from row-level
security on purpose (so its `SECURITY DEFINER` functions could see and
erase across every tenant), which meant a host that misconfigured its
runtime connection as the owner -- not `<database>_rt` -- got no tenant
isolation at all, silently. `read.ts`'s own doc comment claimed RLS backed
the tenant filter "even if" a predicate slipped, which was false for
exactly that connection.

## Decision

**`audit:read`, one permission, checked by the package itself.** This
package's own `@wtfalch/authz` catalogue (`catalogue.ts`) declares
`audit:read`; a host's own catalogue composes it in beside its own
modules. `ledgerReadHandler` refuses `forbidden` (403) unless the caller's
`access.allows('audit:read', resource)`, and `Ledger.page()` throws
`PermissionDeniedError` under the same check -- so a host that calls
`page()` directly, not just through the handler, is gated too. This is
`package-template` ADR 0005 (authz is scaffolded, not optional) applied to
the one read path this package answers to a caller outside its own host.

**`Authorize` returns the resolved access, not a precomputed boolean.**
`AuthorizedRead` gained `access: ResourceAccess` beside `tenantId`. The
handler builds the `AccessResource` itself (`type: 'audit.event'`,
`organisationId` the requested tenant), from `applicationId`/`platformId`
the host now passes into `ledgerReadHandlerOptions` -- ids this package has
no way to know on its own. This mirrors `files.ts`'s
`requirePermission(authority, permission, target)` shape rather than
inventing a lighter one: a host already has a `ResourceAccess` resolved for
every other route: it did not gain new plumbing.

**`page()` takes `access` and `resource` as required options, a breaking
change.** Every existing caller -- the handler, this package's own tests,
a host reading the ledger directly for an operator surface -- must now
supply both. `page()`'s old contract ("applies no permission; the host
gates") is exactly the design that let a permission-less credential read
freely; the fix could not stay opt-in.

**RLS is forced.** `migrations/0006_force_rls.sql` runs
`alter table audit_events force row level security`, so the table owner is
now subject to the same tenant-scoped `SELECT` policy as `<database>_rt`.
The owner's `SECURITY DEFINER` functions (`audit_erase_person`,
`audit_seal_erasure`, `audit_chain_tail`, `audit_pending_erasures`) still
work unchanged: none of them ever calls `scopeAuditTenant`, so they hit
`0005`'s existing unscoped branch (`else true`) for reads, and the new
migration adds the one policy that was missing for writes -- an `UPDATE`
policy, `using` the same unscoped-only condition, `with check (true)`,
which only ever matters for the owner (the runtime role has had `UPDATE`
revoked outright since `0001`, so RLS is moot for it either way). Only an
actual Postgres superuser still bypasses RLS regardless of `FORCE`; a
host's runtime connection should never be one, forced or not.

## Consequence

A credential merely scoped to the right tenant is no longer enough to read
its audit trail; a consumer must also grant it `audit:read` (an existing
app key or admin role, or a dedicated read-only credential). A host that
connects its runtime as the table's owner, by misconfiguration, now still
gets real tenant isolation instead of none. `read.ts`'s doc comment is true
again.

Breaking for every `page()` caller and for `ledgerReadHandler`'s host: see
`CHANGELOG.md` 0.7.0, and pin `@wtfalch/authz` per `package-template` ADR
0016.

**Amended 2026-10-01.** `<database>_rt` above is the runtime role the host now makes with `ensureRuntimeRole` from `@wtfalch/db`; the SQL no longer names it (see package-template ADR 0015, amended the same day, and `packages/audit/README.md`, Install).
