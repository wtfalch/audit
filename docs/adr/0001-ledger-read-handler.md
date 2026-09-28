# 0001 — A read contract, the ledger stays per app; auth is a port, the wire contract is a dependency

## Context

Boule's product promise is "Read an audit log, bounded by what the viewer's
roles allow" for everything that happens in a company, but a company's
events land in several places by this package's own design: per-app
Postgres, no shared store. Boule can read `authz_events` because it holds
that table directly; it cannot read files' file-sharing events, ai's usage
events, integrations' connection events, or cms's site edits, even though
every row already carries `tenantId` and a per-event `tenantVisible` flag
(audit#29).

Two shapes were on the table:

1. **A read contract, the ledger stays per app.** This package ships a
   fetch-shaped handler for `GET /v1/audit`, returning only `tenantVisible`
   rows for the tenant a caller's credential is scoped to. Boule fans out to
   every app the company uses and merges by time. `ledger.page()` already
   exists; this is the HTTP seam and a shared row DTO around it.
2. **A shared org-scoped audit store**, one database every app writes into
   instead of its own. This trades the README's central guarantee -- the
   signer stays inside each app's own trusted base -- for a network hop:
   signer custody would move off the writing app, and "the actor is real"
   would depend on that hop rather than on nothing leaving the process.

## Decision

Option 1. The signer never leaves an app's trusted base; only `page()`'s
output crosses a boundary, and only the columns a cross-app reader needs.

Two further decisions inside that shape:

**Authentication is a port, not a dependency.** `ledgerReadHandler` takes
`authorize: (request: Request) => { tenantId } | null`. This package still
imports nothing from `@wtfalch/keys` -- a host wires `authorize` from
`@wtfalch/keys/issued`'s `check()` (verify the bearer secret, read
`tenantId` off the grant the host's own `TGrant` shape carries) exactly as
it already wires a vocabulary into `createLedger`. A package this small,
whose one job is the table and the signer, does not need to know which
credential system a host chose; the port is the whole contract, and a host
that uses a different credential system altogether still satisfies it with
one function.

**The wire contract is a dependency, optional and exact-pinned like every
other estate peer.** `@wtfalch/contracts` supplies `ServiceError`,
`serviceErrorResponse` and the `PageCursor` type this handler's response
uses, so `unauthorized`/`forbidden`/`invalid_request`/`conflict` come out
looking exactly like every other `-service` package's failures, and a
caller already holding `ServiceApiError`/`serviceApiErrorFrom` parses them
with no special case for audit. This is a real dependency, not a port,
because there is nothing host-specific to inject: every estate service
answers the same four codes the same way, and `@wtfalch/contracts` has no
runtime dependencies of its own (contracts ADR 0001), so taking it changes
nothing about this package's "no framework" footprint. It stays optional
(`peerDependenciesMeta`) alongside `design`/`react`: a host that never
mounts `ledgerReadHandler` does not need it.

**The shared row DTO is a subset, not the full row.** `LedgerReadRow` drops
`before`/`after` (an app's own business payload, not standardized across
apps), `sessionId`/`requestId`/`ip`/`userAgent` (request metadata that
should not cross an app boundary just because a credential is tenant-scoped)
and the hash-chain columns (`prevHash`/`rowHash`/`contentHash`/
`contentSalt`/`erasureHash`, internal integrity state with no meaning to a
reader). `tenantVisible` already decided whether a row leaves the tenant's
own view; the DTO decides, separately, which of its columns leave the app
that wrote it.

**Every read is RLS-scoped inside the handler, not left to the host.** The
handler opens its own transaction and calls `scopeAuditTenant` before
`ledger.page()`, so `migrations/0005_rls.sql`'s row-level security backs the
`tenantId` filter even if a future edit to this function's own `where`
clause were wrong. Defense in depth for the one query this package now
answers to a caller outside its own host.

**The client is per-source, not a fabricated global cursor.** `
fetchMergedLedgerPage` fetches one page from each source in parallel, tags
each row with its source, sorts the merged set by `occurredAt` descending,
and hands back one `nextCursor` per source rather than inventing a single
cursor that would have to encode every source's independent keyset
position. A source that fails is missing from that round's `items` and
named in `errors`; it does not fail the whole call. Boule pages each source
forward by passing the same map back as `cursors`.

## Consequence

A company owner can answer "who shared this file outside the company" or
"who connected our Slack" from Boule once files/ai/integrations/cms each
mount `ledgerReadHandler` and wire an `authorize` from their own
`@wtfalch/keys/issued` issuer -- a per-consumer migration this package does
not do for them, the same shape as every other "adopt this package" change
in the estate.
