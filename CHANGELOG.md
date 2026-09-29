# Changelog

## 0.9.0 — 2026-09-29

- **Breaking for a host on `@wtfalch/design` below 0.30**: the `./react`
  reader (`SecurityLog`, on `ActivityLine`/`Pagination`) is now tested
  against `@wtfalch/design` 0.30.0, which rewrote `Toggle`'s busy state
  (an opacity pulse on the knob, a new spring on the themeable
  `--dur-spring` token; `Toggle`'s own props are unchanged, and this
  package renders no `Toggle`) -- design's own CHANGELOG marks 0.29.0 and
  0.30.0 both not breaking. Bound the peer to `^0.30.0`, per the same
  package-template ADR 0016 discipline as 0.6.0. A host importing
  `@wtfalch/audit/react` must upgrade `@wtfalch/design` to 0.30.0 or later
  before taking this version; a host that does not use `./react` is
  unaffected. Shipped as a minor bump, not a patch, for the same reason as
  0.6.0: it narrows what a caller may already depend on.

## 0.8.0 — 2026-09-28

- **Breaking**: `ledgerReadHandler`, `fetchLedgerPage`/`fetchMergedLedgerPage`,
  `LedgerReadError` and their types moved from the root entry to
  `@wtfalch/audit/read`. `read.ts` imports `@wtfalch/contracts` at the top
  level, so re-exporting it from the root meant a host that only writes to
  the ledger -- never mounts `ledgerReadHandler` -- still crashed on
  `import ... from '@wtfalch/audit'` without `@wtfalch/contracts` installed,
  even though that peer is marked optional. The same split `./react` already
  has for `@wtfalch/design`/`react`/`react-dom`. Update any import of these
  names to `@wtfalch/audit/read` (audit#33).
- `force-rls.test.ts` gained a case connecting as the table's owner (no
  `set role`), scoping to a tenant, and asserting another tenant's row is
  invisible -- the connection `0006_force_rls.sql`'s `FORCE` actually
  changes who RLS applies to; the existing case ran as the non-owner
  runtime role, which RLS already covered with or without `FORCE`.

## 0.7.0 — 2026-09-28

- `ledgerReadHandler`: a fetch-shaped handler for `GET /v1/audit?tenant=&
  cursor=&limit=`, returning a tenant's `tenantVisible` rows as
  `LedgerReadRow` (a deliberate subset of the full row), paged with the
  estate's `cursor`/`limit`/`nextCursor` convention
  (`@wtfalch/contracts` ADR 0008; an invalid or expired cursor answers
  `conflict`). Authentication is a port, `authorize(request) => { tenantId,
  access } | null`, not a dependency -- the host wires it from
  `@wtfalch/keys/issued`'s `check()`; this package imports nothing from
  `keys`. A request whose credential's tenant differs from the `tenant`
  parameter, or whose `access` does not allow `audit:read`, is refused
  (`forbidden`). See README, "Reading across apps".
- `fetchLedgerPage`/`fetchMergedLedgerPage`: a small client, for a host like
  Boule that fans out to several apps' `ledgerReadHandler` and merges their
  pages by `occurredAt`, one source's failure never blanking the rest.
- `@wtfalch/contracts` joins the optional peers, for `ServiceError` and the
  `PageCursor` type the handler and client both use. `ADR 0001` records why
  this stays a port for authentication but a real (optional) dependency for
  the wire contract.
- **Breaking, `@wtfalch/authz` catalogue (`audit:read`)**: this package's
  own catalogue (`catalogue.ts`) names `audit:read`, the one permission a
  ledger reader needs. `ledgerReadHandler` refuses `forbidden` (403) and
  `Ledger.page()` throws `PermissionDeniedError` unless the caller's
  `access.allows('audit:read', resource)` -- a credential merely scoped to
  the right tenant is no longer enough. `page()`'s `access` and `resource`
  are now required options, and `ledgerReadHandlerOptions` gained
  `applicationId`/`platformId` to build that resource. `page()`'s doc
  comment used to say "applies no permission; the host gates" -- now it
  does the gate itself, so a host that forgets to check is not left
  exposed. See ADR 0002 and README, "Reading across apps".
- `migrations/0006_force_rls.sql`: `FORCE ROW LEVEL SECURITY` on
  `audit_events`, so the table's owner is now subject to the same
  tenant-scoped policy as `<database>_rt` -- a host that misconfigures its
  runtime connection as the owner gets real isolation instead of none.
  `read.ts`'s doc comment claiming RLS "backs the tenant filter... even if"
  a predicate slipped was false for that one connection; it is now true.
  See ADR 0002.

## 0.6.0 — 2026-09-28

- **Breaking for a host on `@wtfalch/design` below 0.28**: the `./react`
  readers were tested only against `@wtfalch/design` 0.23, while
  `peerDependencies` declared `>=0.23.0` -- a promise of compatibility with
  every later minor, none of which were ever tested. Tested against design
  0.28.0 (`pnpm check` green) and bound the peer to `^0.28.0`, per
  package-template ADR 0016. A host importing `@wtfalch/audit/react` must
  upgrade `@wtfalch/design` to 0.28.0 or later before taking this version;
  a host that does not use `./react` is unaffected. Shipped as a minor
  bump, not a patch, because it narrows what a caller may already depend on.
- `assertRuntimeRole(handle)`: an opt-in check that queries the connected
  role's privileges and throws `UnsafeRuntimeRoleError` if it can bypass
  RLS (superuser or `BYPASSRLS`) or still holds `UPDATE`, `DELETE` or
  `TRUNCATE` on `audit_events`, so a host that connects as anything but the
  scoped `<database>_rt` role fails closed instead of silently losing both
  the append-only guard and tenant isolation (#24).
- `createLedger` now runs `assertRuntimeRole` by default (memoized once per
  handle), so a host that never wires the check in on its own still fails
  closed. Opt out with `LedgerOptions.checkRuntimeRole: false` for a
  superuser test connection such as PGlite's (#25).
## 0.5.0 — 2026-09-23

- Fix: `audit_erase_person` lost its empty-email guard and its lower-casing
  in 0002_display.sql, so an empty email reached the SQL `LIKE` match as
  `like '%%'` and wiped `before`/`after` on every tenant's rows, not just the
  subject's. `migrations/0003_erase_email_guard.sql` restores both. Shipped
  migrations don't change, so this ships as a new file; copy it with
  `audit-migrations` as usual.
- `ledger.erase()` now refuses an empty `email` outright, instead of passing
  it through to the SQL function.
- `./react`: `SecurityLog`, rows for a tenant's or an operator's security log
  on `ActivityLine` (`@wtfalch/design`), with a "Load more" over
  `ledger.page()`'s keyset cursor. The reader every stamped app was
  hand-rolling from raw rows. `react`, `react-dom` and `@wtfalch/design` are
  optional peers; nothing else in the package needs them.
- `page()`: `actionPrefix` (`'membership.'` for every membership event) and
  `occurredFrom`/`occurredTo`, an inclusive range on `occurred_at`. An
  operator investigation no longer has to bypass the package for raw SQL to
  get either.
- Hash chaining, the schema and the pure math: five nullable columns
  (`prev_hash`, `row_hash`, `content_hash`, `content_salt`, `erasure_hash`,
  `migrations/0004_chain.sql`) and `chain.ts`'s `sealRow`/`verifyChain`/
  `computeErasureHash`, porting `@wtfalch/authz`'s audit-chain design onto
  this package's columns.
- `createLedger({ hashChain: true })`, opt in: wires the math above into
  `sign()` and `erase()`, so the columns above stop being unwritten. `sign()`
  seals and inserts inside an advisory-locked transaction, so concurrent
  writers chain onto the true tail rather than forking it; `erase()`
  chain-seals a row `audit_erase_person` has erased through
  `audit_seal_erasure`, keeping the runtime role's lack of `UPDATE` on
  `audit_events` intact. Off by default: it serializes every `sign()` call
  in that ledger, which a host that does not need tamper evidence should
  not pay for.
- `toCef`/`toCefLines`: a ledger row as a CEF line, for forwarding a
  tenant's security events to their own SIEM. Serialisation only; the
  transport stays the host's.
- Row-level security on `audit_events` (`migrations/0005_rls.sql`) and
  `scopeAuditTenant(tx, tenantId)`: a tenant-scoped transaction sees only
  that tenant's rows, for every role but the owner. `alter role <db>_rt set
  audit.require_tenant = 'on'` makes an unscoped read see nothing. Unscoped
  and unrequired, reads are unchanged.
- With `hashChain` on, `sign()` and `erase()` read the chain tail and the
  pending erasures through two security definer functions added in 0005, so
  a tenant scope cannot fork the chain or hide pending erasures. **Apply 0005
  before deploying this version** if `hashChain` is on.
- README: a ledger for a service with no tenant database (own vocabulary,
  `tenantId: null`, its own Postgres), with a test that runs that shape.

## 0.4.0 — 2026-09-20

- `target_display` and `tenant_display`: what the target and the tenant were
  CALLED when the row was written, beside their ids. A reader of the trail
  wants to know what happened to what, and looking the name up at render time
  fails exactly when it matters -- the file deleted, the organisation closed,
  the key revoked.
- `SignInput.target.display` and `SignInput.tenantDisplay` write them. Both
  are optional: a writer holding only an id is not made to invent a name, and
  a row written before this version keeps a null.
- `audit_erase_person` pseudonymises `target_display` on the rows it already
  erases, where the target is the subject. A target can be a person.
- The append-only guard admits `target_display` for that erasure and refuses
  every change to `tenant_display`.
- `migrations/0002_display.sql`. Copy it with `audit-migrations` as usual.

## 0.3.0 — 2026-09-11

- `ledger.writer({ namespace, handle, context?, actorClass?, tenantId? })`: a
  writer bound to one namespace for an embedding service. It signs that
  namespace's events with the actor the service resolved and refuses any
  other action; the caller may pass its own transaction.
- `WriterEvent`, `AuditWriter`, `WriterOptions` types.

## 0.2.0 — 2026-09-11

- `AUDIT_COLUMNS` and `auditIndexes`: a host declares its own table over the
  ledger's builders when it needs a column beside them.
- `createLedger({ table, schemaVersion })`: sign into that table, and stamp
  every row with the host's schema version (default 1).
- `SignInput.extra`: values for the host's columns, by drizzle key. A ledger
  column or an unknown key is refused before the insert.

## 0.1.0 — 2026-09-11

First release: `audit_events`, its walls, `audit_erase_person`, `createLedger`,
`ledgerVocabularyFromCore`, `rowSchema`, `audit-migrations`.
