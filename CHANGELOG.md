# Changelog

## Unreleased

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
