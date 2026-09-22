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
