# Changelog

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
