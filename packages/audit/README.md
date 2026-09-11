# @wtfalch/audit

The estate's append-only audit ledger, as a package: one table's shape and
walls, a signer, readers, erasure and export. Per-app Postgres, a vocabulary
the host supplies, no framework.

It is **not** a service you call from outside. A host constructs the ledger
once inside its trusted base, keeps the signer there, and hands each module
that wants auditing a writer already bound to the actor the base resolved
and the event names that module may use. The guarantee that a row's actor is
real is the host's, and it holds only while the signer stays private.

## What the package enforces, and what the host does

| Concern | Where |
| --- | --- |
| Column bounds, JSON size, `namespace.name` action shape, subject pair, break-glass shape | `migrations/0001_audit.sql` CHECKs, and `rowSchema` before the insert |
| Append-only: no DELETE, no TRUNCATE, UPDATE limited to what erasure touches | `audit_events_guard` trigger, plus a revoke from `<database>_rt` |
| The closed sets: which events, actor classes, contexts, outcomes, reason codes | `LedgerVocabulary` in TypeScript at write time; the host's own CHECKs in the database when it has them |
| Who may sign what | The host. The package checks no permission and reads no session |
| Tenant visibility | Decided per event in the vocabulary, never per write |
| Erasure | `audit_erase_person(subject, pseudonym, subject_email)`, ledger-only, `SECURITY DEFINER`; the host cleans its own tables in the same transaction |

## Install

```sh
pnpm add @wtfalch/audit
pnpm exec audit-migrations   # copies migrations/*.sql into drizzle/ as the next numbers
```

The copy is recorded in `drizzle/.audit-migrations.json`; running it again
copies nothing. Apply the copied file with the host's own migrate script.

## Use

```ts
import { core } from '@wtfalch/authz';
import { createLedger, ledgerVocabularyFromCore } from '@wtfalch/audit';

// Once, inside the trusted base.
const ledger = createLedger({
  vocabulary: ledgerVocabularyFromCore(core, {
    'invoice.paid': { tenantVisible: true },
  }),
});

// In a server action, inside the transaction that makes the change.
await db.transaction(async (tx) => {
  await tx.update(invoices).set({ paidAt: now }).where(eq(invoices.id, id));
  await ledger.sign(tx, {
    action: 'invoice.paid',
    tenantId,
    actor: { class: 'human', id: access.principal.id, display: access.principal.display },
    context: 'standard',
    target: { type: 'invoice', id },
    after: { paidAt: now },
    request: requestContext(),
  });
});

// Readers. The host gates; a tenant-facing page always passes tenantVisibleOnly.
const page = await ledger.page(db, { tenantId, tenantVisibleOnly: true, limit: 50 });
const rows = await ledger.exportRows(db, tenantId);

// Erasure, inside the host's own erasure transaction.
const touched = await ledger.erase(tx, { subject: personId, pseudonym, email });
```

`ledgerVocabularyFromCore` refuses a host event in a namespace the core
uses: `tenant.invoice_paid` is out, `invoice.paid` is in. The core's
namespaces are the trusted base's.

## A host's own columns

A host that needs a column beside the ledger's (a team, a region) declares
its table over the package's builders and hands it to the ledger:

```ts
import { AUDIT_COLUMNS, auditIndexes, createLedger } from '@wtfalch/audit';

export const auditEvents = pgTable('audit_events', { ...AUDIT_COLUMNS, teamId: uuid('team_id') }, (t) =>
  auditIndexes(t),
);
const ledger = createLedger({ vocabulary, table: auditEvents, schemaVersion: core.version });
await ledger.sign(tx, { ...input, extra: { teamId } });
```

`extra` takes host columns only: a ledger column there is refused, and so is a
key the table does not declare. The host's own migration adds the column; the
package's migration never learns of it.

## Tests

```sh
pnpm test                                        # PGlite, in memory
TEST_DATABASE_URL=postgres://... pnpm test       # a real Postgres; drops its public schema first
```

The real run adds the runtime-role test: `<database>_rt` may insert and
call `audit_erase_person`, and may not update, delete or truncate.

## Release

Tag `v*`. The workflow builds, tests and publishes with npm trusted
publishing; the first publish of a new package is done from a laptop.
