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
| Append-only: no DELETE, no TRUNCATE, UPDATE limited to what erasure touches | `audit_events_guard` trigger, plus a revoke from `<database>_rt`; `createLedger` runs `assertRuntimeRole` on first use to check the revoke actually landed on the connected role |
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
    target: { type: 'invoice', id, display: invoice.number },
    tenantDisplay: tenant.name,
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

## Names, not only ids

`target.display` and `tenantDisplay` are what the target and the tenant were
CALLED when the row was written. Pass them whenever the caller already holds
the object, which is nearly always: it is making the change.

The name is stored, not looked up later, because a lookup answers right up
until it matters. The rows a trail exists for are the deleted file, the closed
organisation, the revoked key — and by then there is nothing left to join to.
A later rename does not reach back either: the row says what the thing was
called at the time, which is what a reader of history wants.

Both are optional and both are null on every row written before 0.4.0, so a
reader falls back to the id. `audit_erase_person` pseudonymises
`target_display` when the target is the person being erased; `tenant_display`
names an organisation, so nothing may change it once written.

## A writer for an embedding service

A service that wants a trail (a forum's moderation, a mail admin's writes) gets
a writer, never the signer. The host binds one per namespace:

```ts
export const forumAudit = ledger.writer({ namespace: 'thread', handle: db });
createThreads({ db, gates, audit: forumAudit });
```

The writer signs `thread.*` and refuses everything else; the actor is whoever
the service resolved; context, actor class and tenant default to what the
host bound. A caller passes its transaction as the second argument when the
row must commit with the change it records.

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

## A service with no tenant database

Nothing in the ledger is per-app. A service that is not a tenant app, such as
foundry recording who ran which plan, needs three things:

- its own closed vocabulary through `ledgerVocabulary({ events, actorClasses,
  contexts, outcomes })`, with no `@wtfalch/authz` core;
- `tenantId: null` on every row, with what the row is about as the `target`
  (`{ type: 'org', id: orgId }`);
- a Postgres of its own, with these migrations applied.

```ts
const ledger = createLedger({
  vocabulary: ledgerVocabulary({
    events: { 'plan.computed': { tenantVisible: false }, 'plan.applied': { tenantVisible: false } },
    actorClasses: ['human', 'service'],
    contexts: ['operator'],
    outcomes: ['success', 'refused', 'failed'],
  }),
  hashChain: true,
});
await ledger.sign(db, {
  action: 'plan.applied', tenantId: null, actor, context: 'operator',
  outcome: 'refused', reason, target: { type: 'org', id: orgId }, after: plan,
});
```

The database is the one thing the package cannot supply.

## Tenant isolation in the database

`migrations/0005_rls.sql` turns on row-level security. For every role but the
table's owner, a read inside a tenant-scoped transaction sees that tenant's
rows and nothing else, whatever predicate the query forgot:

```ts
import { scopeAuditTenant } from '@wtfalch/audit';

await db.transaction(async (tx) => {
  await scopeAuditTenant(tx, tenantId); // set_config('audit.tenant_id', ..., true)
  const page = await ledger.page(tx, { tenantId, tenantVisibleOnly: true });
});
```

Unscoped reads still see every row, so applying the migration changes nothing
until the host scopes. To make a forgotten scope see nothing instead, set it
on the role the app connects as:

```sql
alter role <database>_rt set audit.require_tenant = 'on';
```

An operator surface that reads across tenants then connects as another role.
Which role that is belongs to the host. An app that connects as the table's
owner gets no RLS at all.

Neither that nor the append-only revoke above was enforced at runtime by
this package before `assertRuntimeRole`: both depend on the connection
being named exactly `<database>_rt`, and no migration can see what role a
given deployment's connection string will actually resolve to. It throws
`UnsafeRuntimeRoleError` if the connected role can bypass row-level security
(superuser or BYPASSRLS) or still holds UPDATE, DELETE or TRUNCATE on
`audit_events`.

**`createLedger` runs it for you.** The ledger it returns checks the first
handle any of `sign`/`page`/`erase`/`exportRows` is called with, once, and
fails closed before that call -- and every one after, on the same handle --
touches the table if the role is unsafe. This is on by default
(`LedgerOptions.checkRuntimeRole`); turn it off for a connection that is
deliberately broader than `<database>_rt`, such as a test run against a
superuser fixture:

```ts
const ledger = createLedger({ vocabulary, checkRuntimeRole: false }); // e.g. tests against PGlite's superuser connection
```

The check is once per handle, on that handle's first use, not once per
call and not on a timer. A handle a host holds for a long time -- a pooled
connection, a client built once at module scope -- is checked once for as
long as the host keeps using that same handle object, which can be the
whole process lifetime; a role change made afterward (a revoked grant, a
rotated `<database>_rt`) is not picked up on that handle. To have a role
change take effect, give the ledger a handle it has not seen before -- pass
a fresh transaction handle per request, which is the usual shape for a web
host -- or restart the process. If your own tests run against a superuser
connection -- PGlite is one, and so is a local Postgres reached as
`postgres` -- pass `checkRuntimeRole: false` to `createLedger` in those
tests, the same way this package's own PGlite-backed tests do; the check
throws on a superuser connection by design.

`assertRuntimeRole` also stays exported, for a host that wants the same
check on a connection this package's ledger never sees, or that wants to
fail before `createLedger` is even reachable -- its own boot path, the way
`@wtfalch/tasks`'s `apps/host/src/lib/runtime-role-guard.ts` does for that
package's tables:

```ts
import { assertRuntimeRole } from '@wtfalch/audit';

await assertRuntimeRole(db); // throws if the connection is not the `_rt` role, or one shaped like it
```

With `hashChain` on, `sign()` and `erase()` now read the chain tail and the
pending erasures through `audit_chain_tail()` and `audit_pending_erasures()`,
both added in 0005. Apply 0005 before deploying this version.

## To a customer's SIEM

`toCef(row)` renders one ledger row as a CEF (Common Event Format) line, the
format Splunk, QRadar, Sentinel and ArcSight ingest directly or over syslog;
`toCefLines(rows)` does a page of them, one per line.

```ts
import { toCef, toCefLines } from '@wtfalch/audit';

const { items } = await ledger.page(db, { tenantId, limit: 500 });
const body = toCefLines(items, { vendor: 'Acme', product: 'Acme', version: '2.3' });
```

The push half (a webhook, a syslog socket, a file a shipper tails) is the
host's: which transport, whose endpoint, whose credentials and whose retry
policy are one decision per enterprise customer, not the package's.

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
