# @wtfalch/audit

The estate's append-only audit ledger, as a package: one table's shape and
walls, a signer, readers, erasure and export. Per-app Postgres, a vocabulary
the host supplies, no framework.

It is **not** a service you call from outside. A host constructs the ledger
once inside its trusted base, keeps the signer there, and hands each module
that wants auditing a writer already bound to the actor the base resolved
and the event names that module may use. The guarantee that a row's actor is
real is the host's, and it holds only while the signer stays private.
`ledgerReadHandler` (below, "Reading across apps") does not change this: it
is a plain function a host mounts on its own HTTP layer, never a server this
package runs, and it only ever reads through `ledger.page()` -- the signer
still never leaves the host that built it.

## What the package enforces, and what the host does

| Concern | Where |
| --- | --- |
| Column bounds, JSON size, `namespace.name` action shape, subject pair, break-glass shape | `migrations/0001_audit.sql` CHECKs, and `rowSchema` before the insert |
| Append-only: no DELETE, no TRUNCATE, UPDATE limited to what erasure touches | `audit_events_guard` trigger, plus the host's `appendOnly: ['audit_events']` in `ensureRuntimeRole` (below); `createLedger` runs `assertRuntimeRole` on first use to check the revoke actually landed on the connected role |
| The closed sets: which events, actor classes, contexts, outcomes, reason codes | `LedgerVocabulary` in TypeScript at write time; the host's own CHECKs in the database when it has them |
| Who may sign what | The host. The package checks no permission and reads no session |
| Tenant visibility | Decided per event in the vocabulary, never per write |
| Erasure | `audit_erase_person(subject, pseudonym, subject_email)`, ledger-only, `SECURITY DEFINER`; the host cleans its own tables in the same transaction |

## Install

```sh
pnpm add @wtfalch/audit @wtfalch/db
```

The package ships SQL and never connects or migrates. The host installs
`@wtfalch/db` (this package declares it only as an optional peer, for the
`audit-verify-chain` command), applies the SQL with the owner credential into
a schema of its own, then makes the runtime role. The runtime `searchPath`
and `ensureRuntimeRole({ schemas })` must both cover that schema.

```ts
import { migrationsDir as auditMigrations } from '@wtfalch/audit/migrations-dir';
import { createDatabase } from '@wtfalch/db/postgres';
import { runMigrationSources } from '@wtfalch/db/migrate';
import { assertRuntimeRole, ensureRuntimeRole } from '@wtfalch/db/runtime-role';

const ownerUrl = process.env.DATABASE_URL_OWNER;
const runtimeUrl = process.env.DATABASE_URL;
if (!ownerUrl || !runtimeUrl) throw new Error('DATABASE_URL_OWNER and DATABASE_URL are required');

await runMigrationSources({
  url: ownerUrl,
  schema: 'orders', // created if missing; the ledger lands here, never in public
  sources: [
    { name: 'audit', dir: auditMigrations }, // before the host's own, which may add CHECKs to audit_events
    { name: 'app', dir: 'drizzle' },
  ],
});

await ensureRuntimeRole({
  ownerUrl,
  runtimeUrl,
  schemas: ['orders'],
  appendOnly: ['audit_events'], // insert and read only: UPDATE, DELETE and TRUNCATE revoked
  grants: [ // the four security definer functions, schema-qualified
    'orders.audit_erase_person(text, text, text)',
    'orders.audit_seal_erasure(bigint, text)',
    'orders.audit_chain_tail()',
    'orders.audit_pending_erasures()',
  ],
  settings: { 'audit.require_tenant': 'on' }, // optional: an unscoped read sees nothing
});

const connection = createDatabase({
  url: () => runtimeUrl,
  searchPath: ['orders', 'public'], // `audit_events` resolves in `orders`
});
await assertRuntimeRole(connection.database, { appendOnly: ['orders.audit_events'] });
```

Run `ensureRuntimeRole` after every migration run: the lists apply to the
tables that exist at that moment. `grants` entries are spliced into SQL, so
they are trusted text. Call `assertRuntimeRole` from `@wtfalch/db/runtime-role`
once at boot, as above; it names the table as `schema.table`, and it also
refuses a role that owns objects.

Without `@wtfalch/db`, `audit-migrations` still copies `migrations/*.sql`
into `drizzle/` as the next numbers (recorded in
`drizzle/.audit-migrations.json`; running it again copies nothing), and the
host applies them itself. Prefer `runMigrationSources`: the copy path has no
schema and no runtime-role step, so the host must grant and revoke by hand.

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

// Readers. `page()` refuses unless `access` allows `audit:read` on `resource`;
// a tenant-facing page also always passes tenantVisibleOnly.
const resource = { type: 'audit.event', id: tenantId, organisationId: tenantId, teamId: null, applicationId, platformId };
const page = await ledger.page(db, { access, resource, tenantId, tenantVisibleOnly: true, limit: 50 });
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

`migrations/0005_rls.sql` turns on row-level security, and
`migrations/0006_force_rls.sql` forces it: a read inside a tenant-scoped
transaction sees that tenant's rows and nothing else, whatever predicate the
query forgot, for every role -- including the table's owner, not just
the runtime role. Only an actual Postgres superuser bypasses RLS regardless of
FORCE, and a host's runtime connection should never be one.

```ts
import { scopeAuditTenant } from '@wtfalch/audit';

await db.transaction(async (tx) => {
  await scopeAuditTenant(tx, tenantId); // set_config('audit.tenant_id', ..., true)
  const page = await ledger.page(tx, { access, resource, tenantId, tenantVisibleOnly: true });
});
```

Unscoped reads still see every row, so applying the migration changes nothing
until the host scopes. To make a forgotten scope see nothing instead, set it
on the role the app connects as, through `ensureRuntimeRole` (above):

```ts
settings: { 'audit.require_tenant': 'on' }
```

An operator surface that reads across tenants then connects as another role.
Which role that is belongs to the host.

Neither that nor the append-only revoke above is enforced by this package's
SQL: both depend on the connection being the role `ensureRuntimeRole` made,
and no migration can see what role a given deployment's connection string
will actually resolve to. The package's own `assertRuntimeRole` throws
`UnsafeRuntimeRoleError` if the connected role can bypass row-level security
(superuser or BYPASSRLS) or still holds UPDATE, DELETE or TRUNCATE on
`audit_events`.

**`createLedger` runs it for you.** The ledger it returns checks the first
handle any of `sign`/`page`/`erase`/`exportRows` is called with, once, and
fails closed before that call -- and every one after, on the same handle --
touches the table if the role is unsafe. This is on by default
(`LedgerOptions.checkRuntimeRole`); turn it off for a connection that is
deliberately broader than the runtime role, such as a test run against a
superuser fixture:

```ts
const ledger = createLedger({ vocabulary, checkRuntimeRole: false }); // e.g. tests against PGlite's superuser connection
```

The check is once per handle, on that handle's first use, not once per
call and not on a timer. A handle a host holds for a long time -- a pooled
connection, a client built once at module scope -- is checked once for as
long as the host keeps using that same handle object, which can be the
whole process lifetime; a role change made afterward (a revoked grant, a
rotated runtime role) is not picked up on that handle. To have a role
change take effect, give the ledger a handle it has not seen before -- pass
a fresh transaction handle per request, which is the usual shape for a web
host -- or restart the process. If your own tests run against a superuser
connection -- PGlite is one, and so is a local Postgres reached as
`postgres` -- pass `checkRuntimeRole: false` to `createLedger` in those
tests, the same way this package's own PGlite-backed tests do; the check
throws on a superuser connection by design.

`assertRuntimeRole` also stays exported, but is deprecated for a host's boot
path: call `assertRuntimeRole` from `@wtfalch/db/runtime-role` there, as in
Install above. It is kept so this package needs no runtime dependency on
`@wtfalch/db`, and because `createLedger` runs it. Its table name resolves
through the connection's `search_path`, so the runtime `searchPath` must
include the schema:

```ts
import { assertRuntimeRole } from '@wtfalch/audit';

await assertRuntimeRole(db); // throws if the connection can bypass RLS or update, delete or truncate audit_events
```

With `hashChain` on, `sign()` and `erase()` now read the chain tail and the
pending erasures through `audit_chain_tail()` and `audit_pending_erasures()`,
both added in 0005. Apply 0005 before deploying this version.

## Verifying the chain

`hashChain` costs a serialization on every write; the payoff is checking it.
`audit-verify-chain` reads the whole `audit_events` table and runs
`verifyChain` over it:

```sh
DATABASE_URL="$ADMIN_DATABASE_URL" pnpm exec audit-verify-chain --schema orders
```

It exits 0 when the chain holds, 1 when it does not (printing the first bad
row's id and the reason), 2 when it could not run, and 3 when the table
held 0 rows, so nothing was verified (it prints a warning; the runtime role
reads 0 rows under row-level security). Give the URL as `DATABASE_URL`, not
`--database-url`, so the password stays out of the process list. Connect as the
table's owner or an admin role, not the runtime role: row-level security
hides other tenants' rows from that role and the chain would look broken.
It needs `@wtfalch/db` installed (an optional peer), the one place this
package opens a connection. `--schema <name>` is the schema the host migrated
into; without it the connection's own `search_path` applies.

- `--after-id <n>` skips rows up to an id, for a table whose early rows
  were written before `hashChain` was on and report `unsealed`.
- `--head <hash>` is the `row_hash` the newest row must have. Keep the last
  run's printed head somewhere outside the database; without it, rows
  deleted off the end are not detectable.

Run it on a schedule, for example a nightly cron or scheduled CI job, and
page on a non-zero exit. The same check is `verifyTable(handle, options)`
from the root entry, for a host that would rather call it from its own job.
The scheduling is the host's; this package ships no framework for it.

### Anchoring the head outside the database

The chain alone cannot catch a rewrite by someone who can write the table (a
superuser, a disabled trigger, a restored backup). They change a row and
reseal every later row exactly as `sealRow` does, and `audit-verify-chain`
still exits 0. The one thing they cannot forge is a head you saved before the
rewrite. So after each clean run, the host saves the printed head to storage
the database role cannot write: another host, a bucket with object lock, or
an append-only log service. Keep every head, never overwrite one.

```sh
#!/bin/sh
# ANCHOR is a file on storage the database role cannot write, one head per line.
set -eu
OUT=$(DATABASE_URL="$ADMIN_DATABASE_URL" pnpm exec audit-verify-chain)
echo "$OUT"
HEAD=$(echo "$OUT" | sed -n 's/.*head \([0-9a-f]\{64\}\)$/\1/p')
test -n "$HEAD"
echo "$HEAD" >> "$ANCHOR"
```

`set -e` stops the script on any non-zero exit, so a broken chain (exit 1) or
an empty or hidden table (exit 3) is never anchored. `test -n` stops it when
no head was printed. Page on any failure. On an object-lock bucket, write each
head as its own object instead of appending to one file.

To check against an anchor, pass it as `--head`. It must equal the newest
row's `row_hash`, so use it when no row was written since the anchor was
taken (right after the run, a write freeze, or an incident check on a
restored copy):

```sh
DATABASE_URL="$ADMIN_DATABASE_URL" pnpm exec audit-verify-chain --head "$(tail -n 1 "$ANCHOR")"
```

A rewrite that reseals forward changes every `row_hash` from the edited row
on, so exit 1 with reason `head` means the chain no longer ends where you
anchored it. On a ledger still taking writes, the newest row has moved on, so
check instead that each anchored head is still a stored `row_hash`; a missing
one means a rewrite or a deletion:

```sql
select count(*) from audit_events where row_hash = '<anchored head>';  -- 1 expected
```

## Reading across apps

The ledger stays per app (see "A service with no tenant database" and
"Tenant isolation in the database" above) -- there is no shared store this
section reaches into. What it adds is a read contract a host mounts, so a
company-facing app like Boule can fan out to every app a company uses and
show one merged security log, without any app's signer leaving its own
trusted base. See [ADR 0001](../../docs/adr/0001-ledger-read-handler.md)
for the reasoning behind this shape.

Everything below imports from `@wtfalch/audit/read`, not the root entry:
`@wtfalch/contracts` is an optional peer, and the root entry never loads it,
so a host that only writes to the ledger never needs it installed. Add
`@wtfalch/contracts` before mounting `ledgerReadHandler` or calling
`fetchMergedLedgerPage`.

### The handler

```ts
import { ledgerReadHandler } from '@wtfalch/audit/read';

const handler = ledgerReadHandler({
  ledger,
  handle: db,
  authorize,
  applicationId: 'files', // this host's own ids, for the AccessResource audit:read is checked against
  platformId: 'wtfalch',
});
// Next.js: export const GET = (request) => handler(request);
```

`GET /v1/audit?tenant=<id>&cursor=&limit=` answers only that tenant's
`tenantVisible` rows, as `LedgerReadRow` (a deliberate subset of the full
row -- no `before`/`after`, no request metadata, no hash-chain internals;
see the ADR), paged with the estate's convention: `cursor`/`limit` in,
`nextCursor` out (`@wtfalch/contracts` ADR 0008). A `cursor` that fails to
decode answers `conflict` (409) -- restart from the first page.

### `authorize`: a port, not a dependency

`authorize(request) => { tenantId, access } | null` is the whole contract.
This package imports nothing from `@wtfalch/keys` -- a host wires it from
`@wtfalch/keys/issued`'s `check()`, reading `tenantId` off whichever grant
shape that host's own issuer uses, and resolves `access` (a
`@wtfalch/authz` `ResourceAccess`) the same way its other routes already do
for that credential:

```ts
import type { Authorize } from '@wtfalch/audit/read';

// issuer: CredentialIssuer<{ tenantId: string; scope: 'audit:read' }>
// from createCredentialIssuer (@wtfalch/keys/issued), built once at module
// scope inside this app's own trusted base.
const authorize: Authorize = async (request) => {
  const header = request.headers.get('authorization');
  const secret = header?.startsWith('Bearer ') ? header.slice(7) : null;
  if (!secret) return null;
  const result = await issuer.check(secret);
  if (!result.ok) return null;
  const grant = result.grants.find((g) => g.scope === 'audit:read');
  if (!grant) return null;
  const access = resourceAccessFor(result); // this host's own resolution, as for any other route
  return { tenantId: grant.tenantId, access };
};
```

A request whose credential resolves to a different tenant than the
`tenant` query parameter, or whose `access` does not allow `audit:read`, is
refused (`forbidden`), never silently substituted -- Boule fans out with
one credential per tenant per app, not one credential that can read every
tenant.

### The client

```ts
import { fetchMergedLedgerPage } from '@wtfalch/audit/read';

const page = await fetchMergedLedgerPage({
  tenant: tenantId,
  sources: [
    { name: 'files', baseUrl: 'https://files.example.com', credential: filesKey },
    { name: 'ai', baseUrl: 'https://ai.example.com', credential: aiKey },
  ],
});
// page.items: MergedLedgerRow[], newest first, each carrying `source`.
// page.nextCursors: { files: '...' | null, ai: '...' | null } — pass back
// as `cursors` on the next call to page every source forward together.
// page.errors: { [sourceName]: message } for a source that failed this round.
```

There is no single cursor across sources -- each keeps its own keyset
position -- and one source failing does not fail the call; it is just
missing from that round and named in `errors`.

## To a customer's SIEM

`toCef(row)` renders one ledger row as a CEF (Common Event Format) line, the
format Splunk, QRadar, Sentinel and ArcSight ingest directly or over syslog;
`toCefLines(rows)` does a page of them, one per line.

```ts
import { toCef, toCefLines } from '@wtfalch/audit';

const { items } = await ledger.page(db, { access, resource, tenantId, limit: 500 });
const body = toCefLines(items, { vendor: 'Acme', product: 'Acme', version: '2.3' });
```

The push half (a webhook, a syslog socket, a file a shipper tails) is the
host's: which transport, whose endpoint, whose credentials and whose retry
policy are one decision per enterprise customer, not the package's.

## Tests

```sh
pnpm test                                        # PGlite, in memory
TEST_DATABASE_URL=postgres://... pnpm test       # a real Postgres; one uniquely named schema per test, dropped after
```

The real run never touches `public`. It adds the runtime-role tests: a role
made by `ensureRuntimeRole` with the lists above may insert and call
`audit_erase_person`, and may not update, delete or truncate.

## Release

Tag `v*`. The workflow builds, tests and publishes with npm trusted
publishing; the first publish of a new package is done from a laptop.
