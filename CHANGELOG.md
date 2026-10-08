# Changelog

## 0.13.0 — unreleased

0.12.0 is skipped: another open change claims that number.

- **Breaking, `hashChain` writes row format 2.** A row carries `chain_version`
  2, a gap-free `seq` and `received_at` (the database clock to the
  millisecond), and its hash covers both. The salted content hash and the
  erasure hash are canonical JSON v2 (RFC 8785, restricted). Rows written in
  format 1 keep verifying; `verifyChain` and `verifyTable` check a table with
  both, and the first format 2 row links to the last format 1 row.
- **Breaking, `sign()` with `hashChain` on refuses a float** in `before` or
  `after`. A number must be a safe integer; it throws before any insert.
- **Breaking, three migrations.** `0007_chain_v2.sql` (three nullable columns on
  `audit_events`, a unique `seq`, `audit_chain_tail_v2()`,
  `audit_chain_leaves()`), `0008_checkpoints.sql` (`audit_checkpoints`,
  `audit_signing_keys`, `audit_retire_signing_key()`) and `0009_anchors.sql`
  (`audit_anchors`). Apply them before deploying: `sign()` with `hashChain`
  fails without 0007.
- **Breaking, no overlap with an older writer.** Once the first format 2 row is
  written, a writer on the older package version fails on every `sign()` until
  it is replaced (0007 refuses its sealed format 1 row). Deploy without
  overlap, or accept failed writes during it.
- **Breaking, new grants.** The host's `ensureRuntimeRole` call adds
  `audit_chain_tail_v2()`, `audit_chain_leaves(bigint, integer)` and
  `audit_retire_signing_key(text)` to `grants`, and `audit_checkpoints`,
  `audit_signing_keys` and `audit_anchors` to `appendOnly`. See "Install".
- `sealCheckpoint`, `retireSigningKey`, `verifyCheckpoint`, `listCheckpoints`:
  signed Merkle checkpoints (RFC 6962) over the format 2 rows. The host passes
  a `CheckpointSigner` whose private key stays outside this package.
- `proveInclusion`, `verifyInclusion`, `proveConsistency`, `verifyConsistency`:
  proofs for one row and between two checkpoints.
- `anchorCheckpoints`: RFC 3161 timestamps of checkpoints from an outside
  authority. Only each checkpoint's hash leaves the system.
- `buildBundle` and `audit-export-bundle`: an evidence bundle for a range of
  rows. `audit-verify-bundle` checks it offline with Node alone, and exits 0,
  1, 2 or 3 (unconfirmed: keys or authority roots not supplied).
- The root entry also exports `canonicalJsonV2`, `sealRowV2`, and the
  `audit_checkpoints`, `audit_signing_keys` and `audit_anchors` tables.
- README: "Sealed checkpoints, anchors and bundles", with what a pass proves
  and what it does not.

## 0.11.1

- The peer `@wtfalch/authz` widens from `^0.16.0` to `>=0.16.0 <0.18.0`. A host
  that installs this package with `@wtfalch/authz-store` 0.6.0 (peer
  `@wtfalch/authz ^0.17.0`) could not satisfy both. This package imports only
  authz's resource subset, which 0.17.0 did not move (authz STABILITY.md), so
  no code changes. The dev dependency moves to `@wtfalch/authz` 0.17.0; the
  suite also passes against 0.16.0.

## 0.11.0 — unreleased

0.7.0 to 0.10.0 were never released: npm has 0.6.0, and a host moving from it
takes every Breaking entry below and in 0.7.0, 0.8.0 and 0.9.0.

- **Breaking, the SQL no longer names a role or a schema.** `migrations/0001`
  to `0006` are edited in place under package-template ADR 0015 as amended,
  because every estate database is recreated empty in this move. npm 0.6.0
  shipped 0001 to 0005, so a database that applied those files must be
  recreated. The seven
  `SECURITY DEFINER` functions use `set search_path from current` instead of
  the literal `pg_catalog, public`, so they find their table in whatever
  schema the host migrated into. Every `DO` block that computed
  `<database>_rt` to revoke and grant is deleted.
- **Hosts migrate with `@wtfalch/db` 0.5.2 or later.** Before 0.5.2 the runner's
  `search_path` had no `pg_temp`, so `set search_path from current` froze a
  path on which PostgreSQL searches temp objects first, and a runtime role's
  temp table named `audit_events` shadowed the function's table. 0.5.2
  migrates with `<schema>, public, pg_temp`, which closes that.
- **Breaking, the revokes and grants move to the host.** `ensureRuntimeRole`
  from `@wtfalch/db` replaces the `<database>_rt` blocks: `appendOnly:
  ['audit_events']`, `grants` with the four schema-qualified function
  signatures, and `settings: { 'audit.require_tenant': 'on' }` where wanted.
  A host that does not pass them has a runtime role that can UPDATE and DELETE
  the ledger. See "Moving from 0.10".
- `@wtfalch/audit/migrations-dir` exports `migrationsDir`, the directory of
  `.sql` files, for `runMigrationSources({ sources: [{ name: 'audit', dir:
  migrationsDir }] })`. Its own subpath with no imports but `node:url`; the
  main entry does not export it. `audit-migrations` and
  `@wtfalch/audit/migrations/*.sql` stay, as the fallback.
- `audit-verify-chain --schema <name>` verifies a chain in a named schema. The
  command now connects through `@wtfalch/db` (`createDatabase`, `max: 1`), so
  the optional `postgres` peer added in 0.10.0 is replaced by an optional
  `@wtfalch/db` peer, `>=0.5.2 <0.6.0`. It is the one place this package
  opens a connection.
- `assertRuntimeRole` stays exported and `createLedger` still runs it, but it
  is deprecated for a host's boot path: use `assertRuntimeRole` from
  `@wtfalch/db/runtime-role` with `appendOnly: ['<schema>.audit_events']`.
  No runtime dependency on `@wtfalch/db` was added for it.
- `drizzle-orm` peer is `>=0.39.3 <1.0.0` (was `>=0.39.0`); the devDependency
  is `0.39.3`, the low end. `@wtfalch/db` 0.5.2 is a devDependency (tests).
- Tests: the fixture applies the migrations with `runMigrationSources`. With
  `TEST_DATABASE_URL` each test gets a uniquely named schema, dropped after
  and when setup fails, and `public` is never dropped or touched. A new
  default-tier test migrates into a named schema and proves the tables are
  not in `public`. The runtime-role, privilege and FORCE RLS tests log in as a
  role made by `ensureRuntimeRole`, in a named schema.

### Breaking since 0.6.0, the last release on npm

1. 0.11.0: the two entries above (SQL edited in place; revokes and grants are
   the host's through `ensureRuntimeRole`).
2. 0.10.0: new optional peer `postgres`, now superseded by the optional
   `@wtfalch/db` peer above.
3. 0.9.0: the `./react` reader needs `@wtfalch/design` `^0.30.0` (was
   `^0.28.0`).
4. 0.8.0: `ledgerReadHandler`, `fetchLedgerPage`, `fetchMergedLedgerPage`,
   `LedgerReadError` and their types are only at `@wtfalch/audit/read`; 0.6.0
   never had them in the main entry (0.7.0 added them there, 0.8.0 moved them).
5. 0.7.0: `page()` requires `access` and `resource` and throws
   `PermissionDeniedError` unless `access.allows('audit:read', resource)`;
   `@wtfalch/authz` `^0.16.0` is a new peer; `@wtfalch/contracts` `^0.2.0` is a
   new optional peer; `migrations/0006_force_rls.sql` forces RLS on the table's
   owner.

### Moving from 0.10

Before, the host copied the SQL and relied on a role named after the database:

```sh
pnpm exec audit-migrations   # into drizzle/, applied by the host's migrate script
```

The `DO` blocks revoked `UPDATE, DELETE, TRUNCATE` from `<database>_rt` and
granted it `EXECUTE` on the functions. In a named schema on a shared database
they would have found no such role, and done nothing.

After, with the owner credential, once per deploy (full docs:
https://github.com/wtfalch/audit/blob/main/packages/audit/README.md):

```ts
import { migrationsDir as auditMigrations } from '@wtfalch/audit/migrations-dir';
import { runMigrationSources } from '@wtfalch/db/migrate';
import { ensureRuntimeRole } from '@wtfalch/db/runtime-role';

await runMigrationSources({
  url: ownerUrl,
  schema: 'orders',
  sources: [
    { name: 'audit', dir: auditMigrations }, // before the host's own
    { name: 'app', dir: 'drizzle' },
  ],
});
await ensureRuntimeRole({
  ownerUrl,
  runtimeUrl,
  schemas: ['orders'],
  appendOnly: ['audit_events'],
  grants: [
    'orders.audit_erase_person(text, text, text)',
    'orders.audit_seal_erasure(bigint, text)',
    'orders.audit_chain_tail()',
    'orders.audit_pending_erasures()',
  ],
  settings: { 'audit.require_tenant': 'on' }, // replaces `alter role <database>_rt set ...`
});
```

In the server, the runtime connection's `searchPath` must include the schema,
and the boot check names the table with its schema:

```ts
import { createDatabase } from '@wtfalch/db/postgres';
import { assertRuntimeRole } from '@wtfalch/db/runtime-role';

const connection = createDatabase({ url: () => runtimeUrl, searchPath: ['orders', 'public'] });
await assertRuntimeRole(connection.database, { appendOnly: ['orders.audit_events'] });
```

`audit-verify-chain` takes the owner credential and the schema:

```sh
DATABASE_URL="$DATABASE_URL_OWNER" pnpm exec audit-verify-chain --schema orders
```

## 0.10.0 — unreleased

- `audit-verify-chain` command and `verifyTable(handle, options)`: run
  `verifyChain` over a whole live `audit_events` table, page by page, and
  exit non-zero with the first bad row's id when the chain is broken. Until
  now nothing in the package called `verifyChain`. `postgres` is a new
  optional peer, needed only by the command. (#23)

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
