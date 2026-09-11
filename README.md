# audit

The estate's append-only audit ledger, published as `@wtfalch/audit`. It
sits beside `auth` (who is this), `authz` (what may they do), `reporting`
(what did the system do) and `design` (what does it look like), and answers
the question the others cannot: what did a person do, and who did what to
them.

The package is in `packages/audit`; its README says what it enforces, what
the host does, and how an app binds it. The design it implements is
`docs/plans/reporting/audit.md` and ADR 0016 in `wtfalch/app-template`.

```
pnpm install
pnpm build && pnpm lint && pnpm typecheck && pnpm test
```

Tests run on PGlite in memory by default. With `TEST_DATABASE_URL` pointing
at a throwaway Postgres 16 they run there instead, and the runtime-role test
joins them. Releases are tags: `git tag v0.1.0 && git push --tags` builds,
tests and publishes through npm trusted publishing.
