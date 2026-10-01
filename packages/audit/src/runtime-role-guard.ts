import { getTableName, sql } from 'drizzle-orm';
import type { Handle } from './ledger.js';
import { resultRows } from './sql-result.js';
import { type AuditTable, auditEvents as auditEvents_ } from './tables.js';

/**
 * Both of this package's runtime guarantees -- `audit_events` is
 * append-only, and (with `migrations/0005_rls.sql` applied) tenant isolation
 * -- depend on the connection being the runtime role the host made with
 * `ensureRuntimeRole` from `@wtfalch/db`, listing `audit_events` in
 * `appendOnly`. No migration can see what role a given deployment's
 * connection string will actually resolve to, so a host that connects as
 * the table's owner, as a superuser, or as any role `ensureRuntimeRole` never
 * touched gets neither guarantee, with no error anywhere -- README.md's "An
 * app that connects as the table's owner gets no RLS at all" names the exact
 * failure this closes for real, at startup, instead of leaving it to be
 * discovered later.
 *
 * `createLedger` (`ledger.ts`) calls this itself, once per handle it is
 * given, before `sign`/`page`/`erase`/`exportRows` touch the table --
 * `LedgerOptions.checkRuntimeRole` (on by default) is the switch. It stays
 * exported too, but a host's boot path should call `assertRuntimeRole` from
 * `@wtfalch/db/runtime-role` with `appendOnly: ['<schema>.audit_events']`
 * instead: it also refuses a role that owns objects or belongs to a role that
 * does. This copy stays so the package needs no runtime dependency on
 * `@wtfalch/db`, and so `createLedger` keeps its own per-handle check.
 */
export class UnsafeRuntimeRoleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeRuntimeRoleError';
  }
}

interface RoleRow {
  rolsuper: boolean;
  rolbypassrls: boolean;
}

interface PrivilegeRow {
  can_update: boolean;
  can_delete: boolean;
  can_truncate: boolean;
}

/**
 * Checks the role `handle`'s connection is actually authenticated as --
 * never a name anyone configured it to have -- and throws
 * `UnsafeRuntimeRoleError` if it can bypass row-level security (superuser or
 * BYPASSRLS) or still holds UPDATE, DELETE or TRUNCATE on `table` (the
 * table's owner, or a role `ensureRuntimeRole` never listed `appendOnly`
 * for). Resolves without a value when the role is safe. Unqualified
 * `table` names resolve through the connection's `search_path`, so the host's
 * runtime `searchPath` must include the schema.
 *
 * @deprecated for a host's boot path; use `assertRuntimeRole` from
 * `@wtfalch/db/runtime-role`. `createLedger` still runs this one itself.
 */
export async function assertRuntimeRole(
  handle: Handle,
  table: AuditTable = auditEvents_,
): Promise<void> {
  const tableName = getTableName(table);

  const roleRows = resultRows<RoleRow>(
    await handle.execute(
      sql`select rolsuper, rolbypassrls from pg_roles where rolname = current_user`,
    ),
  );
  const role = roleRows[0];
  if (!role) {
    throw new UnsafeRuntimeRoleError('audit: the connected role is not visible in pg_roles');
  }
  if (role.rolsuper || role.rolbypassrls) {
    throw new UnsafeRuntimeRoleError(
      'audit: the connected role can bypass row-level security (superuser or BYPASSRLS): tenant isolation would not hold for it',
    );
  }

  const privilegeRows = resultRows<PrivilegeRow>(
    await handle.execute(sql`
      select
        has_table_privilege(current_user, ${tableName}, 'UPDATE') as can_update,
        has_table_privilege(current_user, ${tableName}, 'DELETE') as can_delete,
        has_table_privilege(current_user, ${tableName}, 'TRUNCATE') as can_truncate
    `),
  );
  const privileges = privilegeRows[0];
  if (!privileges) {
    throw new UnsafeRuntimeRoleError(
      `audit: could not read privileges on "${tableName}" for the connected role`,
    );
  }
  const offending = (['can_update', 'can_delete', 'can_truncate'] as const).filter(
    (key) => privileges[key],
  );
  if (offending.length > 0) {
    const verbs = offending.map((key) => key.slice('can_'.length).toUpperCase());
    throw new UnsafeRuntimeRoleError(
      `audit: the connected role still has ${verbs.join(', ')} on "${tableName}": it is not the role ensureRuntimeRole made with appendOnly: ['audit_events'], so audit_events is not append-only for it`,
    );
  }
}
