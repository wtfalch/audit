import { type ResourceModule, defineResourceCatalogue } from '@wtfalch/authz';

/**
 * This package's own `@wtfalch/authz` catalogue: the one permission a
 * caller needs to read across the audit log, whether through
 * `ledgerReadHandler` or `ledger.page()` directly. A host's own catalogue
 * composes this module in beside its own (`defineResourceCatalogue([...its
 * modules, auditPolicyModule])`) so `audit:read` is assignable and
 * ceiling-checked the same way every other estate permission is.
 */
export const auditPolicyModule = {
  namespace: 'audit',
  permissions: [
    {
      id: 'audit:read',
      label: 'Read audit log',
      description:
        "Read a tenant's audit trail -- across every app that signs into it, not just the reading app's own rows.",
      resourceType: 'audit.event',
      effect: 'read',
      scopes: ['organisation'],
      boundaries: ['organisation', 'organisations', 'platform'],
      relations: ['any'],
      tenantKinds: ['customer', 'operator'],
      offered: false,
      assignable: true,
      sensitive: true,
      survives: ['read_only'],
      support: 'read',
    },
  ],
} as const satisfies ResourceModule;

export const catalogue = defineResourceCatalogue([auditPolicyModule]);
export type Permission = (typeof auditPolicyModule.permissions)[number]['id'];
