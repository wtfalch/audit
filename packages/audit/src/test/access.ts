import type { AccessResource, ResourceGrant } from '@wtfalch/authz';
import { resourceAccess } from '@wtfalch/authz';
import { catalogue } from '../catalogue.js';

/**
 * A minimal `@wtfalch/authz` fixture for this package's own tests: one
 * platform-wide grant (or none), so the same `access` fixture works for a
 * resource in any tenant this file's tests use, real or `null`. Not a
 * pattern for a host to copy wholesale -- a host's own tests build against
 * its own catalogue and organisations, the way `files.test.ts` does.
 */
const APPLICATION_ID = 'audit-test';
const PLATFORM_ID = 'wtfalch';
const PRINCIPAL = { class: 'human' as const, id: 'tester' };

const ALL_RESTRICTIONS = {
  kind: 'customer' as const,
  state: 'active' as const,
  ceiling: Object.keys(catalogue),
  selfDenied: [],
  denied: [],
  support: null,
};

function grantsFor(permissions: readonly string[]): ResourceGrant[] {
  return permissions.map((permission) => ({
    id: permission,
    applicationId: APPLICATION_ID,
    platformId: PLATFORM_ID,
    boundary: { kind: 'platform' },
    permission,
    recipient: { kind: 'principal', principal: PRINCIPAL },
    scope: { kind: 'organisation' },
    relation: 'any',
  }));
}

/** Every tenant id this package's own tests read the ledger for. */
const KNOWN_TENANTS = [
  '11111111-1111-4111-8111-111111111111',
  '22222222-2222-4222-8222-222222222222',
  'tenant_a',
  'tenant_b',
];

function makeAccess(permissions: readonly string[]) {
  return resourceAccess({
    applicationId: APPLICATION_ID,
    platformId: PLATFORM_ID,
    principal: PRINCIPAL,
    catalogue,
    organisations: KNOWN_TENANTS.map((id) => ({ id, restrictions: ALL_RESTRICTIONS })),
    platformRestrictions: { ...ALL_RESTRICTIONS, kind: 'operator' },
    teams: [],
    memberships: [],
    now: Date.now(),
    grants: grantsFor(permissions),
  });
}

/** Holds `audit:read`, platform-wide. */
export const ALLOW_AUDIT_READ = makeAccess(['audit:read']);
/** Holds nothing this catalogue names. */
export const DENY_AUDIT_READ = makeAccess([]);

/** The resource `audit:read` is checked against, for one tenant (or `null` for an estate-level read). */
export function auditResource(tenantId: string | null): AccessResource {
  return {
    id: tenantId ?? 'platform',
    type: 'audit.event',
    applicationId: APPLICATION_ID,
    platformId: PLATFORM_ID,
    organisationId: tenantId,
    teamId: null,
  };
}
