import { describe, expect, it } from 'vitest';
import { catalogue } from './catalogue.js';
import { ALLOW_AUDIT_READ, DENY_AUDIT_READ, auditResource } from './test/access.js';

describe('audit:read catalogue', () => {
  it('names audit:read', () => {
    expect(Object.keys(catalogue)).toEqual(['audit:read']);
  });

  it('allows a principal holding audit:read', () => {
    expect(ALLOW_AUDIT_READ.allows('audit:read', auditResource('tenant_a'))).toBe(true);
  });

  it('refuses an ungranted principal, with a reason', () => {
    expect(DENY_AUDIT_READ.allows('audit:read', auditResource('tenant_a'))).toBe(false);
    expect(DENY_AUDIT_READ.whyDenied('audit:read', auditResource('tenant_a'))).not.toBeNull();
  });
});
