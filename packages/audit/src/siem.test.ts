import { describe, expect, it } from 'vitest';
import { toCef, toCefLines } from './siem.js';
import type { AuditEventRow } from './tables.js';

const when = new Date('2026-09-23T12:00:00.000Z');

function row(over: Partial<AuditEventRow> = {}): AuditEventRow {
  return {
    id: 1,
    occurredAt: when,
    tenantId: '11111111-1111-4111-8111-111111111111',
    actorClass: 'human',
    actorId: 'user_ada',
    actorDisplay: 'Ada Lovelace',
    action: 'membership.created',
    targetType: 'membership',
    targetId: 'm1',
    targetDisplay: null,
    tenantDisplay: null,
    outcome: 'success',
    context: 'standard',
    sessionId: null,
    reason: null,
    reference: null,
    requestId: 'req_1',
    ip: null,
    userAgent: null,
    tenantVisible: true,
    before: null,
    after: null,
    erasedAt: null,
    schemaVersion: 1,
    subjectClass: 'human',
    subjectId: 'user_bob',
    prevHash: null,
    rowHash: null,
    contentHash: null,
    contentSalt: null,
    erasureHash: null,
    ...over,
  };
}

describe('toCef', () => {
  it('writes the header and the standard-dictionary extension fields', () => {
    const line = toCef(row());
    expect(line).toBe(
      `CEF:0|wtfalch|@wtfalch/audit|1|membership.created|membership.created|1|rt=${when.getTime()} act=membership.created outcome=success suser=Ada Lovelace suid=user_ada cs1Label=TargetType cs1=membership cs2Label=TargetID cs2=m1 cs3Label=TenantID cs3=11111111-1111-4111-8111-111111111111 cs4Label=Context cs4=standard cs5Label=RequestID cs5=req_1 cs6Label=SubjectID cs6=user_bob`,
    );
  });

  it('a non-success outcome reads severity 7 by default; success reads 1', () => {
    expect(toCef(row({ outcome: 'success' }))).toContain('|1|');
    expect(toCef(row({ outcome: 'denied' }))).toContain('|7|');
  });

  it('a caller may override severity', () => {
    expect(toCef(row({ outcome: 'denied' }), { severity: () => 3 })).toContain('|3|');
  });

  it('omits a labelled custom field entirely when its value is null, not as an empty value', () => {
    const line = toCef(row({ tenantId: null, requestId: null, subjectId: null }));
    expect(line).not.toContain('cs3');
    expect(line).not.toContain('cs5');
    expect(line).not.toContain('cs6');
    expect(line).toContain('cs1Label=TargetType');
  });

  it('includes msg only when reason is given', () => {
    expect(toCef(row())).not.toContain('msg=');
    expect(toCef(row({ reason: 'customer requested export' }))).toContain(
      'msg=customer requested export',
    );
  });

  it('names the device from options, defaulting to the package', () => {
    const line = toCef(row(), { vendor: 'Acme', product: 'Acme Audit', version: '2.3' });
    expect(line.startsWith('CEF:0|Acme|Acme Audit|2.3|')).toBe(true);
  });

  it('escapes header metacharacters (\\ and |) and extension metacharacters (\\, = and newlines)', () => {
    const line = toCef(row({ actorDisplay: 'Weird\\Name|With=Chars\nAnd a newline' }), {
      vendor: 'A\\B|C',
    });
    expect(line).toContain('CEF:0|A\\\\B\\|C|');
    expect(line).toContain('suser=Weird\\\\Name|With\\=Chars\\nAnd a newline');
  });
});

describe('toCefLines', () => {
  it('joins one line per row with newlines, in the given order', () => {
    const lines = toCefLines([
      row({ id: 1, action: 'invoice.paid' }),
      row({ id: 2, action: 'tenant.created' }),
    ]);
    const parts = lines.split('\n');
    expect(parts).toHaveLength(2);
    expect(parts[0]).toContain('invoice.paid');
    expect(parts[1]).toContain('tenant.created');
  });

  it('the empty array is the empty string', () => {
    expect(toCefLines([])).toBe('');
  });
});
