import { describe, expect, it } from 'vitest';
import { AUDIT_LIMITS, isJsonValue, rowSchema } from './schema.js';
import { CORE } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

const vocabulary = ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } });
const schema = rowSchema(vocabulary);

const base = {
  occurred_at: '2026-09-11T10:00:00.000Z',
  tenant_id: '11111111-1111-4111-8111-111111111111',
  actor_class: 'human',
  actor_id: 'user_1',
  actor_display: 'Ada',
  action: 'membership.created',
  target_type: 'membership',
  target_id: 'm_1',
  outcome: 'success',
  context: 'standard',
  session_id: null,
  reason: null,
  reference: null,
  request_id: null,
  ip: null,
  user_agent: null,
  tenant_visible: true,
  before: null,
  after: { role: 'member' },
  erased_at: null,
  schema_version: 1,
  subject_class: null,
  subject_id: null,
};

describe('rowSchema', () => {
  it('accepts a well-formed row', () => {
    expect(schema.parse(base)).toEqual(base);
  });

  it('refuses an event outside the vocabulary and a column it does not know', () => {
    expect(schema.safeParse({ ...base, action: 'invoice.refunded' }).success).toBe(false);
    expect(schema.safeParse({ ...base, actorId: 'x' }).success).toBe(false);
    expect(schema.safeParse({ ...base, actor_class: 'robot' }).success).toBe(false);
    expect(schema.safeParse({ ...base, outcome: 'maybe' }).success).toBe(false);
    expect(schema.safeParse({ ...base, context: 'sudo' }).success).toBe(false);
  });

  it('requires session, a reason code and a reference in the break-glass context', () => {
    const bg = { ...base, context: 'break_glass' };
    const r = schema.safeParse(bg);
    expect(r.success).toBe(false);
    if (!r.success) {
      expect(r.error.issues.map((i) => i.path[0]).sort()).toEqual([
        'reason',
        'reference',
        'session_id',
      ]);
    }
    expect(
      schema.safeParse({ ...bg, session_id: 's', reason: 'because', reference: 'INC-1' }).success,
    ).toBe(false);
    expect(
      schema.safeParse({ ...bg, session_id: 's', reason: 'incident', reference: 'INC-1' }).success,
    ).toBe(true);
    // Outside break-glass, reason is free text.
    expect(schema.safeParse({ ...base, reason: 'because' }).success).toBe(true);
  });

  it('keeps subject_class and subject_id together', () => {
    expect(schema.safeParse({ ...base, subject_id: 'u_2' }).success).toBe(false);
    expect(schema.safeParse({ ...base, subject_class: 'human' }).success).toBe(false);
    expect(schema.safeParse({ ...base, subject_class: 'human', subject_id: 'u_2' }).success).toBe(
      true,
    );
    expect(schema.safeParse({ ...base, subject_class: 'robot', subject_id: 'u_2' }).success).toBe(
      false,
    );
  });

  it('bounds every text column and the payloads', () => {
    expect(schema.safeParse({ ...base, actor_id: 'x'.repeat(AUDIT_LIMITS.id + 1) }).success).toBe(
      false,
    );
    expect(schema.safeParse({ ...base, actor_display: '' }).success).toBe(false);
    expect(schema.safeParse({ ...base, target_type: 'x'.repeat(65) }).success).toBe(false);
    expect(schema.safeParse({ ...base, user_agent: 'x'.repeat(1025) }).success).toBe(false);
    expect(
      schema.safeParse({ ...base, after: { blob: 'x'.repeat(AUDIT_LIMITS.jsonBytes) } }).success,
    ).toBe(false);
  });

  it('refuses payloads that would not survive JSON', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(schema.safeParse({ ...base, after: cyclic }).success).toBe(false);
    expect(schema.safeParse({ ...base, after: { d: new Date() } }).success).toBe(false);
    expect(schema.safeParse({ ...base, after: { n: Number.NaN } }).success).toBe(false);
    expect(schema.safeParse({ ...base, after: [1, 'two', null, { three: true }] }).success).toBe(
      true,
    );
  });
});

describe('isJsonValue', () => {
  it('is what JSON.stringify would keep intact', () => {
    expect(isJsonValue(null)).toBe(true);
    expect(isJsonValue('s')).toBe(true);
    expect(isJsonValue(1.5)).toBe(true);
    expect(isJsonValue(Number.POSITIVE_INFINITY)).toBe(false);
    expect(isJsonValue(undefined)).toBe(false);
    expect(isJsonValue(() => 1)).toBe(false);
    expect(isJsonValue(new Map())).toBe(false);
    expect(isJsonValue(Object.create(null))).toBe(true);
  });
});
