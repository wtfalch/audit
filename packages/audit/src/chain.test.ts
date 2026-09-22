import { describe, expect, it } from 'vitest';
import { type SealInput, computeErasureHash, sealRow, verifyChain } from './chain.js';
import type { AuditEventRow } from './tables.js';

const input: SealInput = {
  occurred_at: '2026-09-22T12:00:00.000Z',
  tenant_id: null,
  tenant_display: null,
  actor_class: 'human',
  actor_id: 'user_ada',
  actor_display: 'Ada Lovelace',
  action: 'invoice.paid',
  target_type: 'invoice',
  target_id: 'i_1',
  target_display: null,
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
  after: { amount: 100 },
  schema_version: 1,
  subject_class: null,
  subject_id: null,
};

/** What `ledger.page()`/`exportRows()` actually return, built from a `sealRow` result the way `sign()` stores it. */
function toEventRow(
  id: number,
  seal: SealInput,
  sealed: Awaited<ReturnType<typeof sealRow>>,
): AuditEventRow {
  return {
    id,
    occurredAt: new Date(seal.occurred_at),
    tenantId: seal.tenant_id,
    tenantDisplay: seal.tenant_display,
    actorClass: seal.actor_class,
    actorId: seal.actor_id,
    actorDisplay: seal.actor_display,
    action: seal.action,
    targetType: seal.target_type,
    targetId: seal.target_id,
    targetDisplay: seal.target_display,
    outcome: seal.outcome,
    context: seal.context,
    sessionId: seal.session_id,
    reason: seal.reason,
    reference: seal.reference,
    requestId: seal.request_id,
    ip: seal.ip,
    userAgent: seal.user_agent,
    tenantVisible: seal.tenant_visible,
    before: seal.before,
    after: seal.after,
    erasedAt: null,
    schemaVersion: seal.schema_version,
    subjectClass: seal.subject_class,
    subjectId: seal.subject_id,
    prevHash: sealed.prev_hash,
    rowHash: sealed.row_hash,
    contentHash: sealed.content_hash,
    contentSalt: sealed.content_salt,
    erasureHash: null,
  };
}

describe('sealRow / verifyChain round trip', () => {
  it('a row sealRow seals verifies, read back in the camelCase shape page()/exportRows() return', async () => {
    const sealed = await sealRow(input, null);
    expect(sealed.row_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(sealed.content_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(sealed.content_salt).toMatch(/^[0-9a-f]{32}$/);
    expect(sealed.prev_hash).toBeNull();
    const row = toEventRow(1, input, sealed);
    expect(await verifyChain([row])).toEqual({ ok: true });
  });

  it('chains three rows, and verifies the run together', async () => {
    const s1 = await sealRow(input, null);
    const r1 = toEventRow(1, input, s1);
    const s2 = await sealRow({ ...input, target_id: 'i_2' }, s1.row_hash);
    const r2 = toEventRow(2, { ...input, target_id: 'i_2' }, s2);
    const s3 = await sealRow({ ...input, target_id: 'i_3' }, s2.row_hash);
    const r3 = toEventRow(3, { ...input, target_id: 'i_3' }, s3);
    expect(r2.prevHash).toBe(r1.rowHash);
    expect(r3.prevHash).toBe(r2.rowHash);
    expect(await verifyChain([r1, r2, r3])).toEqual({ ok: true });
    // Anchored at both ends.
    expect(
      await verifyChain([r1, r2, r3], { origin: null, head: r3.rowHash ?? undefined }),
    ).toEqual({
      ok: true,
    });
  });

  it('catches an edited covered field: row_hash no longer recomputes', async () => {
    const sealed = await sealRow(input, null);
    const row = { ...toEventRow(1, input, sealed), action: 'invoice.refunded' };
    expect(await verifyChain([row])).toEqual({ ok: false, index: 0, reason: 'row_hash' });
  });

  it("catches an edited erasable field while content_salt is still set: content_hash doesn't recompute", async () => {
    const sealed = await sealRow(input, null);
    const row = { ...toEventRow(1, input, sealed), actorDisplay: 'Someone else' };
    expect(await verifyChain([row])).toEqual({ ok: false, index: 0, reason: 'content' });
  });

  it('catches a broken link between two otherwise-valid rows', async () => {
    const s1 = await sealRow(input, null);
    const r1 = toEventRow(1, input, s1);
    // Sealed as if chained onto something else entirely.
    const s2 = await sealRow({ ...input, target_id: 'i_2' }, 'f'.repeat(64));
    const r2 = toEventRow(2, { ...input, target_id: 'i_2' }, s2);
    expect(await verifyChain([r1, r2])).toEqual({ ok: false, index: 1, reason: 'link' });
  });

  it('reports an unsealed row rather than failing the hash check', async () => {
    const row = { ...toEventRow(1, input, await sealRow(input, null)), rowHash: null };
    expect(await verifyChain([row])).toEqual({ ok: false, index: 0, reason: 'unsealed' });
  });

  it('a chain-mismatched head is caught even when every row verifies on its own', async () => {
    const sealed = await sealRow(input, null);
    const row = toEventRow(1, input, sealed);
    expect(await verifyChain([row], { head: 'f'.repeat(64) })).toEqual({
      ok: false,
      index: 0,
      reason: 'head',
    });
  });
});

describe('erasure', () => {
  it('an erased row (content_salt nulled, erasure_hash set) still verifies, and its content can no longer be checked', async () => {
    const sealed = await sealRow(input, null);
    const erasedAt = new Date('2026-09-23T00:00:00.000Z');
    const erasureHash = await computeErasureHash(sealed.row_hash, erasedAt);
    const erased: AuditEventRow = {
      ...toEventRow(1, input, sealed),
      actorDisplay: 'Erased person 7',
      before: { erased: true },
      after: { erased: true },
      erasedAt,
      contentSalt: null,
      erasureHash,
    };
    expect(await verifyChain([erased])).toEqual({ ok: true });
  });

  it('refuses a row claiming erasure with the wrong erasure_hash', async () => {
    const sealed = await sealRow(input, null);
    const erasedAt = new Date('2026-09-23T00:00:00.000Z');
    const erased: AuditEventRow = {
      ...toEventRow(1, input, sealed),
      erasedAt,
      contentSalt: null,
      erasureHash: 'f'.repeat(64),
    };
    expect(await verifyChain([erased])).toEqual({ ok: false, index: 0, reason: 'erasure' });
  });

  it('refuses content_salt nulled without erased_at/erasure_hash set, and the reverse', async () => {
    const sealed = await sealRow(input, null);
    const halfErased: AuditEventRow = { ...toEventRow(1, input, sealed), contentSalt: null };
    expect(await verifyChain([halfErased])).toEqual({ ok: false, index: 0, reason: 'erasure' });
    const erasedAt = new Date('2026-09-23T00:00:00.000Z');
    const erasureHash = await computeErasureHash(sealed.row_hash, erasedAt);
    const saltStillSet: AuditEventRow = {
      ...toEventRow(1, input, sealed),
      erasedAt,
      erasureHash,
    };
    expect(await verifyChain([saltStillSet])).toEqual({ ok: false, index: 0, reason: 'erasure' });
  });

  it('computeErasureHash is deterministic and binds both the row and the instant', async () => {
    const at = new Date('2026-09-23T00:00:00.000Z');
    const a = await computeErasureHash('a'.repeat(64), at);
    const b = await computeErasureHash('a'.repeat(64), at);
    const differentRow = await computeErasureHash('b'.repeat(64), at);
    const differentTime = await computeErasureHash(
      'a'.repeat(64),
      new Date('2026-09-23T00:00:01.000Z'),
    );
    expect(a).toBe(b);
    expect(a).not.toBe(differentRow);
    expect(a).not.toBe(differentTime);
  });
});
