import { describe, expect, it } from 'vitest';
import { type SealInput, computeErasureHash, sealRow, sealRowV2, verifyChain } from './chain.js';
import type { AuditEventRow } from './tables.js';

/** Guards of verifyChain the main chain tests leave to other checks. */
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
const T0 = new Date('2026-09-22T12:00:01.000Z');

function rowOf(
  id: number,
  sealed: Awaited<ReturnType<typeof sealRow>> & Partial<Awaited<ReturnType<typeof sealRowV2>>>,
): AuditEventRow {
  return {
    id,
    occurredAt: new Date(input.occurred_at),
    tenantId: null,
    tenantDisplay: null,
    actorClass: input.actor_class,
    actorId: input.actor_id,
    actorDisplay: input.actor_display,
    action: input.action,
    targetType: input.target_type,
    targetId: input.target_id,
    targetDisplay: null,
    outcome: input.outcome,
    context: input.context,
    sessionId: null,
    reason: null,
    reference: null,
    requestId: null,
    ip: null,
    userAgent: null,
    tenantVisible: true,
    before: null,
    after: input.after,
    erasedAt: null,
    schemaVersion: 1,
    subjectClass: null,
    subjectId: null,
    prevHash: sealed.prev_hash,
    rowHash: sealed.row_hash,
    contentHash: sealed.content_hash,
    contentSalt: sealed.content_salt,
    erasureHash: null,
    chainVersion: sealed.chain_version ?? null,
    seq: sealed.seq ?? null,
    receivedAt: sealed.received_at ?? null,
  } as AuditEventRow;
}

describe('verifyChain guards', () => {
  it('a format 1 row after a window that began at a format 2 seq is a seq failure', async () => {
    const v1 = rowOf(1, await sealRow(input, null));
    expect(await verifyChain([v1], { seqOrigin: 5 })).toEqual({
      ok: false,
      index: 0,
      reason: 'seq',
    });
  });

  it('an erased row with no erased_at fails as erasure and does not throw', async () => {
    const sealed = await sealRow(input, null);
    const erased = {
      ...rowOf(1, sealed),
      contentSalt: null,
      erasedAt: null,
      erasureHash: await computeErasureHash(sealed.row_hash, new Date('2026-09-23T00:00:00.000Z')),
    } as AuditEventRow;
    expect(await verifyChain([erased])).toEqual({ ok: false, index: 0, reason: 'erasure' });
  });

  it('takes rows in any order and reports the position in id order', async () => {
    const s1 = await sealRowV2(input, null, 1, T0);
    const s2 = await sealRowV2(input, s1.row_hash, 2, T0);
    const s3 = await sealRowV2(input, s2.row_hash, 4, T0); // a gap after row 2
    const rows = [rowOf(3, s3), rowOf(1, s1), rowOf(2, s2)];
    expect(await verifyChain([rows[1] as AuditEventRow, rows[2] as AuditEventRow])).toEqual({
      ok: true,
    });
    expect(await verifyChain(rows)).toEqual({ ok: false, index: 2, reason: 'seq' });
  });
});
