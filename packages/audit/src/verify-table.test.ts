import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { sealRow, sealRowV2 } from './chain.js';
import { type Ledger, createLedger } from './ledger.js';
import { auditEvents } from './tables.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { verifyTable } from './verify-table.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';
const ada = { class: 'human', id: 'user_ada', display: 'Ada Lovelace' };

let t: TestDb;
let chained: Ledger;
let plain: Ledger;

beforeAll(async () => {
  t = await testDb();
  const vocabulary = ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } });
  chained = createLedger({ vocabulary, hashChain: true, checkRuntimeRole: false });
  plain = createLedger({ vocabulary, checkRuntimeRole: false });
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  await t.exec('alter table audit_events disable trigger all');
  await t.exec('delete from audit_events');
  await t.exec('alter table audit_events enable trigger all');
});

async function sign(ledger: Ledger, n: number) {
  for (let i = 0; i < n; i++) {
    await ledger.sign(t.db, {
      action: 'invoice.paid',
      tenantId: i % 2 === 0 ? TENANT_A : TENANT_B,
      actor: ada,
      context: 'standard',
      target: { type: 'invoice', id: `i_${i}` },
    });
  }
}

describe('verifyTable', () => {
  it('passes an intact chain across tenants and pages, and returns the head', async () => {
    await sign(chained, 7);
    const result = await verifyTable(t.db, { pageSize: 3 });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.rows).toBe(7);
    const [tail] = await t.query('select row_hash from audit_events order by id desc limit 1');
    expect(result.head).toBe(tail?.row_hash);
    expect(await verifyTable(t.db, { pageSize: 3, head: result.head ?? '' })).toMatchObject({
      ok: true,
    });
  });

  it('names the row id of an edit, including one past the first page', async () => {
    await sign(chained, 7);
    const [victim] = await t.query('select id from audit_events order by id offset 4 limit 1');
    await t.exec('alter table audit_events disable trigger all');
    await t.exec(`update audit_events set action = 'invoice.refunded' where id = ${victim?.id}`);
    await t.exec('alter table audit_events enable trigger all');
    expect(await verifyTable(t.db, { pageSize: 3 })).toEqual({
      ok: false,
      id: Number(victim?.id),
      reason: 'row_hash',
    });
  });

  it('catches a row deleted from the middle of a page boundary', async () => {
    await sign(chained, 7);
    const [victim] = await t.query('select id from audit_events order by id offset 3 limit 1');
    await t.exec('alter table audit_events disable trigger all');
    await t.exec(`delete from audit_events where id = ${victim?.id}`);
    await t.exec('alter table audit_events enable trigger all');
    const result = await verifyTable(t.db, { pageSize: 3 });
    expect(result).toMatchObject({ ok: false, reason: 'link' });
  });

  it('catches the earliest rows deleted, unless afterId makes the start a window', async () => {
    await sign(chained, 4);
    await t.exec('alter table audit_events disable trigger all');
    await t.exec('delete from audit_events where id = (select min(id) from audit_events)');
    await t.exec('alter table audit_events enable trigger all');
    expect(await verifyTable(t.db)).toMatchObject({ ok: false, reason: 'link' });
    const [first] = await t.query('select id from audit_events order by id limit 1');
    expect(await verifyTable(t.db, { afterId: Number(first?.id) })).toMatchObject({ ok: true });
  });

  it('catches rows cut off the end only when a head is given', async () => {
    await sign(chained, 4);
    const first = await verifyTable(t.db);
    if (!first.ok) throw new Error('setup');
    await t.exec('alter table audit_events disable trigger all');
    await t.exec('delete from audit_events where id = (select max(id) from audit_events)');
    await t.exec('alter table audit_events enable trigger all');
    expect(await verifyTable(t.db)).toMatchObject({ ok: true, rows: 3 });
    expect(await verifyTable(t.db, { head: first.head ?? '' })).toMatchObject({
      ok: false,
      reason: 'head',
    });
  });

  it('reports rows from before hashChain as unsealed, and afterId skips them', async () => {
    await sign(plain, 2);
    await sign(chained, 3);
    const [boundary] = await t.query('select id from audit_events order by id offset 1 limit 1');
    expect(await verifyTable(t.db)).toMatchObject({ ok: false, reason: 'unsealed' });
    expect(await verifyTable(t.db, { afterId: Number(boundary?.id) })).toMatchObject({
      ok: true,
      rows: 3,
    });
  });

  it('passes an empty table', async () => {
    expect(await verifyTable(t.db)).toEqual({ ok: true, rows: 0, head: null });
  });

  /** Insert a v1 row the way the old `sign()` did: sealed by `sealRow` onto the tail, written directly as the owner. */
  async function insertV1(n: number) {
    for (let i = 0; i < n; i++) {
      const [tail] = await t.query('select row_hash from audit_events order by id desc limit 1');
      const occurredAt = new Date(Date.UTC(2026, 8, 1, 0, 0, i));
      const sealInput = {
        occurred_at: occurredAt,
        tenant_id: TENANT_A,
        tenant_display: null,
        actor_class: ada.class,
        actor_id: ada.id,
        actor_display: ada.display,
        action: 'invoice.paid',
        target_type: 'invoice',
        target_id: `old_${i}`,
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
        after: { n: i },
        schema_version: 1,
        subject_class: null,
        subject_id: null,
      };
      const sealed = await sealRow(sealInput, (tail?.row_hash as string | null) ?? null);
      await t.db.insert(auditEvents).values({
        occurredAt,
        tenantId: TENANT_A,
        actorClass: ada.class,
        actorId: ada.id,
        actorDisplay: ada.display,
        action: 'invoice.paid',
        targetType: 'invoice',
        targetId: `old_${i}`,
        outcome: 'success',
        context: 'standard',
        tenantVisible: true,
        after: { n: i },
        schemaVersion: 1,
        prevHash: sealed.prev_hash,
        rowHash: sealed.row_hash,
        contentHash: sealed.content_hash,
        contentSalt: sealed.content_salt,
      });
    }
  }

  async function unguarded(statement: string) {
    await t.exec('alter table audit_events disable trigger all');
    await t.exec(statement);
    await t.exec('alter table audit_events enable trigger all');
  }

  it('passes v1 rows then v2 rows, linked across the boundary and across pages', async () => {
    await insertV1(3);
    await sign(chained, 4);
    const rows = await t.query(
      'select chain_version, seq, prev_hash from audit_events order by id',
    );
    expect(rows.map((r) => (r.seq === null ? null : Number(r.seq)))).toEqual([
      null,
      null,
      null,
      1,
      2,
      3,
      4,
    ]);
    const [lastV1] = await t.query(
      'select row_hash from audit_events where seq is null order by id desc limit 1',
    );
    expect(rows[3]?.prev_hash).toBe(lastV1?.row_hash);
    for (const pageSize of [2, 3, 100]) {
      expect(await verifyTable(t.db, { pageSize })).toMatchObject({ ok: true, rows: 7 });
    }
  });

  it('fails an edited received_at and an edited seq, by the row id', async () => {
    await insertV1(1);
    await sign(chained, 3);
    const [victim] = await t.query('select id from audit_events order by id offset 2 limit 1');
    await unguarded(
      `update audit_events set received_at = received_at + interval '1 millisecond' where id = ${victim?.id}`,
    );
    expect(await verifyTable(t.db, { pageSize: 2 })).toEqual({
      ok: false,
      id: Number(victim?.id),
      reason: 'row_hash',
    });
    await unguarded(
      `update audit_events set received_at = received_at - interval '1 millisecond' where id = ${victim?.id}`,
    );
    expect(await verifyTable(t.db)).toMatchObject({ ok: true });
    await unguarded(`update audit_events set seq = 50 where id = ${victim?.id}`);
    expect(await verifyTable(t.db)).toEqual({
      ok: false,
      id: Number(victim?.id),
      reason: 'row_hash',
    });
  });

  it('fails swapped seq values', async () => {
    await sign(chained, 3);
    // The unique index is not deferrable, so the swap goes through a spare value.
    for (const [from, to] of [
      [2, 99],
      [3, 2],
      [99, 3],
    ]) {
      await unguarded(`update audit_events set seq = ${to} where seq = ${from}`);
    }
    expect(await verifyTable(t.db)).toMatchObject({ ok: false, reason: 'row_hash' });
  });

  it('fails a row deleted from a format 2 run', async () => {
    await sign(chained, 4);
    await unguarded('delete from audit_events where seq = 2');
    expect(await verifyTable(t.db)).toMatchObject({ ok: false, reason: 'link' });
  });

  it('fails a validly sealed row whose seq skips, as seq, across a page boundary', async () => {
    await sign(chained, 2);
    const [tail] = await t.query('select row_hash from audit_events order by id desc limit 1');
    const base = {
      occurred_at: new Date('2026-10-01T00:00:00.000Z'),
      tenant_id: null,
      tenant_display: null,
      actor_class: ada.class,
      actor_id: ada.id,
      actor_display: ada.display,
      action: 'invoice.paid',
      target_type: 'invoice',
      target_id: 'skip',
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
      after: null,
      schema_version: 1,
      subject_class: null,
      subject_id: null,
    };
    const receivedAt = new Date('2026-10-01T00:00:01.000Z');
    const sealed = await sealRowV2(base, tail?.row_hash as string, 4, receivedAt);
    await t.db.insert(auditEvents).values({
      occurredAt: base.occurred_at,
      actorClass: base.actor_class,
      actorId: base.actor_id,
      actorDisplay: base.actor_display,
      action: base.action,
      targetType: base.target_type,
      targetId: base.target_id,
      outcome: base.outcome,
      context: base.context,
      tenantVisible: true,
      schemaVersion: 1,
      chainVersion: 2,
      seq: 4,
      receivedAt,
      prevHash: sealed.prev_hash,
      rowHash: sealed.row_hash,
      contentHash: sealed.content_hash,
      contentSalt: sealed.content_salt,
    });
    const [last] = await t.query('select id from audit_events order by id desc limit 1');
    for (const pageSize of [1, 2, 100]) {
      expect(await verifyTable(t.db, { pageSize })).toEqual({
        ok: false,
        id: Number(last?.id),
        reason: 'seq',
      });
    }
  });

  it('fails a first format 2 row that does not start at seq 1', async () => {
    const base = {
      occurred_at: new Date('2026-10-01T00:00:00.000Z'),
      tenant_id: null,
      tenant_display: null,
      actor_class: ada.class,
      actor_id: ada.id,
      actor_display: ada.display,
      action: 'invoice.paid',
      target_type: 'invoice',
      target_id: 'skip',
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
      after: null,
      schema_version: 1,
      subject_class: null,
      subject_id: null,
    };
    const receivedAt = new Date('2026-10-01T00:00:01.000Z');
    const sealed = await sealRowV2(base, null, 5, receivedAt);
    await t.db.insert(auditEvents).values({
      occurredAt: base.occurred_at,
      actorClass: base.actor_class,
      actorId: base.actor_id,
      actorDisplay: base.actor_display,
      action: base.action,
      targetType: base.target_type,
      targetId: base.target_id,
      outcome: base.outcome,
      context: base.context,
      tenantVisible: true,
      schemaVersion: 1,
      chainVersion: 2,
      seq: 5,
      receivedAt,
      prevHash: sealed.prev_hash,
      rowHash: sealed.row_hash,
      contentHash: sealed.content_hash,
      contentSalt: sealed.content_salt,
    });
    const [only] = await t.query('select id from audit_events');
    expect(await verifyTable(t.db)).toEqual({ ok: false, id: Number(only?.id), reason: 'seq' });
    // A window that starts after earlier rows is not held to seq 1.
    expect(await verifyTable(t.db, { afterId: 0 })).toMatchObject({ ok: true, rows: 1 });
  });
});
