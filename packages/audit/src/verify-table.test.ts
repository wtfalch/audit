import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type Ledger, createLedger } from './ledger.js';
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
});
