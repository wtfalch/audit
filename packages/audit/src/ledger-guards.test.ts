import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createLedger } from './ledger.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { verifyTable } from './verify-table.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

let t: TestDb;
const ledger = createLedger({
  vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
  hashChain: true,
  checkRuntimeRole: false,
});
beforeAll(async () => {
  t = await testDb();
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  await t.exec('alter table audit_events disable trigger all');
  await t.exec('delete from audit_events');
  await t.exec('alter table audit_events enable trigger all');
});
afterEach(() => {
  vi.useRealTimers();
});

describe('sign() on the chain', () => {
  it('takes received_at from the database clock, not from the application', async () => {
    // PGlite reads the same JS clock, so only a real server can tell the two apart.
    if (!t.real) return;
    const before = Date.now();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2001-02-03T04:05:06.000Z'));
    await ledger.sign(t.db, {
      action: 'invoice.paid',
      tenantId: null,
      actor: { class: 'human', id: 'user_ada', display: 'Ada' },
      context: 'standard',
      target: { type: 'invoice', id: 'i_1' },
    });
    vi.useRealTimers();
    const [row] = await t.query('select received_at from audit_events');
    const receivedAt = (row?.received_at as Date).getTime();
    expect(Math.abs(receivedAt - before)).toBeLessThan(60_000);
    expect(await verifyTable(t.db)).toMatchObject({ ok: true, rows: 1 });
  });
});
