import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { verifyChain } from './chain.js';
import { createLedger } from './ledger.js';
import { type TestDb, testDb } from './test/db.js';
import { ledgerVocabulary } from './vocabulary.js';

/**
 * A service with no tenant database and no `@wtfalch/authz` core: foundry's
 * plan/apply trail (#6). Its own closed vocabulary through
 * `ledgerVocabulary`, every row `tenantId: null`, the org the plan is for as
 * the target, and one Postgres of its own. Nothing here is per-app.
 */
let t: TestDb;
const vocabulary = ledgerVocabulary({
  events: {
    'plan.computed': { tenantVisible: false },
    'plan.applied': { tenantVisible: false },
  },
  actorClasses: ['human', 'service'],
  contexts: ['operator'],
  outcomes: ['success', 'refused', 'failed'],
});
const ledger = createLedger({ vocabulary, hashChain: true });
const william = { class: 'human', id: 'william', display: 'William' };

beforeAll(async () => {
  t = await testDb();
});
afterAll(async () => {
  await t.close();
});

describe('a ledger for a service with no tenant database', () => {
  it('records plan and apply rows with no tenant, and reads them back in a chain', async () => {
    const plan = { steps: 3, digest: 'abc' };
    await ledger.sign(t.db, {
      action: 'plan.computed',
      tenantId: null,
      actor: william,
      context: 'operator',
      target: { type: 'org', id: 'org_acme', display: 'Acme' },
      after: plan,
    });
    await ledger.sign(t.db, {
      action: 'plan.applied',
      tenantId: null,
      actor: william,
      context: 'operator',
      outcome: 'refused',
      reason: 'drift since the plan was computed',
      target: { type: 'org', id: 'org_acme', display: 'Acme' },
      after: plan,
    });

    const { items } = await ledger.page(t.db, { tenantId: null, actionPrefix: 'plan.' });
    expect(items.map((r) => [r.action, r.outcome])).toEqual([
      ['plan.applied', 'refused'],
      ['plan.computed', 'success'],
    ]);
    expect(items.every((r) => r.tenantId === null && r.targetId === 'org_acme')).toBe(true);
    expect(await verifyChain(items)).toEqual({ ok: true });
  });

  it('still holds the service to its own closed sets', async () => {
    await expect(
      ledger.sign(t.db, {
        action: 'membership.created',
        tenantId: null,
        actor: william,
        context: 'operator',
        target: { type: 'org', id: 'org_acme' },
      }),
    ).rejects.toThrow();
  });
});
