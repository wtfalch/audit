import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type Ledger, createLedger } from './ledger.js';
import type { Authorize } from './read.js';
import { ledgerReadHandler } from './read.js';
import { ALLOW_AUDIT_READ, DENY_AUDIT_READ } from './test/access.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';
const ada = { class: 'human', id: 'user_ada', display: 'Ada Lovelace' };

let t: TestDb;
let ledger: Ledger;

beforeAll(async () => {
  t = await testDb();
  const vocabulary = ledgerVocabularyFromCore(CORE, {});
  ledger = createLedger({ vocabulary, checkRuntimeRole: false });
});

beforeEach(async () => {
  await t.exec('alter table audit_events disable trigger all');
  await t.exec('delete from audit_events');
  await t.exec('alter table audit_events enable trigger all');
});

async function seed(n: number, tenantId = TENANT_A, opts: { tenantVisible?: boolean } = {}) {
  for (let i = 0; i < n; i++) {
    await ledger.sign(t.db, {
      action: 'membership.created',
      tenantId,
      actor: ada,
      context: 'standard',
      target: { type: 'membership', id: `m_${i}` },
      tenantVisible: opts.tenantVisible ?? true,
    });
  }
}

function authorizeAs(tenantId: string | null, access = ALLOW_AUDIT_READ): Authorize {
  return () => (tenantId ? { tenantId, access } : null);
}

function handlerFor(authorize: Authorize) {
  return ledgerReadHandler({
    ledger,
    handle: t.db,
    authorize,
    applicationId: 'audit-test',
    platformId: 'wtfalch',
    defaultLimit: 2,
  });
}

function req(query: string): Request {
  return new Request(`https://host.example/v1/audit${query}`);
}

describe('ledgerReadHandler', () => {
  it('answers unauthorized with no credential', async () => {
    const handler = handlerFor(authorizeAs(null));
    const res = await handler(req(`?tenant=${TENANT_A}`));
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.code).toBe('unauthorized');
  });

  it('answers invalid_request with no tenant parameter', async () => {
    const handler = handlerFor(authorizeAs(TENANT_A));
    const res = await handler(req(''));
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe('invalid_request');
  });

  it('answers forbidden when the credential is scoped to a different tenant', async () => {
    const handler = handlerFor(authorizeAs(TENANT_B));
    const res = await handler(req(`?tenant=${TENANT_A}`));
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.code).toBe('forbidden');
  });

  it('answers forbidden when the credential lacks audit:read', async () => {
    const handler = handlerFor(authorizeAs(TENANT_A, DENY_AUDIT_READ));
    const res = await handler(req(`?tenant=${TENANT_A}`));
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error.code).toBe('forbidden');
  });

  it('answers invalid_request on a malformed limit', async () => {
    const handler = handlerFor(authorizeAs(TENANT_A));
    const res = await handler(req(`?tenant=${TENANT_A}&limit=not-a-number`));
    expect(res.status).toBe(400);
  });

  it('answers conflict on a malformed cursor', async () => {
    const handler = handlerFor(authorizeAs(TENANT_A));
    const res = await handler(req(`?tenant=${TENANT_A}&cursor=not-a-real-cursor!!`));
    expect(res.status).toBe(409);
    const body = await res.json();
    expect(body.error.code).toBe('conflict');
  });

  it("returns only this tenant's tenantVisible rows, as the read DTO", async () => {
    await seed(1, TENANT_A);
    await seed(1, TENANT_A, { tenantVisible: false });
    await seed(1, TENANT_B);
    const handler = handlerFor(authorizeAs(TENANT_A));
    const res = await handler(req(`?tenant=${TENANT_A}&limit=10`));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.items).toHaveLength(1);
    const [row] = body.items;
    expect(row).toMatchObject({
      tenantId: TENANT_A,
      actorId: 'user_ada',
      actorDisplay: 'Ada Lovelace',
      action: 'membership.created',
    });
    expect(typeof row.occurredAt).toBe('string');
    expect(row).not.toHaveProperty('before');
    expect(row).not.toHaveProperty('rowHash');
    expect(row).not.toHaveProperty('ip');
  });

  it('pages with a cursor round-trip', async () => {
    await seed(3, TENANT_A);
    const handler = handlerFor(authorizeAs(TENANT_A));
    const first = await handler(req(`?tenant=${TENANT_A}`));
    const firstBody = await first.json();
    expect(firstBody.items).toHaveLength(2);
    expect(firstBody.nextCursor).not.toBeNull();

    const second = await handler(req(`?tenant=${TENANT_A}&cursor=${firstBody.nextCursor}`));
    const secondBody = await second.json();
    expect(secondBody.items).toHaveLength(1);
    expect(secondBody.nextCursor).toBeNull();

    const seen = new Set(
      [...firstBody.items, ...secondBody.items].map((r: { id: number }) => r.id),
    );
    expect(seen.size).toBe(3);
  });
});
