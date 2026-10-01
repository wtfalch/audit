import { afterEach, describe, expect, it } from 'vitest';
import { type Handle, createLedger } from './ledger.js';
import { UnsafeRuntimeRoleError, assertRuntimeRole } from './runtime-role-guard.js';
import { CORE, type RuntimeRoleDb, withRuntimeRole } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

/**
 * Real Postgres only: PGlite has one role, so there is no "wrong role" to
 * catch. Each case logs in as the role under test; no `set role`.
 */
const url = process.env.TEST_DATABASE_URL;

let t: RuntimeRoleDb | undefined;
afterEach(async () => {
  await t?.close();
  t = undefined;
});

const count = async (db: RuntimeRoleDb) =>
  Number(
    (await db.owner.database.query('select count(*)::int as count from audit_events'))[0]?.count,
  );

describe.skipIf(!url)('assertRuntimeRole', () => {
  it('throws for the table owner', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    await expect(assertRuntimeRole(t.ownerDb)).rejects.toThrow(UnsafeRuntimeRoleError);
  });

  it('throws for a runtime role ensureRuntimeRole made without appendOnly', async () => {
    if (!url) return;
    t = await withRuntimeRole(url, { appendOnly: [] });
    await expect(assertRuntimeRole(t.runtimeDb)).rejects.toThrow(UnsafeRuntimeRoleError);
  });

  // One privilege at a time: a guard that ignores any single verb must fail here.
  it.each(['delete', 'truncate'])('throws for a role holding only %s', async (verb) => {
    if (!url) return;
    t = await withRuntimeRole(url);
    // appendOnly revoked UPDATE, DELETE and TRUNCATE; give back exactly one.
    await t.owner.database.query(`grant ${verb} on audit_events to "${t.role}"`);
    await expect(assertRuntimeRole(t.runtimeDb)).rejects.toThrow(UnsafeRuntimeRoleError);
  });

  it('resolves for the role ensureRuntimeRole made with appendOnly: audit_events', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    await expect(assertRuntimeRole(t.runtimeDb)).resolves.toBeUndefined();
  });
});

describe.skipIf(!url)("createLedger's own check (LedgerOptions.checkRuntimeRole)", () => {
  const vocabulary = ledgerVocabularyFromCore(CORE);
  const ada = { class: 'human', id: 'user_ada', display: 'Ada' };
  const event = {
    action: 'membership.created',
    tenantId: null,
    actor: ada,
    context: 'standard',
    target: { type: 'membership', id: 'm_1' },
  } as const;

  it('throws instead of writing, on for the table owner', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    const ledger = createLedger({ vocabulary });
    await expect(ledger.sign(t.ownerDb, event)).rejects.toThrow(UnsafeRuntimeRoleError);
    expect(await count(t)).toBe(0);
  });

  it('writes normally for the role ensureRuntimeRole made with appendOnly: audit_events', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    const ledger = createLedger({ vocabulary });
    await expect(ledger.sign(t.runtimeDb, event)).resolves.toBeUndefined();
    // A second call on the same handle reuses the first check rather than
    // repeating it -- this would time out on a role the check itself
    // never resolves for, so a passing second write here also stands in
    // for that.
    await expect(ledger.sign(t.runtimeDb, event)).resolves.toBeUndefined();
    expect(await count(t)).toBe(2);
  });

  it('writes for the table owner when checkRuntimeRole is false', async () => {
    if (!url) return;
    t = await withRuntimeRole(url);
    const ledger = createLedger({ vocabulary, checkRuntimeRole: false });
    const db: Handle = t.ownerDb;
    await expect(ledger.sign(db, event)).resolves.toBeUndefined();
    expect(await count(t)).toBe(1);
  });
});
