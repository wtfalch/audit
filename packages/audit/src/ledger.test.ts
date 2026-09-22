import { pgTable, uuid } from 'drizzle-orm/pg-core';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { type Ledger, createLedger } from './ledger.js';
import { AUDIT_COLUMNS, auditIndexes } from './tables.js';
import { CORE, type TestDb, testDb } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';
const ada = { class: 'human', id: 'user_ada', display: 'Ada Lovelace' };
const ops = { class: 'human', id: 'op_1', display: 'Ops' };

let t: TestDb;
let ledger: Ledger;

beforeAll(async () => {
  t = await testDb();
  ledger = createLedger({
    vocabulary: ledgerVocabularyFromCore(CORE, { 'invoice.paid': { tenantVisible: true } }),
  });
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  // Owner-side reset between tests. The guard refuses DELETE and TRUNCATE, so
  // the only way to empty the table is to drop the guard, which is itself the
  // point: nothing short of DDL gets a row out.
  await t.exec('alter table audit_events disable trigger all');
  await t.exec('delete from audit_events');
  await t.exec('alter table audit_events enable trigger all');
});

describe('sign', () => {
  it('writes a row with the vocabulary defaults filled in', async () => {
    await ledger.sign(t.db, {
      action: 'membership.created',
      tenantId: TENANT_A,
      actor: ada,
      context: 'standard',
      target: { type: 'membership', id: 'm_1' },
      subject: { class: 'human', id: 'user_bob' },
      after: { role: 'member' },
      request: { id: 'abc123', ip: '10.0.0.1', userAgent: 'test' },
    });
    const [row] = await t.query('select * from audit_events');
    expect(row).toMatchObject({
      tenant_id: TENANT_A,
      actor_class: 'human',
      actor_id: 'user_ada',
      actor_display: 'Ada Lovelace',
      action: 'membership.created',
      outcome: 'success',
      context: 'standard',
      tenant_visible: true,
      after: { role: 'member' },
      before: null,
      subject_class: 'human',
      subject_id: 'user_bob',
      request_id: 'abc123',
      schema_version: 1,
      erased_at: null,
      target_display: null,
      tenant_display: null,
    });
  });

  it('writes what the target and the tenant were called, and keeps null when told nothing', async () => {
    await ledger.sign(t.db, {
      action: 'membership.created',
      tenantId: TENANT_A,
      tenantDisplay: 'Northwind',
      actor: ada,
      context: 'standard',
      target: { type: 'membership', id: 'm_1', display: 'Bob Brown' },
    });
    await ledger.sign(t.db, {
      action: 'membership.created',
      tenantId: TENANT_A,
      actor: ada,
      context: 'standard',
      target: { type: 'membership', id: 'm_2' },
    });
    const rows = await t.query(
      'select target_display, tenant_display from audit_events order by id',
    );
    expect(rows).toEqual([
      { target_display: 'Bob Brown', tenant_display: 'Northwind' },
      { target_display: null, tenant_display: null },
    ]);
  });

  it('refuses a name longer than the column allows', async () => {
    await expect(
      ledger.sign(t.db, {
        action: 'membership.created',
        tenantId: TENANT_A,
        actor: ada,
        context: 'standard',
        target: { type: 'membership', id: 'm_3', display: 'x'.repeat(257) },
      }),
    ).rejects.toThrow();
  });

  it('follows the vocabulary for tenant visibility and lets a row override it', async () => {
    await ledger.sign(t.db, {
      action: 'tenant.created',
      tenantId: TENANT_A,
      actor: ops,
      context: 'operator',
      target: { type: 'tenant', id: TENANT_A },
    });
    await ledger.sign(t.db, {
      action: 'tenant.created',
      tenantId: TENANT_B,
      actor: ops,
      context: 'operator',
      target: { type: 'tenant', id: TENANT_B },
      tenantVisible: true,
    });
    const rows = await t.query('select tenant_id, tenant_visible from audit_events order by id');
    expect(rows).toEqual([
      { tenant_id: TENANT_A, tenant_visible: false },
      { tenant_id: TENANT_B, tenant_visible: true },
    ]);
  });

  it('refuses an event the vocabulary does not declare, before touching the database', async () => {
    await expect(
      ledger.sign(t.db, {
        action: 'invoice.refunded',
        tenantId: TENANT_A,
        actor: ada,
        context: 'standard',
        target: { type: 'invoice', id: 'i_1' },
      }),
    ).rejects.toThrow(/not an event this ledger's vocabulary declares/);
    expect(await t.query('select count(*)::int as n from audit_events')).toEqual([{ n: 0 }]);
  });

  it('refuses a break-glass row without its session, reason code and reference', async () => {
    await expect(
      ledger.sign(t.db, {
        action: 'break_glass.started',
        tenantId: TENANT_A,
        actor: ops,
        context: 'break_glass',
        target: { type: 'tenant', id: TENANT_A },
        reason: 'incident',
      }),
    ).rejects.toThrow(/session_id is required/);
    await ledger.sign(t.db, {
      action: 'break_glass.started',
      tenantId: TENANT_A,
      actor: ops,
      context: 'break_glass',
      target: { type: 'tenant', id: TENANT_A },
      sessionId: 'bg_1',
      reason: 'incident',
      reference: 'INC-42',
    });
    expect(await t.query('select count(*)::int as n from audit_events')).toEqual([{ n: 1 }]);
  });

  it('commits with the change it records, or not at all', async () => {
    await expect(
      t.db.transaction(async (tx) => {
        await ledger.sign(tx, {
          action: 'invoice.paid',
          tenantId: TENANT_A,
          actor: ada,
          context: 'standard',
          target: { type: 'invoice', id: 'i_1' },
        });
        throw new Error('the change failed');
      }),
    ).rejects.toThrow('the change failed');
    expect(await t.query('select count(*)::int as n from audit_events')).toEqual([{ n: 0 }]);
  });
});

describe('the walls', () => {
  beforeEach(async () => {
    await ledger.sign(t.db, {
      action: 'invoice.paid',
      tenantId: TENANT_A,
      actor: ada,
      context: 'standard',
      target: { type: 'invoice', id: 'i_1' },
      after: { amount: 100 },
    });
  });

  it('refuses delete and truncate, even from the owner', async () => {
    await expect(t.exec('delete from audit_events')).rejects.toThrow(/append-only: delete refused/);
    await expect(t.exec('truncate audit_events')).rejects.toThrow(/append-only: truncate refused/);
  });

  it('refuses an update to anything erasure does not touch', async () => {
    await expect(t.exec("update audit_events set action = 'invoice.refunded'")).rejects.toThrow(
      /only actor_display, target_display, before, after and erased_at may change/,
    );
    await expect(t.exec("update audit_events set actor_id = 'someone_else'")).rejects.toThrow(
      /append-only/,
    );
    await expect(t.exec('update audit_events set tenant_visible = false')).rejects.toThrow(
      /append-only/,
    );
    // The tenant's name is not a person's, so erasure never rewrites it and
    // nothing else may either -- a "correction" is a new row, not an edit.
    await expect(t.exec("update audit_events set tenant_display = 'Renamed'")).rejects.toThrow(
      /append-only/,
    );
    await t.exec("update audit_events set actor_display = 'Erased'");
    await t.exec("update audit_events set target_display = 'Erased'");
  });

  it('checks the shape of every row in the database too', async () => {
    const insert = (over: string) =>
      t.exec(
        `insert into audit_events (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible ${over}`,
      );
    await expect(
      insert(") values ('human','a','A','NotAnEvent','t','1','success','standard',true)"),
    ).rejects.toThrow(/action_shape_check/);
    await expect(
      insert(") values ('human','a','A','x.y','t','1','success','break_glass',true)"),
    ).rejects.toThrow(/break_glass_shape_check/);
    await expect(
      insert(", subject_id) values ('human','a','A','x.y','t','1','success','standard',true,'s')"),
    ).rejects.toThrow(/subject_pair_check/);
    await expect(
      insert(
        `, before) values ('human','a','A','x.y','t','1','success','standard',true, ('{"k":"' || repeat('x', 70000) || '"}')::jsonb)`,
      ),
    ).rejects.toThrow(/before_check/);
  });
});

describe('page', () => {
  beforeEach(async () => {
    const base = new Date('2026-09-11T10:00:00Z').getTime();
    for (let i = 0; i < 7; i++) {
      await ledger.sign(t.db, {
        action: i % 2 === 0 ? 'invoice.paid' : 'tenant.created',
        tenantId: i === 6 ? TENANT_B : TENANT_A,
        actor: i === 3 ? ops : ada,
        context: 'standard',
        target: { type: 'invoice', id: `i_${i}` },
        occurredAt: new Date(base + i * 1000),
        request: { id: i < 2 ? 'req_shared' : null },
        subject: i === 5 ? { class: 'human', id: 'user_bob' } : null,
      });
    }
  });

  it('pages newest first on (occurred_at, id) with no row lost or repeated', async () => {
    const first = await ledger.page(t.db, { limit: 3 });
    expect(first.items.map((r) => r.targetId)).toEqual(['i_6', 'i_5', 'i_4']);
    expect(first.next).not.toBeNull();
    const second = await ledger.page(t.db, { limit: 3, after: first.next ?? undefined });
    expect(second.items.map((r) => r.targetId)).toEqual(['i_3', 'i_2', 'i_1']);
    const third = await ledger.page(t.db, { limit: 3, after: second.next ?? undefined });
    expect(third.items.map((r) => r.targetId)).toEqual(['i_0']);
    expect(third.next).toBeNull();
  });

  it('breaks a tie on occurred_at by id', async () => {
    const same = new Date('2026-09-11T12:00:00Z');
    for (const id of ['tie_a', 'tie_b', 'tie_c']) {
      await ledger.sign(t.db, {
        action: 'invoice.paid',
        tenantId: TENANT_A,
        actor: ada,
        context: 'standard',
        target: { type: 'invoice', id },
        occurredAt: same,
      });
    }
    const first = await ledger.page(t.db, { limit: 2 });
    expect(first.items.map((r) => r.targetId)).toEqual(['tie_c', 'tie_b']);
    const second = await ledger.page(t.db, { limit: 2, after: first.next ?? undefined });
    expect(second.items[0]?.targetId).toBe('tie_a');
  });

  it('filters by tenant, visibility, actor, subject, action and request', async () => {
    expect((await ledger.page(t.db, { tenantId: TENANT_B })).items).toHaveLength(1);
    expect((await ledger.page(t.db, { tenantId: TENANT_A })).items).toHaveLength(6);
    // tenant.created is not tenant-visible in the core.
    expect(
      (await ledger.page(t.db, { tenantId: TENANT_A, tenantVisibleOnly: true })).items,
    ).toHaveLength(3);
    expect((await ledger.page(t.db, { actorId: 'op_1' })).items.map((r) => r.targetId)).toEqual([
      'i_3',
    ]);
    expect(
      (await ledger.page(t.db, { subjectId: 'user_bob' })).items.map((r) => r.targetId),
    ).toEqual(['i_5']);
    expect((await ledger.page(t.db, { action: 'tenant.created' })).items).toHaveLength(3);
    expect((await ledger.page(t.db, { requestId: 'req_shared' })).items).toHaveLength(2);
    expect((await ledger.page(t.db, { tenantId: null })).items).toHaveLength(0);
  });

  it('filters by action prefix and an occurred_at range', async () => {
    const base = new Date('2026-09-11T10:00:00Z').getTime();
    expect(
      (await ledger.page(t.db, { actionPrefix: 'invoice.' })).items.map((r) => r.targetId),
    ).toEqual(['i_6', 'i_4', 'i_2', 'i_0']);
    expect((await ledger.page(t.db, { actionPrefix: 'tenant.' })).items).toHaveLength(3);
    // occurredFrom and occurredTo are both inclusive; i_2..i_4 fall between them.
    expect(
      (
        await ledger.page(t.db, {
          occurredFrom: new Date(base + 2000),
          occurredTo: new Date(base + 4000),
        })
      ).items.map((r) => r.targetId),
    ).toEqual(['i_4', 'i_3', 'i_2']);
    // Combined: only the range's invoice.paid rows.
    expect(
      (
        await ledger.page(t.db, {
          actionPrefix: 'invoice.',
          occurredFrom: new Date(base + 2000),
          occurredTo: new Date(base + 4000),
        })
      ).items.map((r) => r.targetId),
    ).toEqual(['i_4', 'i_2']);
  });

  it('escapes % and _ in actionPrefix so they match themselves, not any character', async () => {
    // A raw insert, not ledger.sign(): CORE's vocabulary has no pair of real
    // event names that differ only at an underscore, so proving the escape
    // holds at the SQL layer needs actions outside the closed set.
    await t.exec(
      'insert into audit_events (actor_class, actor_id, actor_display, action, target_type, target_id, outcome, context, tenant_visible) values ' +
        "('human','u1','U','x.a_b','t','esc_literal','success','standard',true)," +
        "('human','u1','U','x.axb','t','esc_wildcard','success','standard',true)",
    );
    // Unescaped, '_' in the pattern would match any single character, so
    // 'x.a_b%' would also match 'x.axb'. It must not.
    const matched = await ledger.page(t.db, { actionPrefix: 'x.a_b' });
    expect(matched.items.map((r) => r.targetId)).toEqual(['esc_literal']);
  });

  it('clamps the page size', async () => {
    expect((await ledger.page(t.db, { limit: 0 })).items).toHaveLength(1);
    expect((await ledger.page(t.db, { limit: 10_000 })).items).toHaveLength(7);
  });
});

describe('erase', () => {
  beforeEach(async () => {
    await ledger.sign(t.db, {
      action: 'invoice.paid',
      tenantId: TENANT_A,
      actor: ada,
      context: 'standard',
      target: { type: 'invoice', id: 'own' },
      after: { by: 'ada' },
    });
    await ledger.sign(t.db, {
      action: 'membership.created',
      tenantId: TENANT_A,
      actor: ops,
      context: 'operator',
      target: { type: 'membership', id: 'about' },
      subject: { class: 'human', id: 'user_ada' },
      before: { email: 'Ada@Example.com' },
    });
    await ledger.sign(t.db, {
      action: 'invitation.sent',
      tenantId: TENANT_A,
      actor: ops,
      context: 'operator',
      target: { type: 'invitation', id: 'mentions' },
      after: { to: 'ada@example.com' },
    });
    await ledger.sign(t.db, {
      action: 'invoice.paid',
      tenantId: TENANT_A,
      actor: ops,
      context: 'operator',
      target: { type: 'invoice', id: 'unrelated' },
      after: { by: 'ops' },
    });
  });

  it("pseudonymises the target's name when the target is the person erased", async () => {
    await ledger.sign(t.db, {
      action: 'membership.created',
      tenantId: TENANT_A,
      actor: ops,
      context: 'operator',
      target: { type: 'human', id: 'user_ada', display: 'Ada Lovelace' },
      subject: { class: 'human', id: 'user_ada' },
    });
    await t.db.transaction((tx) =>
      ledger.erase(tx, { subject: 'user_ada', pseudonym: 'Erased person 7' }),
    );
    const rows = await t.query(
      "select target_display from audit_events where target_id = 'user_ada'",
    );
    expect(rows).toEqual([{ target_display: 'Erased person 7' }]);
  });

  it("pseudonymises the person's rows, rows about them and rows naming them; keeps the count", async () => {
    const touched = await t.db.transaction((tx) =>
      ledger.erase(tx, {
        subject: 'user_ada',
        pseudonym: 'Erased person 7',
        email: 'ada@example.com',
      }),
    );
    expect(touched).toBe(3);
    const rows = await t.query(
      'select target_id, actor_id, actor_display, before, after, erased_at is not null as erased from audit_events order by id',
    );
    expect(rows).toEqual([
      {
        target_id: 'own',
        actor_id: 'user_ada',
        actor_display: 'Erased person 7',
        before: null,
        after: { erased: true },
        erased: true,
      },
      {
        target_id: 'about',
        actor_id: 'op_1',
        actor_display: 'Ops',
        before: { erased: true },
        after: null,
        erased: true,
      },
      {
        target_id: 'mentions',
        actor_id: 'op_1',
        actor_display: 'Ops',
        before: null,
        after: { erased: true },
        erased: true,
      },
      {
        target_id: 'unrelated',
        actor_id: 'op_1',
        actor_display: 'Ops',
        before: null,
        after: { by: 'ops' },
        erased: false,
      },
    ]);
    // A second pass finds nothing left to do.
    expect(await ledger.erase(t.db, { subject: 'user_ada', pseudonym: 'x' })).toBe(0);
  });

  it('matches a payload email regardless of case on either side', async () => {
    // 0002_display.sql's audit_erase_person also dropped the lower() fold, so
    // a differently-cased email survived erasure. "about" and "mentions" match
    // only by their payload email ('Ada@Example.com' / 'ada@example.com');
    // neither row's actor_id or subject_id is "nobody". Looking the email up
    // with yet another case on both sides must still find both.
    const touched = await ledger.erase(t.db, {
      subject: 'nobody',
      pseudonym: 'Erased person 7',
      email: 'ADA@Example.COM',
    });
    expect(touched).toBe(2);
    const rows = await t.query(
      "select target_id, erased_at is not null as erased from audit_events where target_id in ('about', 'mentions', 'unrelated') order by target_id",
    );
    expect(rows).toEqual([
      { target_id: 'about', erased: true },
      { target_id: 'mentions', erased: true },
      { target_id: 'unrelated', erased: false },
    ]);
  });

  it('refuses an empty subject or pseudonym', async () => {
    await expect(ledger.erase(t.db, { subject: '', pseudonym: 'x' })).rejects.toThrow(
      /subject id is required/,
    );
    await expect(ledger.erase(t.db, { subject: 'user_ada', pseudonym: '' })).rejects.toThrow(
      /pseudonym/,
    );
  });

  it('refuses an empty email', async () => {
    await expect(
      ledger.erase(t.db, { subject: 'user_ada', pseudonym: 'x', email: '' }),
    ).rejects.toThrow(/empty email/);
    // Nothing touched: the guard fires before the SQL function runs.
    const rows = await t.query('select erased_at is not null as erased from audit_events');
    expect(rows.every((r) => r.erased === false)).toBe(true);
  });

  it("an empty subject_email at the SQL function touches only the subject's own rows, not every tenant's payloads", async () => {
    // 0002_display.sql's audit_erase_person dropped the `length() > 0` guard,
    // so an empty string became a `like '%%'` match against every row's
    // before/after text -- regardless of subject. Calling the function
    // directly (below the ledger.erase() guard added above) proves the fix
    // in migrations/0003_erase_email_guard.sql holds at the database level
    // too: an empty subject_email matches by actor_id/subject_id only.
    const touched = await t.query(
      "select audit_erase_person('user_ada', 'Erased person 7', '') as n",
    );
    expect(Number(touched[0]?.n)).toBe(2);
    const rows = await t.query(
      'select target_id, erased_at is not null as erased from audit_events order by id',
    );
    expect(rows).toEqual([
      { target_id: 'own', erased: true }, // actor_id = subject
      { target_id: 'about', erased: true }, // subject_id = subject
      { target_id: 'mentions', erased: false }, // only the email in the payload names them
      { target_id: 'unrelated', erased: false }, // no match at all
    ]);
  });
});

describe('exportRows', () => {
  it("returns one tenant's rows oldest first", async () => {
    const base = new Date('2026-09-11T10:00:00Z').getTime();
    for (const [i, tenant] of [TENANT_A, TENANT_B, TENANT_A].entries()) {
      await ledger.sign(t.db, {
        action: 'invoice.paid',
        tenantId: tenant,
        actor: ada,
        context: 'standard',
        target: { type: 'invoice', id: `i_${i}` },
        occurredAt: new Date(base - i * 1000),
      });
    }
    const rows = await ledger.exportRows(t.db, TENANT_A);
    expect(rows.map((r) => r.targetId)).toEqual(['i_2', 'i_0']);
  });
});

describe("a host's own columns", () => {
  const hostTable = pgTable('audit_events', { ...AUDIT_COLUMNS, teamId: uuid('team_id') }, (t) =>
    auditIndexes(t),
  );
  const host = createLedger({
    vocabulary: ledgerVocabularyFromCore(CORE),
    table: hostTable,
    schemaVersion: 2,
  });

  beforeEach(async () => {
    await t.exec('alter table audit_events add column if not exists team_id uuid');
  });

  it('writes them beside the ledger columns, and carries the configured schema version', async () => {
    const team = '33333333-3333-4333-8333-333333333333';
    await host.sign(t.db, {
      action: 'membership.created',
      tenantId: TENANT_A,
      actor: ada,
      context: 'standard',
      target: { type: 'membership', id: 'm_1' },
      extra: { teamId: team },
    });
    expect(await t.query('select team_id, schema_version from audit_events')).toEqual([
      { team_id: team, schema_version: 2 },
    ]);
  });

  it('refuses a ledger column or an unknown column through extra', async () => {
    const base = {
      action: 'membership.created',
      tenantId: TENANT_A,
      actor: ada,
      context: 'standard',
      target: { type: 'membership', id: 'm_1' },
    } as const;
    await expect(host.sign(t.db, { ...base, extra: { actorId: 'x' } })).rejects.toThrow(
      /is a ledger column/,
    );
    await expect(host.sign(t.db, { ...base, extra: { region: 'eu' } })).rejects.toThrow(
      /has no column "region"/,
    );
    expect(await t.query('select count(*)::int as n from audit_events')).toEqual([{ n: 0 }]);
  });
});

describe('writer', () => {
  it('signs its own namespace with the bound defaults, and refuses another', async () => {
    const write = ledger.writer({ namespace: 'invoice', handle: t.db });
    await write({
      action: 'invoice.paid',
      actor: { id: 'u_1', display: 'Ada' },
      target: { type: 'invoice', id: 'i_1' },
      after: { amount: 100 },
    });
    expect(
      await t.query(
        'select action, actor_class, context, tenant_id, tenant_visible, after from audit_events',
      ),
    ).toEqual([
      {
        action: 'invoice.paid',
        actor_class: 'human',
        context: 'standard',
        tenant_id: null,
        tenant_visible: true,
        after: { amount: 100 },
      },
    ]);
    await expect(
      write({
        action: 'tenant.created',
        actor: { id: 'u_1', display: 'Ada' },
        target: { type: 'tenant', id: TENANT_A },
      }),
    ).rejects.toThrow(/outside the namespace "invoice"/);
    await expect(
      write({
        action: 'invoice.refunded',
        actor: { id: 'u_1', display: 'Ada' },
        target: { type: 'invoice', id: 'i_1' },
      }),
    ).rejects.toThrow(/not an event this ledger's vocabulary declares/);
    expect(await t.query('select count(*)::int as n from audit_events')).toEqual([{ n: 1 }]);
  });

  it("writes on the caller's handle when given one, so the row rolls back with the change", async () => {
    const write = ledger.writer({
      namespace: 'invoice',
      handle: t.db,
      context: 'operator',
      actorClass: 'service',
      tenantId: TENANT_B,
    });
    await expect(
      t.db.transaction(async (tx) => {
        await write(
          {
            action: 'invoice.paid',
            actor: { id: 'job', display: 'Nightly' },
            target: { type: 'invoice', id: 'i_2' },
          },
          tx,
        );
        throw new Error('the change failed');
      }),
    ).rejects.toThrow('the change failed');
    expect(await t.query('select count(*)::int as n from audit_events')).toEqual([{ n: 0 }]);
    await write({
      action: 'invoice.paid',
      actor: { id: 'job', display: 'Nightly' },
      target: { type: 'invoice', id: 'i_2' },
    });
    expect(await t.query('select actor_class, context, tenant_id from audit_events')).toEqual([
      { actor_class: 'service', context: 'operator', tenant_id: TENANT_B },
    ]);
  });

  it('refuses a namespace that is not a word', () => {
    expect(() => ledger.writer({ namespace: 'Invoice.x', handle: t.db })).toThrow(
      /not a namespace/,
    );
  });
});
