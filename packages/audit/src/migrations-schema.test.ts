import { PGlite } from '@electric-sql/pglite';
import { runMigrationSources } from '@wtfalch/db/migrate';
import { createPgliteDatabase } from '@wtfalch/db/pglite';
import { drizzle } from 'drizzle-orm/pglite';
import { afterEach, describe, expect, it } from 'vitest';
import { createLedger } from './ledger.js';
import { tables } from './tables.js';
import { CORE, sources } from './test/db.js';
import { ledgerVocabularyFromCore } from './vocabulary.js';

let pglite: PGlite;

afterEach(async () => {
  await pglite.close();
});

// The default tier runs the SQL in a named schema, the way a service host does.
describe('migrations in a named schema', () => {
  it('creates the ledger in the schema, not in public, and the functions work on a schema-only search_path', async () => {
    pglite = new PGlite();
    await runMigrationSources({
      owner: createPgliteDatabase(pglite),
      schema: 'svc',
      sources,
      log: () => undefined,
    });

    const where = await pglite.query<{ table_schema: string }>(
      "select table_schema from information_schema.tables where table_name = 'audit_events'",
    );
    expect(where.rows.map((row) => row.table_schema)).toEqual(['svc']);
    const functions = await pglite.query<{ proname: string; schema: string; proconfig: string[] }>(
      `select proname, pronamespace::regnamespace::text as schema, proconfig from pg_proc
        where proname in ('audit_erase_person', 'audit_seal_erasure', 'audit_chain_tail', 'audit_pending_erasures')
        order by 1`,
    );
    expect(functions.rows.map((row) => row.schema)).toEqual(['svc', 'svc', 'svc', 'svc']);
    // Pinned to the schema the migration ran in, which is what lets a security definer find its table.
    for (const row of functions.rows) expect(row.proconfig).toEqual(['search_path=svc, public']);

    // The runner restores the owner's search_path; a runtime connection sets its own.
    await pglite.exec('set search_path to svc');
    const db = drizzle(pglite, { schema: tables });
    const ledger = createLedger({
      vocabulary: ledgerVocabularyFromCore(CORE),
      hashChain: true,
      checkRuntimeRole: false,
    });
    const event = {
      action: 'membership.created',
      tenantId: null,
      actor: { class: 'human', id: 'user_ada', display: 'Ada' },
      context: 'standard',
      target: { type: 'membership', id: 'm_1' },
    } as const;
    await ledger.sign(db, event);
    expect(await ledger.erase(db, { subject: 'user_ada', pseudonym: 'Erased' })).toBe(1);
    const rows = await pglite.query<{ erased_at: unknown; erasure_hash: string | null }>(
      'select erased_at, erasure_hash from audit_events',
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]?.erased_at).not.toBeNull();
    // erase() sealed the row through audit_seal_erasure, and audit_chain_tail answered sign().
    expect(rows.rows[0]?.erasure_hash).not.toBeNull();
    const pending = await pglite.query('select * from audit_pending_erasures()');
    expect(pending.rows).toEqual([]);
  });
});
