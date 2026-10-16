import { describe, expect, it } from 'vitest';
// The built entry, not src: this is the file a Worker bundles.
import { createLedger, ledgerVocabulary } from '../dist/index.js';

const vocabulary = ledgerVocabulary({
  events: { 'invoice.paid': { tenantVisible: true } },
  actorClasses: ['human'],
  contexts: ['standard'],
  outcomes: ['success'],
});

/** The statements sign() sends with hashChain on, answered in memory. */
function fakeHandle(tail: { seq: number | null; row_hash: string | null }, failInsert = false) {
  const inserted: Record<string, unknown>[] = [];
  const statements: string[] = [];
  const tx = {
    execute: async (query: { queryChunks?: unknown[] }) => {
      statements.push(JSON.stringify(query.queryChunks ?? []));
      return [{ ...tail, received_at: new Date('2026-10-16T10:00:00.000Z') }];
    },
    insert: () => ({
      values: async (row: Record<string, unknown>) => {
        if (failInsert) throw new Error('insert refused');
        inserted.push(row);
      },
    }),
  };
  return {
    handle: { transaction: async (fn: (t: typeof tx) => Promise<void>) => fn(tx) },
    inserted,
    statements,
  };
}

const event = {
  action: 'invoice.paid',
  tenantId: null,
  actor: { class: 'human', id: 'u_1', display: 'Ada' },
  context: 'standard',
  target: { type: 'invoice', id: 'i_1' },
  after: { amount: 100 },
} as const;

describe('the built main entry on workerd', () => {
  it('runs on workerd', () => {
    expect(navigator.userAgent).toBe('Cloudflare-Workers');
  });

  it('signs a chained row: lock, tail read, one insert sealed with SHA-256 from Web Crypto', async () => {
    const ledger = createLedger({ vocabulary, hashChain: true, checkRuntimeRole: false });
    const { handle, inserted, statements } = fakeHandle({ seq: null, row_hash: null });
    // biome-ignore lint/suspicious/noExplicitAny: a fake handle stands in for a Postgres one
    await ledger.sign(handle as any, event);
    expect(statements.length).toBe(2);
    expect(statements[0]).toContain('pg_advisory_xact_lock');
    expect(statements[1]).toContain('audit_chain_tail_v2');
    expect(inserted).toHaveLength(1);
    const [row] = inserted;
    expect(row?.seq).toBe(1);
    expect(row?.chainVersion).toBe(2);
    expect(row?.prevHash).toBeNull();
    expect(row?.rowHash).toMatch(/^[0-9a-f]{64}$/);
    expect(row?.contentHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('links the next row to the tail it read', async () => {
    const ledger = createLedger({ vocabulary, hashChain: true, checkRuntimeRole: false });
    const first = fakeHandle({ seq: null, row_hash: null });
    // biome-ignore lint/suspicious/noExplicitAny: a fake handle stands in for a Postgres one
    await ledger.sign(first.handle as any, event);
    const a = first.inserted[0] as Record<string, unknown>;
    const second = fakeHandle({ seq: 1, row_hash: a.rowHash as string });
    // biome-ignore lint/suspicious/noExplicitAny: a fake handle stands in for a Postgres one
    await ledger.sign(second.handle as any, { ...event, target: { type: 'invoice', id: 'i_2' } });
    const b = second.inserted[0] as Record<string, unknown>;
    expect(b.seq).toBe(2);
    expect(b.prevHash).toBe(a.rowHash);
  });

  it('writes nothing when the insert fails', async () => {
    const ledger = createLedger({ vocabulary, hashChain: true, checkRuntimeRole: false });
    const { handle, inserted } = fakeHandle({ seq: null, row_hash: null }, true);
    // biome-ignore lint/suspicious/noExplicitAny: a fake handle stands in for a Postgres one
    await expect(ledger.sign(handle as any, event)).rejects.toThrow('insert refused');
    expect(inserted).toEqual([]);
  });
});
