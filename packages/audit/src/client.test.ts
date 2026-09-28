import { describe, expect, it, vi } from 'vitest';
import { LedgerReadError, fetchLedgerPage, fetchMergedLedgerPage } from './client.js';
import type { LedgerReadPage } from './read.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const row = (id: number, occurredAt: string) => ({
  id,
  occurredAt,
  tenantId: 't1',
  actorClass: 'human',
  actorId: 'u1',
  actorDisplay: 'Ada',
  action: 'membership.created',
  targetType: 'membership',
  targetId: 'm1',
  targetDisplay: null,
  tenantDisplay: null,
  outcome: 'success',
  context: 'standard',
  reason: null,
  reference: null,
  subjectClass: null,
  subjectId: null,
});

describe('fetchLedgerPage', () => {
  it('sends the tenant, cursor and limit, and the bearer credential', async () => {
    const fetchImpl = vi.fn(async (url: string | URL, _init?: RequestInit) => {
      const u = new URL(url);
      expect(u.pathname).toBe('/v1/audit');
      expect(u.searchParams.get('tenant')).toBe('t1');
      expect(u.searchParams.get('cursor')).toBe('c1');
      expect(u.searchParams.get('limit')).toBe('10');
      return jsonResponse({ items: [row(1, '2026-01-01T00:00:00.000Z')], nextCursor: null });
    });
    const page = await fetchLedgerPage(
      { name: 'files', baseUrl: 'https://files.example.com', credential: 'sekret' },
      { tenant: 't1', cursor: 'c1', limit: 10, fetchImpl: fetchImpl as unknown as typeof fetch },
    );
    expect(page.items).toHaveLength(1);
    const [, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer sekret');
  });

  it('throws LedgerReadError on a non-2xx wire error', async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ error: { code: 'forbidden', message: 'nope' } }, 403),
    );
    await expect(
      fetchLedgerPage(
        { name: 'files', baseUrl: 'https://files.example.com', credential: 'sekret' },
        { tenant: 't1', fetchImpl: fetchImpl as unknown as typeof fetch },
      ),
    ).rejects.toMatchObject(new LedgerReadError(403, 'forbidden', 'nope'));
  });
});

describe('fetchMergedLedgerPage', () => {
  it('merges several sources by occurredAt descending and keeps per-source cursors', async () => {
    const pages: Record<string, LedgerReadPage> = {
      files: { items: [row(1, '2026-01-01T00:00:02.000Z')], nextCursor: 'files-next' },
      ai: { items: [row(2, '2026-01-01T00:00:05.000Z')], nextCursor: null },
    };
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const u = new URL(url);
      const name = u.host.split('.')[0] ?? '';
      return jsonResponse(pages[name]);
    });
    const result = await fetchMergedLedgerPage({
      tenant: 't1',
      sources: [
        { name: 'files', baseUrl: 'https://files.example.com', credential: 'a' },
        { name: 'ai', baseUrl: 'https://ai.example.com', credential: 'b' },
      ],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(result.items.map((r) => r.id)).toEqual([2, 1]);
    expect(result.items[0]?.source).toBe('ai');
    expect(result.nextCursors).toEqual({ files: 'files-next', ai: null });
    expect(result.errors).toEqual({});
  });

  it('reports a failing source without failing the whole merge', async () => {
    const fetchImpl = vi.fn(async (url: string | URL) => {
      const u = new URL(url);
      if (u.host.startsWith('down')) return jsonResponse({ error: { code: 'unavailable' } }, 503);
      return jsonResponse({ items: [row(1, '2026-01-01T00:00:00.000Z')], nextCursor: null });
    });
    const result = await fetchMergedLedgerPage({
      tenant: 't1',
      sources: [
        { name: 'files', baseUrl: 'https://files.example.com', credential: 'a' },
        { name: 'ai', baseUrl: 'https://down.example.com', credential: 'b' },
      ],
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(result.items).toHaveLength(1);
    expect(result.items[0]?.source).toBe('files');
    expect(result.errors.ai).toBeDefined();
    expect(result.nextCursors.ai).toBeUndefined();
  });
});
