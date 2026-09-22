// @vitest-environment jsdom
import { act, createElement } from 'react';
import { type Root, createRoot } from 'react-dom/client';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEventRow } from '../tables.js';
import { SecurityLog } from './SecurityLog.js';

const when = new Date('2026-09-22T12:00:00Z');

function row(over: Partial<AuditEventRow> = {}): AuditEventRow {
  return {
    id: 1,
    occurredAt: when,
    tenantId: null,
    actorClass: 'human',
    actorId: 'user_ada',
    actorDisplay: 'Ada Lovelace',
    action: 'membership.created',
    targetType: 'membership',
    targetId: 'm1',
    targetDisplay: null,
    tenantDisplay: null,
    outcome: 'success',
    context: 'standard',
    sessionId: null,
    reason: null,
    reference: null,
    requestId: null,
    ip: null,
    userAgent: null,
    tenantVisible: true,
    before: null,
    after: null,
    erasedAt: null,
    schemaVersion: 1,
    subjectClass: null,
    subjectId: null,
    prevHash: null,
    rowHash: null,
    contentHash: null,
    contentSalt: null,
    erasureHash: null,
    ...over,
  };
}

describe('SecurityLog (static)', () => {
  it('renders one line per item, in the sentence the host gave it', () => {
    const html = renderToStaticMarkup(
      createElement(SecurityLog, {
        page: { items: [row({ id: 1 }), row({ id: 2, action: 'invoice.paid' })], next: null },
        sentence: (r) => `${r.actorDisplay} did ${r.action}`,
      }),
    );
    expect(html).toContain('Ada Lovelace did membership.created');
    expect(html).toContain('Ada Lovelace did invoice.paid');
    expect(html).toContain('membership.created · event 1 · success');
  });

  it('shows the empty state when there is nothing, and no "Load more"', () => {
    const html = renderToStaticMarkup(
      createElement(SecurityLog, {
        page: { items: [], next: { occurredAt: when, id: 9 } },
        sentence: () => 'unreachable',
      }),
    );
    expect(html).toContain('Nothing here yet.');
    expect(html).not.toContain('Load more');
  });

  it('defaults the actor by actor_class, and the outcome by success/not', () => {
    const html = renderToStaticMarkup(
      createElement(SecurityLog, {
        page: {
          items: [
            row({ id: 1, actorClass: 'api_key', actorDisplay: 'CI key' }),
            row({ id: 2, actorClass: 'service', actorDisplay: 'Bootstrap', outcome: 'denied' }),
          ],
          next: null,
        },
        sentence: (r) => r.action,
      }),
    );
    // api_key -> a key tile, titled with the display name (ActivityLine's Avatar).
    expect(html).toContain('title="CI key"');
    // Anything not literally "success" reads as "refused" by default.
    expect(html).toContain('Refused');
  });

  it('omits "Load more" without both a cursor and a handler', () => {
    const withCursorNoHandler = renderToStaticMarkup(
      createElement(SecurityLog, {
        page: { items: [row()], next: { occurredAt: when, id: 2 } },
        sentence: () => 'x',
      }),
    );
    expect(withCursorNoHandler).not.toContain('Load more');

    const noCursorWithHandler = renderToStaticMarkup(
      createElement(SecurityLog, {
        page: { items: [row()], next: null },
        sentence: () => 'x',
        onLoadMore: () => {},
      }),
    );
    expect(noCursorWithHandler).not.toContain('Load more');
  });
});

// Mounted: "Load more" is a real button, and pressing it is the one behaviour
// static markup cannot show. Follows design's scopePicker.test.ts/
// menuInfo.test.ts: createRoot under act, a plain .click() standing in for a
// press.
describe('SecurityLog (mounted)', () => {
  let container: HTMLDivElement | undefined;
  let root: Root | undefined;

  afterEach(() => {
    if (root) act(() => root?.unmount());
    container?.remove();
    container = undefined;
    root = undefined;
  });

  it("calls onLoadMore with the page's cursor when pressed, and disables while loading", () => {
    const calls: Array<{ occurredAt: Date; id: number }> = [];
    const cursor = { occurredAt: when, id: 7 };

    container = document.createElement('div');
    document.body.appendChild(container);
    root = createRoot(container);
    act(() => {
      root?.render(
        createElement(SecurityLog, {
          page: { items: [row()], next: cursor },
          sentence: () => 'x',
          onLoadMore: (c) => calls.push(c),
        }),
      );
    });

    const button = container.querySelector('button');
    expect(button?.textContent).toBe('Load more');
    act(() => button?.click());
    expect(calls).toEqual([cursor]);

    act(() => {
      root?.render(
        createElement(SecurityLog, {
          page: { items: [row()], next: cursor },
          sentence: () => 'x',
          onLoadMore: (c) => calls.push(c),
          loading: true,
        }),
      );
    });
    expect(container.querySelector('button')?.hasAttribute('disabled')).toBe(true);
  });
});
