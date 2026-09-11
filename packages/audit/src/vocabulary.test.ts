import { describe, expect, it } from 'vitest';
import { CORE } from './test/db.js';
import { LedgerVocabularyError, ledgerVocabulary, ledgerVocabularyFromCore } from './vocabulary.js';

describe('ledgerVocabulary', () => {
  it('freezes a valid vocabulary', () => {
    const v = ledgerVocabulary({
      events: { 'invoice.paid': { tenantVisible: true } },
      actorClasses: ['human'],
      contexts: ['standard'],
      outcomes: ['success'],
    });
    expect(Object.isFrozen(v)).toBe(true);
    expect(Object.isFrozen(v.events)).toBe(true);
    expect(v.breakGlassContext).toBeUndefined();
  });

  it('names every problem at once', () => {
    let caught: unknown;
    try {
      ledgerVocabulary({
        events: { 'Invoice.Paid': { tenantVisible: true }, flat: { tenantVisible: true } },
        actorClasses: [],
        contexts: ['standard', 'standard'],
        outcomes: ['Success'],
        breakGlassContext: 'break_glass',
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(LedgerVocabularyError);
    const { problems } = caught as LedgerVocabularyError;
    expect(problems).toEqual(
      expect.arrayContaining([
        'event "Invoice.Paid" is not namespace.name',
        'event "flat" is not namespace.name',
        'actorClasses is empty',
        'contexts repeats a value',
        'outcomes value "Success" is not a lower-case word',
        'breakGlassContext "break_glass" is not one of the contexts',
        'breakGlassContext needs breakGlassReasonCodes',
      ]),
    );
  });

  it('refuses reason codes without a break-glass context', () => {
    expect(() =>
      ledgerVocabulary({
        events: { 'a.b': { tenantVisible: false } },
        actorClasses: ['human'],
        contexts: ['standard'],
        outcomes: ['success'],
        breakGlassReasonCodes: ['other'],
      }),
    ).toThrow(/without a breakGlassContext/);
  });
});

describe('ledgerVocabularyFromCore', () => {
  it("takes the core's words and marks tenant visibility per event", () => {
    const v = ledgerVocabularyFromCore(CORE);
    expect(Object.keys(v.events)).toHaveLength(26);
    expect(v.events['membership.created']).toEqual({ tenantVisible: true });
    expect(v.events['tenant.created']).toEqual({ tenantVisible: false });
    expect(v.events['person.erased']).toEqual({ tenantVisible: false });
    expect(v.breakGlassContext).toBe('break_glass');
    expect(v.breakGlassReasonCodes).toEqual(CORE.breakGlass.reasonCodes);
  });

  it("adds the host's own events outside the core's namespaces", () => {
    const v = ledgerVocabularyFromCore(CORE, {
      'invoice.paid': { tenantVisible: true },
      'mail.sent': { tenantVisible: false, requires: 'mail:send' },
    });
    expect(Object.keys(v.events)).toHaveLength(28);
    expect(v.events['mail.sent']?.requires).toBe('mail:send');
  });

  it('refuses an event in a namespace the core uses, and one the core already has', () => {
    expect(() =>
      ledgerVocabularyFromCore(CORE, {
        'tenant.invoice_paid': { tenantVisible: true },
        'membership.created': { tenantVisible: true },
      }),
    ).toThrow(
      /reserved namespace "tenant".*already the core's|already the core's.*reserved namespace "tenant"/s,
    );
  });
});
