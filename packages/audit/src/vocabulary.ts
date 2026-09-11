/**
 * The closed sets a host admits into its ledger. The package enforces them
 * in TypeScript at write time; the database CHECKs that enumerate the same
 * sets are the host's own migration, when it has one.
 *
 * Built by a host from `@wtfalch/authz`'s `core` (the estate's shared audit
 * words: the twenty-six authority events, four actor classes, three contexts,
 * three outcomes, five break-glass reason codes) plus whatever events the
 * host's own modules declare, through `ledgerVocabulary` below. This package
 * does not import that package; it takes the words as data.
 */

export const EVENT_PATTERN = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;

export interface LedgerEventMeta {
  /** Whether the tenant's own security log shows rows of this kind. Decided per event, never per write. */
  readonly tenantVisible: boolean;
  /** Free for the host: the permission its seam checks before signing this kind. Opaque here. */
  readonly requires?: string;
}

export interface LedgerVocabulary {
  readonly events: Readonly<Record<string, LedgerEventMeta>>;
  readonly actorClasses: readonly string[];
  readonly contexts: readonly string[];
  readonly outcomes: readonly string[];
  /** The context whose rows must carry a session, a reason from `breakGlassReasonCodes` and a reference. Omit for a host with no support sessions. */
  readonly breakGlassContext?: string;
  readonly breakGlassReasonCodes?: readonly string[];
}

export interface LedgerVocabularyInput {
  readonly events: Readonly<Record<string, LedgerEventMeta>>;
  readonly actorClasses: readonly string[];
  readonly contexts: readonly string[];
  readonly outcomes: readonly string[];
  readonly breakGlassContext?: string;
  readonly breakGlassReasonCodes?: readonly string[];
}

export class LedgerVocabularyError extends Error {
  readonly problems: readonly string[];
  constructor(problems: readonly string[]) {
    super(`ledger vocabulary: ${problems.join('; ')}`);
    this.name = 'LedgerVocabularyError';
    this.problems = problems;
  }
}

const distinct = (values: readonly string[]) => new Set(values).size === values.length;

/**
 * Validates and freezes. Every problem is named at once, so a fix is one
 * edit rather than a loop.
 */
export function ledgerVocabulary(input: LedgerVocabularyInput): LedgerVocabulary {
  const problems: string[] = [];
  const names = Object.keys(input.events);
  if (names.length === 0) problems.push('at least one event is required');
  for (const name of names) {
    if (!EVENT_PATTERN.test(name)) problems.push(`event "${name}" is not namespace.name`);
    if (typeof input.events[name]?.tenantVisible !== 'boolean')
      problems.push(`event "${name}" needs tenantVisible`);
  }
  for (const [label, values] of [
    ['actorClasses', input.actorClasses],
    ['contexts', input.contexts],
    ['outcomes', input.outcomes],
  ] as const) {
    if (values.length === 0) problems.push(`${label} is empty`);
    if (!distinct(values)) problems.push(`${label} repeats a value`);
    for (const v of values) {
      if (!/^[a-z][a-z0-9_]{0,63}$/.test(v))
        problems.push(`${label} value "${v}" is not a lower-case word`);
    }
  }
  if (input.breakGlassContext !== undefined) {
    if (!input.contexts.includes(input.breakGlassContext))
      problems.push(`breakGlassContext "${input.breakGlassContext}" is not one of the contexts`);
    if (!input.breakGlassReasonCodes || input.breakGlassReasonCodes.length === 0)
      problems.push('breakGlassContext needs breakGlassReasonCodes');
  } else if (input.breakGlassReasonCodes) {
    problems.push('breakGlassReasonCodes without a breakGlassContext');
  }
  if (problems.length > 0) throw new LedgerVocabularyError(problems);
  return Object.freeze({
    events: Object.freeze({ ...input.events }),
    actorClasses: Object.freeze([...input.actorClasses]),
    contexts: Object.freeze([...input.contexts]),
    outcomes: Object.freeze([...input.outcomes]),
    breakGlassContext: input.breakGlassContext,
    breakGlassReasonCodes: input.breakGlassReasonCodes
      ? Object.freeze([...input.breakGlassReasonCodes])
      : undefined,
  });
}

/** The shape of `@wtfalch/authz`'s `core`, as much of it as a ledger needs. Taken structurally. */
export interface AuthzCoreLike {
  readonly events: readonly string[];
  readonly tenantVisible: readonly string[];
  readonly actorClasses: readonly string[];
  readonly contexts: readonly string[];
  readonly outcomes: readonly string[];
  readonly breakGlass: { readonly reasonCodes: readonly string[] };
}

/**
 * The estate's usual construction: `@wtfalch/authz`'s core words plus the
 * host's own events. An app's event may not sit in a namespace the core
 * uses, so `tenant.invoice_paid` is refused while `invoice.paid` is not:
 * the core's namespaces are the trusted base's, and a module claiming one
 * would be writing rows a reader takes for authority changes.
 */
export function ledgerVocabularyFromCore(
  core: AuthzCoreLike,
  own: Readonly<Record<string, LedgerEventMeta>> = {},
): LedgerVocabulary {
  const visible = new Set(core.tenantVisible);
  const reserved = new Set(core.events.map((e) => e.split('.')[0] ?? e));
  const problems: string[] = [];
  const events: Record<string, LedgerEventMeta> = {};
  for (const name of core.events) events[name] = { tenantVisible: visible.has(name) };
  for (const [name, meta] of Object.entries(own)) {
    const ns = name.split('.')[0] ?? name;
    if (name in events) problems.push(`event "${name}" is already the core's`);
    else if (reserved.has(ns))
      problems.push(`event "${name}" sits in the reserved namespace "${ns}"`);
    else events[name] = meta;
  }
  if (problems.length > 0) throw new LedgerVocabularyError(problems);
  return ledgerVocabulary({
    events,
    actorClasses: core.actorClasses,
    contexts: core.contexts,
    outcomes: core.outcomes,
    breakGlassContext: 'break_glass',
    breakGlassReasonCodes: core.breakGlass.reasonCodes,
  });
}
