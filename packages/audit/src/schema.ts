import { z } from 'zod';
import { EVENT_PATTERN, type LedgerVocabulary } from './vocabulary.js';

/** The bounds every row honours, in characters; `jsonBytes` is `before` and `after`, each, serialised. Match `migrations/0001_audit.sql`. */
export const AUDIT_LIMITS = {
  id: 256,
  display: 256,
  targetType: 64,
  reason: 512,
  reference: 512,
  requestId: 128,
  ip: 64,
  userAgent: 1024,
  jsonBytes: 65536,
} as const;

/** A value that survives a JSON round trip unchanged: null, finite numbers, strings, booleans, arrays and plain objects of the same, with no cycle. */
export function isJsonValue(value: unknown, seen = new WeakSet<object>()): boolean {
  if (value === null) return true;
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return true;
    case 'number':
      return Number.isFinite(value);
    case 'object': {
      const obj = value as object;
      if (seen.has(obj)) return false;
      seen.add(obj);
      if (Array.isArray(obj)) return obj.every((v) => isJsonValue(v, seen));
      const proto = Object.getPrototypeOf(obj);
      if (proto !== Object.prototype && proto !== null) return false;
      return Object.values(obj).every((v) => isJsonValue(v, seen));
    }
    default:
      return false;
  }
}

const identifier = (max: number) => z.string().trim().min(1).max(max);
const jsonColumn = z.unknown().superRefine((value, ctx) => {
  if (value === null || value === undefined) return;
  if (!isJsonValue(value)) {
    ctx.addIssue({ code: 'custom', message: 'must be a JSON value with no cycle' });
    return;
  }
  if (JSON.stringify(value).length > AUDIT_LIMITS.jsonBytes) {
    ctx.addIssue({
      code: 'custom',
      message: `must serialise to at most ${AUDIT_LIMITS.jsonBytes} characters`,
    });
  }
});

const enumOf = (values: readonly string[]) => z.enum([...values] as [string, ...string[]]);

/**
 * One row as the ledger writes it, for a given vocabulary. Unknown keys are
 * refused, so a misspelt column fails loudly instead of vanishing. A row in
 * the break-glass context must carry the session, a reason from the closed
 * code set and a reference; every other row's reason is free text.
 */
export function rowSchema(vocabulary: LedgerVocabulary, options: { schemaVersion?: number } = {}) {
  const schemaVersion = options.schemaVersion ?? 1;
  const eventNames = Object.keys(vocabulary.events);
  const reasonCodes = new Set(vocabulary.breakGlassReasonCodes ?? []);
  return z
    .strictObject({
      occurred_at: z.iso.datetime({ offset: true }),
      tenant_id: identifier(AUDIT_LIMITS.id).nullable(),
      actor_class: enumOf(vocabulary.actorClasses),
      actor_id: identifier(AUDIT_LIMITS.id),
      actor_display: identifier(AUDIT_LIMITS.display),
      action: enumOf(eventNames).refine((a) => EVENT_PATTERN.test(a)),
      target_type: identifier(AUDIT_LIMITS.targetType),
      target_id: identifier(AUDIT_LIMITS.id),
      outcome: enumOf(vocabulary.outcomes),
      context: enumOf(vocabulary.contexts),
      session_id: identifier(AUDIT_LIMITS.id).nullable(),
      reason: identifier(AUDIT_LIMITS.reason).nullable(),
      reference: identifier(AUDIT_LIMITS.reference).nullable(),
      request_id: z.string().max(AUDIT_LIMITS.requestId).nullable(),
      ip: z.string().max(AUDIT_LIMITS.ip).nullable(),
      user_agent: z.string().max(AUDIT_LIMITS.userAgent).nullable(),
      tenant_visible: z.boolean(),
      before: jsonColumn.nullable(),
      after: jsonColumn.nullable(),
      erased_at: z.iso.datetime({ offset: true }).nullable(),
      schema_version: z.literal(schemaVersion),
      subject_class: enumOf(vocabulary.actorClasses).nullable(),
      subject_id: identifier(AUDIT_LIMITS.id).nullable(),
    })
    .superRefine((row, ctx) => {
      if ((row.subject_id === null) !== (row.subject_class === null)) {
        ctx.addIssue({
          code: 'custom',
          path: ['subject_id'],
          message: 'subject_id and subject_class come together or not at all',
        });
      }
      if (
        vocabulary.breakGlassContext === undefined ||
        row.context !== vocabulary.breakGlassContext
      )
        return;
      for (const field of ['session_id', 'reason', 'reference'] as const) {
        if (row[field] === null) {
          ctx.addIssue({
            code: 'custom',
            path: [field],
            message: `${field} is required when context is ${vocabulary.breakGlassContext}`,
          });
        }
      }
      if (row.reason !== null && !reasonCodes.has(row.reason)) {
        ctx.addIssue({
          code: 'custom',
          path: ['reason'],
          message: `reason must be one of ${[...reasonCodes].join(', ')} when context is ${vocabulary.breakGlassContext}`,
        });
      }
    });
}

export type AuditRow = z.infer<ReturnType<typeof rowSchema>>;
