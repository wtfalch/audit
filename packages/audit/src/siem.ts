import type { AuditEventRow } from './tables.js';

/**
 * The ledger's public surface was `sign`/`page`/`erase`/`exportRows`/
 * `writer` only: nothing bridged a row out to an enterprise customer's own
 * security tooling except a per-tenant raw dump (`exportRows`). This is
 * that bridge's serialisation half: CEF (Common Event Format), the format
 * ArcSight defined and Splunk, QRadar, Sentinel and most other SIEMs
 * ingest directly or over syslog -- the most widely adopted of the formats
 * a SIEM export is usually asked for.
 *
 * The push half -- a webhook, a syslog socket, a file a log shipper
 * tails -- is deliberately not here: which transport, whose endpoint,
 * whose credentials and whose retry policy are the host's own, one per
 * enterprise customer, and a generic package cannot decide them. `toCef`'s
 * output is already a syslog message body; a host wraps it in whatever
 * envelope its own shipper wants.
 */

export interface CefOptions {
  /** Names the device in the CEF header. Defaults are generic; a host
   *  exporting to its own customers' SIEMs should pass its own product's. */
  readonly vendor?: string;
  readonly product?: string;
  readonly version?: string;
  /** Overrides the default severity (CEF 0-10): `'success'` reads as 1, everything else as 7. */
  readonly severity?: (row: AuditEventRow) => number;
}

// CEF's own escaping, not JSON's: in the header, "\" and "|"; in the
// extension, "\", "=" and a literal newline (CEF is one line per event).
const escapeHeader = (s: string) => s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
const escapeExtension = (s: string) =>
  s
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/\r\n|\r|\n/g, '\\n');

function defaultSeverity(row: AuditEventRow): number {
  return row.outcome === 'success' ? 1 : 7;
}

/**
 * One row as a CEF line: `CEF:0|vendor|product|version|signature|name|
 * severity|extension`. `action` (the closed vocabulary's own event name,
 * e.g. `membership.role_changed`) is both the signature and the name --
 * this package does not know how to phrase a friendlier one, the same
 * reason `./react`'s `sentence` prop has no default.
 *
 * The extension favours CEF's own dictionary where a field fits (`rt`,
 * `act`, `outcome`, `suser`, `suid`), and the numbered custom-string slots
 * (`cs1`-`cs6`, each with its own `csNLabel`) for what does not: target
 * type and id, the tenant, the context (so a break-glass row reads as
 * one), the request id and the subject id. A null field is left out of the
 * extension entirely rather than sent as `cs3=`, matching how most CEF
 * receivers expect an absent value.
 */
export function toCef(row: AuditEventRow, options: CefOptions = {}): string {
  const vendor = options.vendor ?? 'wtfalch';
  const product = options.product ?? '@wtfalch/audit';
  const version = options.version ?? '1';
  const severity = (options.severity ?? defaultSeverity)(row);
  const header = [
    'CEF:0',
    escapeHeader(vendor),
    escapeHeader(product),
    escapeHeader(version),
    escapeHeader(row.action),
    escapeHeader(row.action),
    String(severity),
  ].join('|');

  const fields: Array<readonly [string, string | null]> = [
    ['rt', String(row.occurredAt.getTime())],
    ['act', row.action],
    ['outcome', row.outcome],
    ['suser', row.actorDisplay],
    ['suid', row.actorId],
    ['cs1Label', 'TargetType'],
    ['cs1', row.targetType],
    ['cs2Label', 'TargetID'],
    ['cs2', row.targetId],
    ['cs3Label', row.tenantId !== null ? 'TenantID' : null],
    ['cs3', row.tenantId],
    ['cs4Label', 'Context'],
    ['cs4', row.context],
    ['cs5Label', row.requestId !== null ? 'RequestID' : null],
    ['cs5', row.requestId],
    ['cs6Label', row.subjectId !== null ? 'SubjectID' : null],
    ['cs6', row.subjectId],
    ['msg', row.reason],
  ];
  const extension = fields
    .filter((pair): pair is [string, string] => pair[1] !== null)
    .map(([key, value]) => `${key}=${escapeExtension(value)}`)
    .join(' ');

  return `${header}|${extension}`;
}

/** Every row, one CEF line each, newline-joined -- ready for a file, a syslog body, or a webhook payload's text. */
export function toCefLines(rows: readonly AuditEventRow[], options?: CefOptions): string {
  return rows.map((row) => toCef(row, options)).join('\n');
}
