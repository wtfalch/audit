import { sql } from 'drizzle-orm';
import { auditAnchors } from './anchor-tables.js';
import {
  type Der,
  DerError,
  boolean,
  children,
  decodeOid,
  integer,
  integerMagnitude,
  nullValue,
  octetString,
  oid,
  readDerExact,
  sequence,
} from './der.js';
import type { Handle } from './ledger.js';
import { resultRows } from './sql-result.js';

/**
 * Anchoring: an outside timestamp authority (RFC 3161) signs a checkpoint's
 * hash with the time. The token is stored beside the checkpoint and checked
 * offline by `audit-verify-bundle`; this file only asks, and makes sure the
 * answer is about the right hash before it keeps it.
 */

const SHA256 = '2.16.840.1.101.3.4.2.1';
const ID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const ID_CT_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const MAX_RESPONSE_BYTES = 1 << 20;

export interface AnchorOptions {
  /** The authority's RFC 3161 endpoint. */
  readonly tsaUrl: string;
  /** A name for this authority; one anchor per checkpoint and name. */
  readonly provider: string;
  /** Defaults to the global `fetch`. */
  readonly fetch?: typeof fetch;
  /** The whole request, connection to last byte. Default 10000. */
  readonly timeoutMs?: number;
}

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
const same = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new Uint8Array(data)));
}

/**
 * A `TimeStampReq` (RFC 3161 2.4.1): version 1, a SHA-256 message imprint,
 * the nonce, and `certReq` true so the token carries the authority's
 * certificate.
 */
export function buildTimestampRequest(
  imprint: Uint8Array,
  nonce: Uint8Array,
): Uint8Array<ArrayBuffer> {
  return sequence(
    integer(Uint8Array.of(1)),
    sequence(sequence(oid(SHA256), nullValue()), octetString(imprint)),
    integer(nonce),
    boolean(true),
  );
}

export interface ParsedReply {
  /** PKIStatus: 0 granted, 1 granted with modifications; anything else is a refusal. */
  readonly status: number;
  readonly token: Uint8Array | null;
  readonly imprint: Uint8Array | null;
  readonly nonce: Uint8Array | null;
  readonly genTime: Date | null;
}

/** `GeneralizedTime` as RFC 3161 writes it: `YYYYMMDDHHMMSS[.f+]Z`, to the millisecond. */
function parseGenTime(der: Der): Date {
  const text = new TextDecoder().decode(der.body);
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(text);
  if (der.tag !== 0x18 || !match) throw new DerError();
  const [, y, mo, d, h, mi, s, frac] = match;
  const ms = Number((frac ?? '').padEnd(3, '0').slice(0, 3));
  const date = new Date(
    Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms),
  );
  if (Number.isNaN(date.getTime())) throw new DerError();
  return date;
}

/** Walks a `TimeStampResp` down to the `TSTInfo`. Throws `DerError` if it is not shaped like one. */
export function parseTimestampReply(bytes: Uint8Array): ParsedReply {
  const resp = readDerExact(bytes);
  const [info, token] = children(resp);
  if (resp.tag !== 0x30 || info === undefined || info.tag !== 0x30) throw new DerError();
  const [statusDer] = children(info);
  if (statusDer === undefined) throw new DerError();
  const magnitude = integerMagnitude(statusDer);
  const status = magnitude.length === 1 ? (magnitude[0] ?? -1) : -1;
  if (status !== 0 && status !== 1) {
    return { status, token: null, imprint: null, nonce: null, genTime: null };
  }
  if (token === undefined || token.tag !== 0x30) throw new DerError();
  // ContentInfo { signedData, [0] SignedData { version, digests, encapContentInfo, ... } }
  const [contentType, explicit] = children(token);
  if (contentType === undefined || decodeOid(contentType) !== ID_SIGNED_DATA) throw new DerError();
  const [signedData] = explicit ? children(explicit) : [];
  const encap = signedData ? children(signedData)[2] : undefined;
  const [encapType, encapContent] = encap ? children(encap) : [];
  if (!encapType || decodeOid(encapType) !== ID_CT_TSTINFO || !encapContent) throw new DerError();
  const [octets] = children(encapContent);
  if (octets === undefined || octets.tag !== 0x04) throw new DerError();
  const tst = readDerExact(octets.body);
  // TSTInfo { version, policy, messageImprint, serialNumber, genTime, accuracy?, ordering?, nonce?, ... }
  const fields = children(tst);
  const messageImprint = fields[2];
  const genTime = fields[4];
  const [algorithm, hashed] = messageImprint ? children(messageImprint) : [];
  const [algorithmOid] = algorithm ? children(algorithm) : [];
  if (!genTime || !hashed || hashed.tag !== 0x04 || !algorithmOid) throw new DerError();
  if (decodeOid(algorithmOid) !== SHA256) throw new DerError();
  const nonce = fields.slice(5).find((field) => field.tag === 0x02);
  return {
    status,
    token: token.raw,
    imprint: hashed.body,
    nonce: nonce ? integerMagnitude(nonce) : null,
    genTime: parseGenTime(genTime),
  };
}

/** One checkpoint to the authority and back; throws on anything but a granted, matching token. */
async function requestAnchor(
  checkpointHash: string,
  options: AnchorOptions,
): Promise<{ token: Uint8Array; genTime: Date }> {
  const imprint = await sha256(fromHex(checkpointHash));
  const nonce = globalThis.crypto.getRandomValues(new Uint8Array(8));
  // The top bit clear and a high bit set: a positive INTEGER with no leading zero to trim.
  nonce[0] = ((nonce[0] ?? 0) & 0x7f) | 0x40;
  const doFetch = options.fetch ?? globalThis.fetch;
  const response = await doFetch(options.tsaUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/timestamp-query' },
    body: buildTimestampRequest(imprint, nonce),
    signal: AbortSignal.timeout(options.timeoutMs ?? 10_000),
  });
  if (!response.ok) throw new Error('audit: the timestamp authority answered with an error');
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length > MAX_RESPONSE_BYTES) throw new Error('audit: the timestamp reply is too large');
  const reply = parseTimestampReply(bytes);
  if (reply.status !== 0 && reply.status !== 1) {
    throw new Error('audit: the timestamp authority refused the request');
  }
  if (!reply.token || !reply.genTime || !reply.imprint || !same(reply.imprint, imprint)) {
    throw new Error('audit: the timestamp token is for another hash');
  }
  if (!reply.nonce || !same(reply.nonce, nonce)) {
    throw new Error('audit: the timestamp token answers another request');
  }
  return { token: reply.token, genTime: reply.genTime };
}

/**
 * Anchors every checkpoint this provider has not anchored yet, oldest first,
 * and returns how many anchors it wrote. No transaction is open while the
 * authority is called: each anchor is one insert after its answer is checked.
 * A checkpoint that fails (timeout, refusal, a token for another hash) writes
 * nothing and does not stop the rest; the function throws at the end, naming
 * how many failed. What was written stays, and a later run picks up only the
 * checkpoints still without an anchor.
 *
 * The token's signature is not checked here: the offline verifier does that
 * against roots the auditor chooses.
 */
export async function anchorCheckpoints(handle: Handle, options: AnchorOptions): Promise<number> {
  const pending = resultRows<{ checkpoint_hash: string }>(
    await handle.execute(sql`
      select c.checkpoint_hash from audit_checkpoints c
       where not exists (
         select 1 from audit_anchors a
          where a.checkpoint_hash = c.checkpoint_hash and a.provider = ${options.provider})
       order by c.tree_size`),
  );
  let written = 0;
  let failed = 0;
  for (const { checkpoint_hash: checkpointHash } of pending) {
    try {
      const { token, genTime } = await requestAnchor(checkpointHash, options);
      const inserted = await handle
        .insert(auditAnchors)
        .values({
          checkpointHash,
          provider: options.provider,
          token: Buffer.from(token).toString('base64'),
          tokenHash: hex(await sha256(token)),
          anchoredAt: genTime,
        })
        .onConflictDoNothing()
        .returning({ id: auditAnchors.id });
      written += inserted.length;
    } catch (_error) {
      failed += 1;
    }
  }
  if (failed > 0) {
    throw new Error(
      `audit: ${failed} of ${pending.length} checkpoints could not be anchored (${written} were)`,
    );
  }
  return written;
}
