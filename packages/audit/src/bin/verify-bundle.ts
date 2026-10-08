#!/usr/bin/env node
import { X509Certificate, createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * `audit-verify-bundle <dir> [--keys <file>] [--tsa-roots <pem file>] [--extends <older dir>]`
 *
 * Checks an evidence bundle (`wtfalch-audit-evidence/1`, a directory) with
 * nothing but Node: no database, no network, no other file of this package.
 * It imports only `node:` modules on purpose, so an auditor can read this one
 * file and trust what it says. Everything it needs is written out again here:
 * canonical JSON, the row hashes, the Merkle tree, the checkpoint hash, the
 * Ed25519 check and the RFC 3161 token checks. A rule changed in the package
 * is changed here by hand, and a test builds bundles with a third copy.
 *
 * Exit 0 PASS. Exit 1 FAIL: a check failed, each failure printed with its
 * `seq` or `checkpoint_hash`. Exit 2 ERROR: bad arguments, an unreadable
 * bundle, an unknown format. Exit 3 UNCONFIRMED: every check held, but the
 * signing keys came only from the bundle's own manifest, or the bundle holds
 * anchors and `--tsa-roots` was not given.
 *
 * The whole bundle is hostile input. A value that is not what the format says
 * is a failure; a failure message names a field or a position, never a value
 * read from the bundle.
 */
const USAGE =
  'usage: audit-verify-bundle <dir> [--keys <file>] [--tsa-roots <pem file>] [--extends <older dir>]\n' +
  '                           [--ledger <name>]\n' +
  '  --keys       JSON array of {public_key, created_at, retired_at}: the signing keys you trust.\n' +
  "               Without it the bundle's own keys are used and the verdict is at best UNCONFIRMED\n" +
  '  --tsa-roots  PEM file of the timestamp authority roots you trust (needed to confirm anchors)\n' +
  '  --extends    an older bundle, from row 1, that this one must extend without rewriting it\n' +
  '  --ledger     the ledger name you expect: a bundle of another ledger fails\n' +
  '  An empty value for any option is an error';

const FORMAT = 'wtfalch-audit-evidence/1';
/** The ledger name is printed, so it is 1 to 256 printable characters. */
const LEDGER_NAME = /^(?:[^\p{C}\p{Z}]| ){1,256}$/u;

export type Verdict = 'PASS' | 'FAIL' | 'UNCONFIRMED';
export interface VerifyOptions {
  /** Path of the trusted keys file. */
  readonly keys?: string;
  /** Path of the trusted timestamp authority roots (PEM). */
  readonly tsaRoots?: string;
  /** Directory of an older bundle this one must extend. */
  readonly extends?: string;
  /** The ledger the auditor means: a bundle of another ledger fails. */
  readonly ledger?: string;
}
export interface VerifyResult {
  readonly verdict: Verdict;
  readonly failures: string[];
  readonly lines: string[];
}

/** The bundle cannot be read or is not a bundle we know: exit 2, not a verdict. */
export class BundleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BundleError';
  }
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v);
const HEX64 = /^[0-9a-f]{64}$/;
const isHex64 = (v: unknown): v is string => typeof v === 'string' && HEX64.test(v);
/** `Date#toISOString()` text, the one shape a timestamp has in a hash. */
function isIso(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  const t = Date.parse(v);
  return !Number.isNaN(t) && new Date(t).toISOString() === v;
}

const sha256 = (data: string | Uint8Array): Buffer => createHash('sha256').update(data).digest();
const sha256hex = (data: string | Uint8Array): string => sha256(data).toString('hex');

// C1. Canonical JSON v2: RFC 8785 restricted to safe integers.
class CanonError extends Error {}
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
function canon(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new CanonError('number is not a safe integer');
    return value === 0 ? '0' : String(value);
  }
  if (typeof value === 'string') {
    if (LONE_SURROGATE.test(value)) throw new CanonError('string is not well formed');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canon).join(',')}]`;
  if (typeof value === 'object') {
    const obj = value as Obj;
    return `{${Object.keys(obj)
      .sort()
      .map((key) => `${canon(key)}:${canon(obj[key])}`)
      .join(',')}}`;
  }
  throw new CanonError('value has no canonical form');
}

// C2. Row format 2.
const ROW_KEYS = [
  'seq',
  'received_at',
  'occurred_at',
  'tenant_id',
  'tenant_display',
  'actor_class',
  'actor_id',
  'action',
  'target_type',
  'target_id',
  'outcome',
  'context',
  'session_id',
  'reason',
  'reference',
  'request_id',
  'ip',
  'user_agent',
  'tenant_visible',
  'schema_version',
  'subject_class',
  'subject_id',
  'prev_hash',
  'content_hash',
] as const;
type Kind =
  | 'int'
  | 'iso'
  | 'isonull'
  | 'str'
  | 'strnull'
  | 'bool'
  | 'hex'
  | 'hexnull'
  | 'salt'
  | 'any';
const FIELDS: Record<string, Kind> = {
  v: 'int',
  seq: 'int',
  received_at: 'iso',
  occurred_at: 'iso',
  tenant_id: 'strnull',
  tenant_display: 'strnull',
  actor_class: 'str',
  actor_id: 'str',
  action: 'str',
  target_type: 'str',
  target_id: 'str',
  outcome: 'str',
  context: 'str',
  session_id: 'strnull',
  reason: 'strnull',
  reference: 'strnull',
  request_id: 'strnull',
  ip: 'strnull',
  user_agent: 'strnull',
  tenant_visible: 'bool',
  schema_version: 'int',
  subject_class: 'strnull',
  subject_id: 'strnull',
  prev_hash: 'hexnull',
  content_hash: 'hex',
  actor_display: 'str',
  target_display: 'strnull',
  before: 'any',
  after: 'any',
  row_hash: 'hex',
  content_salt: 'salt',
  erased_at: 'isonull',
  erasure_hash: 'hexnull',
};
function kindOk(kind: Kind, v: unknown): boolean {
  switch (kind) {
    case 'int':
      return isInt(v);
    case 'iso':
      return isIso(v);
    case 'isonull':
      return v === null || isIso(v);
    case 'str':
      return typeof v === 'string';
    case 'strnull':
      return v === null || typeof v === 'string';
    case 'bool':
      return typeof v === 'boolean';
    case 'hex':
      return isHex64(v);
    case 'hexnull':
      return v === null || isHex64(v);
    case 'salt':
      return v === null || (typeof v === 'string' && /^[0-9a-f]{32}$/.test(v));
    default:
      return true;
  }
}

// C3. Merkle tree, RFC 6962 section 2.1. A frontier is the roots of the
// complete subtrees of a tree, largest first.
const node = (left: Buffer, right: Buffer): Buffer =>
  sha256(Buffer.concat([Buffer.from([1]), left, right]));
const leafHash = (rowHash: string): Buffer =>
  sha256(Buffer.concat([Buffer.from([0]), Buffer.from(rowHash, 'hex')]));
function foldFrontier(frontier: readonly Buffer[]): Buffer | null {
  let acc = frontier[frontier.length - 1];
  if (acc === undefined) return null;
  for (let i = frontier.length - 2; i >= 0; i -= 1) {
    const left = frontier[i];
    if (left === undefined) return null;
    acc = node(left, acc);
  }
  return acc;
}
/** Adds one leaf to a tree of `size` leaves, in place. */
function appendLeaf(frontier: Buffer[], size: number, leaf: Buffer): void {
  let acc = leaf;
  let rest = size;
  while (rest % 2 === 1) {
    const left = frontier.pop();
    if (left === undefined) throw new BundleError('frontier does not match its size');
    acc = node(left, acc);
    rest = Math.floor(rest / 2);
  }
  frontier.push(acc);
}
function popcount(n: number): number {
  return BigInt(n)
    .toString(2)
    .split('')
    .filter((bit) => bit === '1').length;
}

// C4. Checkpoints.
const CHECKPOINT_KEYS = [
  'v',
  'ledger',
  'tree_size',
  'root',
  'prev_checkpoint',
  'created_at',
  'checkpoint_hash',
  'signature',
  'public_key',
];
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
function ed25519Ok(publicKey: string, message: Buffer, signature: string): boolean {
  try {
    const key = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(publicKey, 'hex')]),
      format: 'der',
      type: 'spki',
    });
    return cryptoVerify(null, message, key, Buffer.from(signature, 'hex'));
  } catch (_error) {
    return false;
  }
}

interface SigningKey {
  public_key: string;
  created_at: string;
  retired_at: string | null;
}
function readKeys(value: unknown, what: string): SigningKey[] {
  if (!Array.isArray(value)) throw new BundleError(`${what} is not a list of keys`);
  return value.map((entry) => {
    if (
      !isObj(entry) ||
      !isHex64(entry.public_key) ||
      !isIso(entry.created_at) ||
      !(entry.retired_at === null || isIso(entry.retired_at))
    ) {
      throw new BundleError(`${what} holds an entry that is not a key`);
    }
    return {
      public_key: entry.public_key,
      created_at: entry.created_at,
      retired_at: entry.retired_at,
    };
  });
}

function readText(path: string, name: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch (_error) {
    throw new BundleError(`cannot read ${name}`);
  }
}
function readJson(path: string, name: string): unknown {
  try {
    return JSON.parse(readText(path, name));
  } catch (error) {
    if (error instanceof BundleError) throw error;
    throw new BundleError(`${name} is not JSON`);
  }
}

// RFC 3161 timestamp tokens: a CMS SignedData (RFC 5652) holding a TSTInfo.
// The DER reader is this file's own: single-byte tags, definite lengths.
class TokenError extends Error {}
function refuse(reason: string): never {
  throw new TokenError(reason);
}

interface Der {
  tag: number;
  raw: Buffer;
  body: Buffer;
}
function readDer(bytes: Buffer, offset: number): Der {
  const tag = bytes[offset];
  const first = bytes[offset + 1];
  if (tag === undefined || first === undefined || (tag & 0x1f) === 0x1f) {
    return refuse('malformed DER');
  }
  let length = first;
  let header = 2;
  if (first >= 0x80) {
    const count = first & 0x7f;
    if (count === 0 || count > 4) return refuse('malformed DER');
    length = 0;
    for (let i = 0; i < count; i += 1) {
      const byte = bytes[offset + 2 + i];
      if (byte === undefined) return refuse('malformed DER');
      length = length * 256 + byte;
    }
    header = 2 + count;
  }
  const end = offset + header + length;
  if (end > bytes.length) return refuse('malformed DER');
  return { tag, raw: bytes.subarray(offset, end), body: bytes.subarray(offset + header, end) };
}
function readExact(bytes: Buffer, tag: number): Der {
  const der = readDer(bytes, 0);
  if (der.raw.length !== bytes.length || der.tag !== tag) return refuse('malformed DER');
  return der;
}
function kids(der: Der): Der[] {
  const out: Der[] = [];
  for (let offset = 0; offset < der.body.length; ) {
    const child = readDer(der.body, offset);
    out.push(child);
    offset += child.raw.length;
  }
  return out;
}
function oidOf(der: Der | undefined): string {
  if (der === undefined || der.tag !== 0x06 || der.body.length === 0)
    return refuse('malformed DER');
  const arcs: number[] = [];
  let value = 0;
  for (const byte of der.body) {
    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  const first = arcs.shift() ?? 0;
  return [...(first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80]), ...arcs].join(
    '.',
  );
}
function need(der: Der | undefined, tag: number): Der {
  if (der === undefined || der.tag !== tag) return refuse('malformed token');
  return der;
}
/** An INTEGER's value with leading zeros removed, as hex. */
function intHex(der: Der | undefined): string {
  return need(der, 0x02)
    .body.toString('hex')
    .replace(/^(00)+(?=.)/, '');
}

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_TIMESTAMPING = '1.3.6.1.5.5.7.3.8';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const DIGESTS: Record<string, string> = {
  [OID_SHA256]: 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};
/** Signature algorithms we check: the hash they fix (or null: the digest algorithm's) and the key type. */
const SIGNATURES: Record<string, { hash: string | null; key: 'rsa' | 'ec' }> = {
  '1.2.840.113549.1.1.1': { hash: null, key: 'rsa' },
  '1.2.840.113549.1.1.11': { hash: 'sha256', key: 'rsa' },
  '1.2.840.113549.1.1.12': { hash: 'sha384', key: 'rsa' },
  '1.2.840.113549.1.1.13': { hash: 'sha512', key: 'rsa' },
  '1.2.840.10045.4.3.2': { hash: 'sha256', key: 'ec' },
  '1.2.840.10045.4.3.3': { hash: 'sha384', key: 'ec' },
  '1.2.840.10045.4.3.4': { hash: 'sha512', key: 'ec' },
};

function genTimeOf(der: Der): Date {
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(
    der.body.toString('latin1'),
  );
  if (der.tag !== 0x18 || !match) return refuse('genTime is malformed');
  const [y, mo, d, h, mi, sec] = match.slice(1, 7).map(Number);
  const ms = Number((match[7] ?? '').padEnd(3, '0').slice(0, 3));
  return new Date(Date.UTC(y ?? 0, (mo ?? 1) - 1, d ?? 1, h ?? 0, mi ?? 0, sec ?? 0, ms));
}

const validAt = (cert: X509Certificate, at: Date): boolean =>
  Date.parse(cert.validFrom) <= at.getTime() && at.getTime() <= Date.parse(cert.validTo);

/** Whether `leaf` reaches a certificate in `roots`, through `pool`, with everyone valid at `at`. */
function chainsTo(
  leaf: X509Certificate,
  pool: readonly X509Certificate[],
  roots: readonly X509Certificate[],
  at: Date,
): boolean {
  let current = leaf;
  for (let depth = 0; depth < 6; depth += 1) {
    const here = current;
    if (roots.some((r) => r.fingerprint256 === here.fingerprint256 && validAt(r, at))) return true;
    const issuedBy = (c: X509Certificate) =>
      c.ca &&
      c.fingerprint256 !== here.fingerprint256 &&
      validAt(c, at) &&
      here.checkIssued(c) &&
      here.verify(c.publicKey);
    if (roots.some(issuedBy)) return true;
    const next = pool.find(issuedBy);
    if (next === undefined) return false;
    current = next;
  }
  return false;
}

/**
 * Checks one token for `checkpointHash` and returns its `genTime`. Throws
 * `TokenError` with fixed text. `roots` null checks everything but the chain.
 */
function verifyToken(
  token: Buffer,
  checkpointHash: string,
  roots: readonly X509Certificate[] | null,
): Date {
  const [contentType, explicit] = kids(readExact(token, 0x30));
  if (oidOf(contentType) !== OID_SIGNED_DATA) refuse('not CMS signed data');
  const signedData = kids(need(explicit, 0xa0))[0];
  const parts = kids(need(signedData, 0x30));
  const encapsulated = kids(need(parts[2], 0x30));
  const signerSet = need(parts[parts.length - 1], 0x31);
  const certNodes = parts.find((part) => part.tag === 0xa0);
  if (oidOf(encapsulated[0]) !== OID_TSTINFO) refuse('the content is not a TSTInfo');
  const eContent = need(kids(need(encapsulated[1], 0xa0))[0], 0x04).body;

  // TSTInfo: the imprint must be SHA-256 of the checkpoint hash's 32 raw bytes.
  const tst = kids(readExact(eContent, 0x30));
  const imprint = kids(need(tst[2], 0x30));
  if (oidOf(kids(need(imprint[0], 0x30))[0]) !== OID_SHA256) refuse('the imprint is not SHA-256');
  if (!need(imprint[1], 0x04).body.equals(sha256(Buffer.from(checkpointHash, 'hex')))) {
    refuse('the token is for another hash');
  }
  const genTime = genTimeOf(need(tst[4], 0x18));

  // SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature.
  const signers = kids(signerSet);
  if (signers.length !== 1) refuse('expected exactly one signer');
  const info = kids(need(signers[0], 0x30));
  const sid = kids(need(info[1], 0x30));
  const digestName = DIGESTS[oidOf(kids(need(info[2], 0x30))[0])];
  const attrs = need(info[3], 0xa0);
  const sigAlg = SIGNATURES[oidOf(kids(need(info[4], 0x30))[0])];
  const signature = need(info[5], 0x04).body;
  if (digestName === undefined) refuse('unsupported digest algorithm');
  if (sigAlg === undefined) refuse('unsupported signature algorithm');

  let messageDigest: Buffer | null = null;
  let attrContentType = '';
  for (const attr of kids(attrs)) {
    const [name, values] = kids(need(attr, 0x30));
    const value = kids(need(values, 0x31))[0];
    const id = oidOf(name);
    if (id === OID_MESSAGE_DIGEST) {
      if (messageDigest !== null) refuse('two message digests');
      messageDigest = need(value, 0x04).body;
    } else if (id === OID_CONTENT_TYPE) {
      attrContentType = oidOf(value);
    }
  }
  if (attrContentType !== OID_TSTINFO) refuse('the signed content type is not a TSTInfo');
  if (
    messageDigest === null ||
    !createHash(digestName).update(eContent).digest().equals(messageDigest)
  ) {
    refuse('the signed digest does not match the content');
  }

  // The signer's certificate, found by issuer and serial among the embedded ones.
  const certs: { cert: X509Certificate; issuer: Buffer; serial: string }[] = [];
  for (const node of certNodes ? kids(certNodes) : []) {
    try {
      const tbs = kids(need(kids(node)[0], 0x30));
      const at = tbs[0]?.tag === 0xa0 ? 1 : 0;
      certs.push({
        cert: new X509Certificate(node.raw),
        issuer: need(tbs[at + 2], 0x30).raw,
        serial: intHex(tbs[at]),
      });
    } catch (_error) {
      refuse('a certificate in the token is unreadable');
    }
  }
  const wantIssuer = need(sid[0], 0x30).raw;
  const wantSerial = intHex(sid[1]);
  const signer = certs.find((c) => c.issuer.equals(wantIssuer) && c.serial === wantSerial)?.cert;
  if (signer === undefined) return refuse('the signer certificate is not in the token');
  if (!signer.keyUsage.includes(OID_TIMESTAMPING)) refuse('the signer may not timestamp');
  if (!validAt(signer, genTime)) refuse('genTime is outside the signer certificate validity');
  if (signer.publicKey.asymmetricKeyType !== sigAlg.key)
    refuse('the signature does not fit the key');

  const signed = Buffer.from(attrs.raw);
  signed[0] = 0x31;
  let signatureOk = false;
  try {
    signatureOk = cryptoVerify(sigAlg.hash ?? digestName, signed, signer.publicKey, signature);
  } catch (_error) {
    signatureOk = false;
  }
  if (!signatureOk) refuse('the token signature does not verify');

  if (
    roots !== null &&
    !chainsTo(
      signer,
      certs.map((c) => c.cert),
      roots,
      genTime,
    )
  ) {
    refuse('the signer does not chain to the trusted roots');
  }
  return genTime;
}

function loadRoots(path: string): X509Certificate[] {
  const blocks = readText(path, 'the TSA roots file').match(
    /-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g,
  );
  if (blocks === null) throw new BundleError('the TSA roots file holds no certificate');
  try {
    return blocks.map((pem) => new X509Certificate(pem));
  } catch (_error) {
    throw new BundleError('the TSA roots file holds an unreadable certificate');
  }
}

interface Anchor {
  checkpoint_hash: string;
  provider: string;
  token: string;
  token_hash: string;
  anchored_at: string;
}
interface Inspected {
  failures: string[];
  lines: string[];
  anchors: number;
  from: number;
  ledger: string;
  /** The newest checkpoint's size and root, as the bundle states them. */
  last: { size: number; root: string } | null;
  roots: Map<number, string>;
}

function inspect(
  dir: string,
  options: { keys?: string; tsaRoots?: string },
  wantRoot: number | null,
): Inspected {
  const failures: string[] = [];
  const lines: string[] = [];
  const group = (name: string, run: () => void): void => {
    const before = failures.length;
    try {
      run();
    } catch (error) {
      if (error instanceof BundleError) throw error;
      failures.push(`${name}: the check could not run`);
    }
    const n = failures.length - before;
    lines.push(n === 0 ? `${name}: ok` : `${name}: FAILED (${n})`);
  };

  const manifest = readJson(join(dir, 'manifest.json'), 'manifest.json');
  if (!isObj(manifest) || manifest.format !== FORMAT) {
    throw new BundleError('unknown bundle format');
  }
  const range = manifest.range;
  if (
    typeof manifest.ledger !== 'string' ||
    !LEDGER_NAME.test(manifest.ledger) ||
    !isObj(range) ||
    !isInt(range.from) ||
    !isInt(range.to) ||
    range.from < 1 ||
    range.to < range.from ||
    !isInt(manifest.event_count)
  ) {
    throw new BundleError('manifest.json is malformed');
  }
  const { from, to } = range as { from: number; to: number };
  const ledger = manifest.ledger;
  const trusted =
    options.keys !== undefined
      ? readKeys(readJson(options.keys, 'the keys file'), 'the keys file')
      : readKeys(manifest.signing_keys, 'manifest signing_keys');

  const tsaRoots = options.tsaRoots !== undefined ? loadRoots(options.tsaRoots) : null;
  const eventsText = readText(join(dir, 'events.ndjson'), 'events.ndjson');
  const cpFile = readJson(join(dir, 'checkpoints.json'), 'checkpoints.json');
  const anchorFile = readJson(join(dir, 'anchors.json'), 'anchors.json');
  if (!isObj(cpFile) || !Array.isArray(cpFile.checkpoints)) {
    throw new BundleError('checkpoints.json is malformed');
  }
  if (!isObj(anchorFile) || !Array.isArray(anchorFile.anchors)) {
    throw new BundleError('anchors.json is malformed');
  }

  const anchorList: unknown[] = anchorFile.anchors;
  lines.push(`format: ${FORMAT}, ledger ${ledger}, rows ${from} to ${to}`);

  // Each event: shape, canonical text, content hash, row hash, erasure.
  const events: (Obj | null)[] = [];
  let erased = 0;
  const label = (ev: Obj | null, index: number): string =>
    ev !== null && isInt(ev.seq) ? `seq ${ev.seq}` : `event line ${index + 1}`;
  group('events', () => {
    const rows = eventsText.split('\n');
    if (rows.pop() !== '') failures.push('events.ndjson: the last line has no newline');
    rows.forEach((text, index) => {
      let ev: Obj;
      try {
        const parsed: unknown = JSON.parse(text);
        if (!isObj(parsed)) throw new CanonError('not an object');
        ev = parsed;
      } catch (_error) {
        events.push(null);
        failures.push(`event line ${index + 1}: not a JSON object`);
        return;
      }
      events.push(ev);
      const at = label(ev, index);
      const keys = Object.keys(ev).sort().join(',');
      if (keys !== Object.keys(FIELDS).sort().join(',')) {
        failures.push(`${at}: wrong set of fields`);
        return;
      }
      for (const [key, kind] of Object.entries(FIELDS)) {
        if (!kindOk(kind, ev[key])) failures.push(`${at}: field ${key} malformed`);
      }
      if (ev.v !== 2) failures.push(`${at}: field v is not 2`);
      let line: string;
      try {
        line = canon(ev);
      } catch (_error) {
        failures.push(`${at}: not canonical JSON (a float or a malformed string)`);
        return;
      }
      if (line !== text) {
        failures.push(`${at}: line is not canonical JSON`);
      }
      if (!ROW_KEYS.every((key) => kindOk(FIELDS[key] ?? 'any', ev[key]))) return;
      if (ev.content_salt !== null) {
        if (ev.erased_at !== null || ev.erasure_hash !== null) {
          failures.push(`${at}: erasure fields on a row that still has its salt`);
        }
        const content = canon({
          actor_display: ev.actor_display,
          target_display: ev.target_display,
          before: ev.before,
          after: ev.after,
        });
        if (sha256hex(String(ev.content_salt) + content) !== ev.content_hash) {
          failures.push(`${at}: content_hash does not match the content`);
        }
      } else {
        erased += 1;
        if (
          ev.erased_at === null ||
          ev.erasure_hash !== sha256hex(canon({ row_hash: ev.row_hash, erased_at: ev.erased_at }))
        ) {
          failures.push(`${at}: erased row without a valid erasure_hash`);
        }
        // erasure_hash covers public values, so the payloads must be what
        // audit_erase_person leaves: null or the marker, nothing else.
        const bare = (value: unknown): boolean =>
          value === null || canon(value) === '{"erased":true}';
        if (!bare(ev.before) || !bare(ev.after)) {
          failures.push(`${at}: an erased row holds a payload`);
        }
      }
      const hashed: Obj = { v: 2 };
      for (const key of ROW_KEYS) hashed[key] = ev[key];
      if (sha256hex(canon(hashed)) !== ev.row_hash) {
        failures.push(`${at}: row_hash does not match the row`);
      }
    });
  });

  if (erased > 0) {
    lines.push(`erased rows: ${erased} (their display names and payloads are not covered)`);
  }

  // seq dense over the range, each row linked to the one before.
  group('sequence', () => {
    if (events.length !== manifest.event_count || events.length !== to - from + 1) {
      failures.push('manifest: event_count does not match the range and the events');
    }
    events.forEach((ev, index) => {
      if (ev === null) return;
      if (ev.seq !== from + index) failures.push(`${label(ev, index)}: seq is not ${from + index}`);
      const before = events[index - 1];
      if (index > 0 && before && ev.prev_hash !== before.row_hash) {
        failures.push(`${label(ev, index)}: prev_hash is not the row before`);
      }
    });
  });

  // Checkpoints: shape first, then the base, then the tree rebuilt from the events.
  const checkpoints: Obj[] = [];
  for (const entry of cpFile.checkpoints) {
    if (!isObj(entry))
      throw new BundleError('checkpoints.json holds an entry that is not an object');
    checkpoints.push(entry);
  }
  const frontier: Buffer[] = [];
  let treeOk = true;
  group('base', () => {
    const base = manifest.base;
    if (from === 1) {
      if (base !== null) failures.push('manifest: base must be null when the range starts at 1');
      return;
    }
    const baseCp = checkpoints[0];
    const list = isObj(base) ? base.frontier : null;
    if (
      !isObj(base) ||
      base.tree_size !== from - 1 ||
      !Array.isArray(list) ||
      list.length !== popcount(from - 1) ||
      !list.every(isHex64)
    ) {
      failures.push('manifest: base is not a frontier of the tree before the range');
      treeOk = false;
      return;
    }
    for (const hash of list) frontier.push(Buffer.from(String(hash), 'hex'));
    if (!baseCp || baseCp.tree_size !== from - 1) {
      failures.push('checkpoints.json: no checkpoint at the base size');
      treeOk = false;
    } else if (foldFrontier(frontier)?.toString('hex') !== baseCp.root) {
      failures.push('manifest: base frontier does not fold to the base checkpoint root');
    }
  });

  // Roots of the tree at each size we need, from the base and the events.
  const roots = new Map<number, string>();
  const want = new Set<number>(wantRoot === null ? [] : [wantRoot]);
  for (const cp of checkpoints) if (isInt(cp.tree_size)) want.add(cp.tree_size);
  if (treeOk) {
    let size = from - 1;
    for (const ev of events) {
      if (ev === null || !isHex64(ev.row_hash)) break;
      appendLeaf(frontier, size, leafHash(ev.row_hash));
      size += 1;
      if (want.has(size)) roots.set(size, foldFrontier(frontier)?.toString('hex') ?? '');
    }
  }

  let lastSize = 0;
  group('checkpoints', () => {
    checkpoints.forEach((cp, index) => {
      const at = isHex64(cp.checkpoint_hash)
        ? `checkpoint ${cp.checkpoint_hash}`
        : `checkpoint ${index + 1}`;
      if (
        Object.keys(cp).sort().join(',') !== [...CHECKPOINT_KEYS].sort().join(',') ||
        cp.v !== 1 ||
        cp.ledger !== ledger ||
        !isInt(cp.tree_size) ||
        cp.tree_size < 1 ||
        !isHex64(cp.root) ||
        !(cp.prev_checkpoint === null || isHex64(cp.prev_checkpoint)) ||
        !isIso(cp.created_at) ||
        !isHex64(cp.checkpoint_hash) ||
        typeof cp.signature !== 'string' ||
        !/^[0-9a-f]{128}$/.test(cp.signature) ||
        !isHex64(cp.public_key)
      ) {
        failures.push(`${at}: malformed, or not for this ledger`);
        return;
      }
      const hash = sha256hex(
        canon({
          v: 1,
          ledger: cp.ledger,
          tree_size: cp.tree_size,
          root: cp.root,
          prev_checkpoint: cp.prev_checkpoint,
          created_at: cp.created_at,
        }),
      );
      if (hash !== cp.checkpoint_hash) failures.push(`${at}: checkpoint_hash does not match`);
      const before = checkpoints[index - 1];
      if (before === undefined) {
        if (from === 1 && cp.prev_checkpoint !== null) {
          failures.push(`${at}: the first checkpoint has a prev_checkpoint`);
        }
      } else {
        if (cp.prev_checkpoint !== before.checkpoint_hash) {
          failures.push(`${at}: prev_checkpoint is not the checkpoint before`);
        }
        if (!isInt(before.tree_size) || cp.tree_size <= before.tree_size) {
          failures.push(`${at}: tree_size does not grow`);
        }
      }
      const isBase = from > 1 && index === 0;
      if (!isBase && (cp.tree_size < from || cp.tree_size > to)) {
        failures.push(`${at}: tree_size is outside the range`);
      }
      if (!isBase && roots.get(cp.tree_size) !== cp.root) {
        failures.push(`${at}: root does not match the events`);
      }
      if (!ed25519Ok(cp.public_key, Buffer.from(cp.checkpoint_hash, 'hex'), cp.signature)) {
        failures.push(`${at}: signature does not verify`);
      }
      const key = trusted.find((k) => k.public_key === cp.public_key);
      if (key === undefined) {
        failures.push(`${at}: signing key is not trusted`);
      } else if (
        Date.parse(cp.created_at) < Date.parse(key.created_at) ||
        (key.retired_at !== null && Date.parse(cp.created_at) > Date.parse(key.retired_at))
      ) {
        failures.push(`${at}: dated outside its signing key's window`);
      }
      lastSize = cp.tree_size;
    });
    if (lastSize !== to) failures.push('the last checkpoint is not at the end of the range');
  });

  const anchors: Anchor[] = [];
  group('anchors', () => {
    const seen = new Set<string>();
    for (const [index, entry] of anchorList.entries()) {
      if (
        !isObj(entry) ||
        !isHex64(entry.checkpoint_hash) ||
        typeof entry.provider !== 'string' ||
        typeof entry.token !== 'string' ||
        !isHex64(entry.token_hash) ||
        !isIso(entry.anchored_at)
      ) {
        failures.push(`anchor ${index + 1}: malformed`);
        continue;
      }
      const anchor = entry as unknown as Anchor;
      anchors.push(anchor);
      const at = `anchor ${anchor.checkpoint_hash}`;
      if (!checkpoints.some((cp) => cp.checkpoint_hash === anchor.checkpoint_hash)) {
        failures.push(`${at}: no such checkpoint in the bundle`);
      }
      const key = `${anchor.checkpoint_hash} ${anchor.provider}`;
      if (seen.has(key)) failures.push(`${at}: anchored twice by one provider`);
      seen.add(key);
      const der = Buffer.from(anchor.token, 'base64');
      if (der.toString('base64') !== anchor.token) {
        failures.push(`${at}: token is not base64`);
      } else if (sha256hex(der) !== anchor.token_hash) {
        failures.push(`${at}: token_hash does not match the token`);
      }
      try {
        const genTime = verifyToken(der, anchor.checkpoint_hash, tsaRoots);
        if (Date.parse(anchor.anchored_at) !== genTime.getTime()) {
          failures.push(`${at}: anchored_at is not the token's genTime`);
        }
      } catch (error) {
        failures.push(
          `${at}: token: ${error instanceof TokenError ? error.message : 'could not be read'}`,
        );
      }
    }
  });

  return {
    failures,
    lines,
    anchors: anchors.length,
    from,
    ledger,
    last: lastSize > 0 ? { size: lastSize, root: String(checkpoints.at(-1)?.root) } : null,
    roots,
  };
}

export function verifyBundle(dir: string, options: VerifyOptions = {}): VerifyResult {
  for (const [flag, value] of Object.entries({
    '--keys': options.keys,
    '--tsa-roots': options.tsaRoots,
    '--extends': options.extends,
    '--ledger': options.ledger,
  })) {
    if (value === '') throw new BundleError(`${flag} needs a value`);
  }
  const own = { keys: options.keys, tsaRoots: options.tsaRoots };
  let older: Inspected | null = null;
  let olderFailures: string[] = [];
  if (options.extends !== undefined) {
    older = inspect(options.extends, own, null);
    olderFailures = older.failures.map((failure) => `older bundle: ${failure}`);
  }
  const result = inspect(dir, own, older?.last?.size ?? null);
  const failures = [...olderFailures, ...result.failures];
  const lines = [...result.lines];
  if (options.ledger !== undefined && options.ledger !== result.ledger) {
    failures.push('ledger: not the ledger asked for');
  }
  if (older !== null) {
    const before = failures.length;
    if (result.from !== 1 || older.from !== 1) {
      failures.push('extends: both bundles must start at row 1');
    } else if (older.last === null || result.roots.get(older.last.size) !== older.last.root) {
      failures.push('extends: the older bundle is not a prefix of this one (the roots differ)');
    }
    lines.push(failures.length === before ? 'extends: ok' : 'extends: FAILED');
  }
  let verdict: Verdict = 'PASS';
  if (failures.length > 0) verdict = 'FAIL';
  else if (options.keys === undefined || (result.anchors > 0 && options.tsaRoots === undefined)) {
    verdict = 'UNCONFIRMED';
  }
  return { verdict, failures, lines };
}

function parse(argv: readonly string[]) {
  const values: Record<string, string> = {};
  const positional: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === undefined) continue;
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    if (!['--keys', '--tsa-roots', '--extends', '--ledger'].includes(arg)) {
      throw new BundleError(`unknown argument ${arg}`);
    }
    const value = argv[i + 1];
    if (value === undefined || value === '' || value.startsWith('--'))
      throw new BundleError(`${arg} needs a value`);
    values[arg] = value;
    i += 1;
  }
  const [dir, ...rest] = positional;
  if (dir === undefined || rest.length > 0) throw new BundleError('expected exactly one directory');
  return {
    dir,
    options: {
      keys: values['--keys'],
      tsaRoots: values['--tsa-roots'],
      extends: values['--extends'],
      ledger: values['--ledger'],
    },
  };
}

/** Runs the command; returns the exit code. */
export function main(argv: readonly string[]): number {
  try {
    const args = parse(argv);
    const result = verifyBundle(args.dir, args.options);
    for (const line of result.lines) console.log(line);
    for (const failure of result.failures) console.error(`FAIL ${failure}`);
    console.log(result.verdict);
    return { PASS: 0, FAIL: 1, UNCONFIRMED: 3 }[result.verdict];
  } catch (error) {
    console.error(
      error instanceof BundleError
        ? `error: ${error.message}\n${USAGE}`
        : `error: the verifier failed on this bundle\n${USAGE}`,
    );
    return 2;
  }
}

function isEntryScript(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch (_error) {
    // The entry path is not a file (a REPL, an eval): this is a library import.
    return false;
  }
}

if (isEntryScript()) process.exitCode = main(process.argv.slice(2));
