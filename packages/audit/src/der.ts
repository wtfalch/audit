/**
 * The little DER this package needs for RFC 3161 anchoring, and no more: a
 * reader for the shapes of a `TimeStampResp` and a writer for a
 * `TimeStampReq`. Single-byte tags, definite lengths, nothing it does not
 * understand. Token signatures are NOT checked here; that is the offline
 * verifier's job (`bin/verify-bundle.ts`, which carries its own reader).
 */

/** One DER element: its tag, its whole encoding and its content. */
export interface Der {
  readonly tag: number;
  readonly raw: Uint8Array;
  readonly body: Uint8Array;
}

export class DerError extends Error {
  constructor() {
    super('audit: malformed DER');
    this.name = 'DerError';
  }
}

/** Reads the element at `offset`. Throws `DerError` on anything truncated or unsupported. */
export function readDer(bytes: Uint8Array, offset = 0): Der {
  const tag = bytes[offset];
  const first = bytes[offset + 1];
  if (tag === undefined || first === undefined || (tag & 0x1f) === 0x1f) throw new DerError();
  let length = first;
  let header = 2;
  if (first >= 0x80) {
    const count = first & 0x7f;
    // 0x80 is the indefinite form, which DER does not have.
    if (count === 0 || count > 4) throw new DerError();
    length = 0;
    for (let i = 0; i < count; i += 1) {
      const byte = bytes[offset + 2 + i];
      if (byte === undefined) throw new DerError();
      length = length * 256 + byte;
    }
    header = 2 + count;
  }
  const end = offset + header + length;
  if (end > bytes.length) throw new DerError();
  return { tag, raw: bytes.subarray(offset, end), body: bytes.subarray(offset + header, end) };
}

/** Like `readDer`, and the element must be all of `bytes`. */
export function readDerExact(bytes: Uint8Array): Der {
  const der = readDer(bytes);
  if (der.raw.length !== bytes.length) throw new DerError();
  return der;
}

/** The elements inside a constructed element. */
export function children(der: Der): Der[] {
  const out: Der[] = [];
  let offset = 0;
  while (offset < der.body.length) {
    const child = readDer(der.body, offset);
    out.push(child);
    offset += child.raw.length;
  }
  return out;
}

export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

export function encode(tag: number, ...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const body = concat(...parts);
  let length: number[];
  if (body.length < 0x80) length = [body.length];
  else {
    const bytes: number[] = [];
    for (let n = body.length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n % 256);
    length = [0x80 | bytes.length, ...bytes];
  }
  return concat(Uint8Array.of(tag, ...length), body);
}

export const sequence = (...parts: Uint8Array[]): Uint8Array<ArrayBuffer> => encode(0x30, ...parts);
export const octetString = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => encode(0x04, bytes);
export const nullValue = (): Uint8Array<ArrayBuffer> => encode(0x05);
export const boolean = (value: boolean): Uint8Array<ArrayBuffer> =>
  encode(0x01, Uint8Array.of(value ? 0xff : 0));

/** A non-negative INTEGER from its big-endian magnitude. */
export function integer(magnitude: Uint8Array): Uint8Array<ArrayBuffer> {
  let start = 0;
  while (start < magnitude.length - 1 && magnitude[start] === 0) start += 1;
  const body = magnitude.subarray(start);
  const high = (body[0] ?? 0) >= 0x80;
  return encode(0x02, high ? Uint8Array.of(0) : new Uint8Array(0), body);
}

/** The magnitude of a non-negative INTEGER, leading zeros removed. */
export function integerMagnitude(der: Der): Uint8Array {
  if (der.tag !== 0x02 || der.body.length === 0) throw new DerError();
  let start = 0;
  while (start < der.body.length - 1 && der.body[start] === 0) start += 1;
  return der.body.subarray(start);
}

export function oid(dotted: string): Uint8Array<ArrayBuffer> {
  const arcs = dotted.split('.').map(Number);
  const [a, b, ...rest] = arcs;
  if (a === undefined || b === undefined) throw new DerError();
  const bytes: number[] = [a * 40 + b];
  for (const arc of rest) {
    const chunk = [arc % 128];
    for (let n = Math.floor(arc / 128); n > 0; n = Math.floor(n / 128))
      chunk.unshift((n % 128) | 0x80);
    bytes.push(...chunk);
  }
  return encode(0x06, Uint8Array.from(bytes));
}

export function decodeOid(der: Der): string {
  if (der.tag !== 0x06 || der.body.length === 0) throw new DerError();
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
  const head = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80];
  return [...head, ...arcs].join('.');
}
