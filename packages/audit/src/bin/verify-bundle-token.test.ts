import { execFileSync } from 'node:child_process';
import {
  type KeyObject,
  X509Certificate,
  createHash,
  createPrivateKey,
  sign as cryptoSign,
} from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  children,
  encode,
  integer,
  nullValue,
  octetString,
  oid,
  readDerExact,
  sequence,
} from '../der.js';
import { type Fixture, writeFixture } from '../test/bundle-fixture.js';
import { verifyBundle } from './verify-bundle.js';

/**
 * RFC 3161 tokens built by hand, so one property at a time can be wrong while
 * the signature stays valid. Certificates come from the `openssl` on PATH; the
 * CMS structure is written here from the RFC, not by the code under test.
 */
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_TSTINFO = '1.2.840.113549.1.9.16.1.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
const OID_SHA1 = '1.3.14.3.2.26';
const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
const OID_RSA_SHA256 = '1.2.840.113549.1.1.11';

let work: string;
let counter = 0;
beforeAll(() => {
  work = mkdtempSync(join(tmpdir(), 'audit-token-'));
});
afterAll(() => {
  rmSync(work, { recursive: true, force: true });
});

const ssl = (cwd: string, ...args: string[]) =>
  execFileSync('openssl', args, { cwd, stdio: ['ignore', 'pipe', 'pipe'] });

interface Pki {
  rootPem: string;
  /** Certificates the token carries besides the signer's, as DER. */
  embedded: Buffer[];
  leaf: X509Certificate;
  leafKey: KeyObject;
}
interface PkiOptions {
  rootDays?: number;
  /** Undefined: no intermediate. */
  intermediate?: { ca: boolean; days?: number };
  leafDays?: number;
  /** The leaf is issued by a different key that carries the root's subject name. */
  impostor?: boolean;
}

function newPki(options: PkiOptions = {}): Pki {
  counter += 1;
  const dir = join(work, `pki${counter}`);
  mkdirSync(dir);
  const key = (name: string) =>
    ssl(
      dir,
      'genpkey',
      '-algorithm',
      'EC',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-out',
      `${name}.key`,
    );
  const root = (name: string, days: number) => {
    key(name);
    ssl(
      dir,
      'req',
      '-x509',
      '-new',
      '-key',
      `${name}.key`,
      '-subj',
      '/CN=Token Test Root',
      '-days',
      String(days),
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign',
      '-out',
      `${name}.pem`,
    );
  };
  const issue = (name: string, issuer: string, days: number, ext: string, subject: string) => {
    key(name);
    ssl(dir, 'req', '-new', '-key', `${name}.key`, '-subj', subject, '-out', `${name}.csr`);
    writeFileSync(join(dir, `${name}.ext`), ext);
    ssl(
      dir,
      'x509',
      '-req',
      '-in',
      `${name}.csr`,
      '-CA',
      `${issuer}.pem`,
      '-CAkey',
      `${issuer}.key`,
      '-CAcreateserial',
      '-days',
      String(days),
      '-extfile',
      `${name}.ext`,
      '-out',
      `${name}.pem`,
    );
  };
  root('root', options.rootDays ?? 30);
  let issuer = 'root';
  const embedded: Buffer[] = [];
  if (options.impostor) {
    root('fake', 30);
    issuer = 'fake';
  }
  if (options.intermediate) {
    issue(
      'inter',
      issuer,
      options.intermediate.days ?? 30,
      `basicConstraints = critical,CA:${options.intermediate.ca ? 'TRUE' : 'FALSE'}\nkeyUsage = critical,keyCertSign\n`,
      '/CN=Token Test Intermediate',
    );
    issuer = 'inter';
    embedded.push(new X509Certificate(readFileSync(join(dir, 'inter.pem'))).raw);
  }
  issue(
    'leaf',
    issuer,
    options.leafDays ?? 30,
    `basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = critical,timeStamping\n${
      options.impostor ? 'authorityKeyIdentifier = none\n' : ''
    }`,
    '/CN=Token Test Leaf',
  );
  return {
    rootPem: readFileSync(join(dir, 'root.pem'), 'utf8'),
    embedded,
    leaf: new X509Certificate(readFileSync(join(dir, 'leaf.pem'))),
    leafKey: createPrivateKey(readFileSync(join(dir, 'leaf.key'))),
  };
}

const generalized = (at: Date) => `${at.toISOString().slice(0, 19).replaceAll(/[-:T]/g, '')}Z`;

interface TokenOptions {
  checkpointHash: string;
  genTime: Date;
  imprintOid?: string;
  messageDigest?: Uint8Array;
  attrContentType?: string;
  outerOid?: string;
  signatureOid?: string;
  signers?: number;
}

function token(pki: Pki, o: TokenOptions): Buffer {
  const imprint = createHash('sha256').update(Buffer.from(o.checkpointHash, 'hex')).digest();
  const tst = sequence(
    integer(Uint8Array.of(1)),
    oid('1.2.3.4.1'),
    sequence(sequence(oid(o.imprintOid ?? OID_SHA256), nullValue()), octetString(imprint)),
    integer(Uint8Array.of(5)),
    encode(0x18, new TextEncoder().encode(generalized(o.genTime))),
  );
  const attr = (id: string, value: Uint8Array) => sequence(oid(id), encode(0x31, value));
  const body = Uint8Array.from([
    ...attr(OID_CONTENT_TYPE, oid(o.attrContentType ?? OID_TSTINFO)),
    ...attr(
      OID_MESSAGE_DIGEST,
      octetString(o.messageDigest ?? createHash('sha256').update(tst).digest()),
    ),
  ]);
  const signature = cryptoSign('sha256', encode(0x31, body), pki.leafKey);
  // The signer's identity: issuer name and serial, copied from its certificate.
  const tbs = children(children(readDerExact(pki.leaf.raw))[0] as never);
  const at = tbs[0]?.tag === 0xa0 ? 1 : 0;
  const info = sequence(
    integer(Uint8Array.of(1)),
    sequence(tbs[at + 2]?.raw as Uint8Array, tbs[at]?.raw as Uint8Array),
    sequence(oid(OID_SHA256), nullValue()),
    encode(0xa0, body),
    sequence(oid(o.signatureOid ?? OID_ECDSA_SHA256)),
    octetString(signature),
  );
  const signedData = sequence(
    integer(Uint8Array.of(3)),
    encode(0x31, sequence(oid(OID_SHA256), nullValue())),
    sequence(oid(OID_TSTINFO), encode(0xa0, octetString(tst))),
    encode(0xa0, pki.leaf.raw, ...pki.embedded),
    encode(0x31, ...Array.from({ length: o.signers ?? 1 }, () => info)),
  );
  return Buffer.from(sequence(oid(o.outerOid ?? OID_SIGNED_DATA), encode(0xa0, signedData)));
}

let fx: Fixture;
beforeAll(() => {
  fx = writeFixture();
});
afterAll(() => {
  rmSync(dirname(fx.dir), { recursive: true, force: true });
});

function check(pki: Pki, options: Partial<TokenOptions> = {}, rootPem = pki.rootPem) {
  const checkpointHash = String(fx.checkpoints[0]?.checkpoint_hash);
  const genTime = options.genTime ?? new Date(Math.floor(Date.now() / 1000) * 1000);
  const der = token(pki, { checkpointHash, genTime, ...options });
  writeFileSync(
    join(fx.dir, 'anchors.json'),
    JSON.stringify({
      anchors: [
        {
          checkpoint_hash: checkpointHash,
          provider: 'hand',
          token: der.toString('base64'),
          token_hash: createHash('sha256').update(der).digest('hex'),
          anchored_at: genTime.toISOString(),
        },
      ],
    }),
  );
  const roots = join(work, `roots-${counter}-${Math.random().toString(16).slice(2)}.pem`);
  writeFileSync(roots, rootPem);
  return verifyBundle(fx.dir, { keys: fx.keysFile, tsaRoots: roots });
}
const hashOf = () => String(fx.checkpoints[0]?.checkpoint_hash);
const fails = (reason: string) => [`anchor ${hashOf()}: token: ${reason}`];
const CHAIN = 'the signer does not chain to the trusted roots';
const inDays = (n: number) => new Date(Math.floor(Date.now() / 1000) * 1000 + n * 86_400_000);

describe('a hand-built token', () => {
  it('passes when every property is right (so the cases below fail for their one reason)', () => {
    const result = check(newPki());
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe('PASS');
  });

  it('passes through a CA intermediate the token carries', () => {
    expect(check(newPki({ intermediate: { ca: true } })).failures).toEqual([]);
  });

  it('fails a signed digest that is not the digest of the content', () => {
    expect(
      check(newPki(), { messageDigest: createHash('sha256').update('other').digest() }).failures,
    ).toEqual(fails('the signed digest does not match the content'));
  });

  it('fails a signed content type that is not a TSTInfo', () => {
    expect(check(newPki(), { attrContentType: '1.2.840.113549.1.7.1' }).failures).toEqual(
      fails('the signed content type is not a TSTInfo'),
    );
  });

  it('fails a token with two signers', () => {
    expect(check(newPki(), { signers: 2 }).failures).toEqual(fails('expected exactly one signer'));
  });

  it('fails a signature algorithm that does not fit the signer key', () => {
    expect(check(newPki(), { signatureOid: OID_RSA_SHA256 }).failures).toEqual(
      fails('the signature does not fit the key'),
    );
  });

  it('fails an imprint that is not SHA-256', () => {
    expect(check(newPki(), { imprintOid: OID_SHA1 }).failures).toEqual(
      fails('the imprint is not SHA-256'),
    );
  });

  it('fails content that is not CMS signed data', () => {
    expect(check(newPki(), { outerOid: '1.2.840.113549.1.7.1' }).failures).toEqual(
      fails('not CMS signed data'),
    );
  });

  it('fails an intermediate that is not a CA', () => {
    expect(check(newPki({ intermediate: { ca: false } })).failures).toEqual(fails(CHAIN));
  });

  it('fails a certificate that carries the root name but was issued by another key', () => {
    const pki = newPki({ impostor: true });
    expect(check(pki).failures).toEqual(fails(CHAIN));
  });

  it('fails an intermediate that had expired at genTime', () => {
    const pki = newPki({ intermediate: { ca: true, days: 1 } });
    expect(check(pki, { genTime: inDays(3) }).failures).toEqual(fails(CHAIN));
  });

  it('fails a root that had expired at genTime', () => {
    const pki = newPki({ rootDays: 1 });
    expect(check(pki, { genTime: inDays(3) }).failures).toEqual(fails(CHAIN));
  });

  it('passes the same chain while every certificate is still valid', () => {
    const pki = newPki({ rootDays: 5, intermediate: { ca: true, days: 5 } });
    expect(check(pki, { genTime: inDays(3) }).failures).toEqual([]);
  });
});
