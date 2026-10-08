import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);

export interface FakeTsa {
  /** Answers a POST of a `TimeStampReq` with a `TimeStampResp`, made by `openssl ts -reply`. */
  fetch: typeof fetch;
  /** The root certificate, for `--tsa-roots`. */
  rootsPem: string;
  /** The timestamping certificate that signs the tokens. */
  leafPem: string;
  /**
   * A token openssl signs over a `TSTInfo` the caller built, with the authority's
   * leaf or, with `usage`, a fresh leaf whose extended key usage is that text
   * (for example `critical,clientAuth`). For tokens `openssl ts -reply` would refuse.
   */
  forge(tstInfo: Uint8Array, usage?: string): Promise<Uint8Array>;
  close(): Promise<void>;
}

/**
 * A timestamp authority for tests: a root and a leaf with
 * `extendedKeyUsage = critical,timeStamping`, made in a temp dir with the
 * `openssl` on PATH (OpenSSL 3). If `openssl` is missing this throws; tests
 * that need an authority must fail, not skip. `keyType` is the leaf's key.
 */
export async function fakeTsa(options: { keyType?: 'rsa' | 'ec' } = {}): Promise<FakeTsa> {
  const dir = await mkdtemp(join(tmpdir(), 'audit-tsa-'));
  const at = (name: string) => join(dir, name);
  const openssl = async (...args: string[]) => {
    try {
      return await run('openssl', args, { cwd: dir });
    } catch (_error) {
      throw new Error(
        `fakeTsa: openssl ${args.slice(0, 2).join(' ')} failed (is openssl 3 on PATH?)`,
      );
    }
  };
  const newKey = (file: string, type: 'rsa' | 'ec') =>
    type === 'rsa'
      ? openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', file)
      : openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', file);
  try {
    await newKey(at('root.key'), 'ec');
    await openssl(
      'req',
      '-x509',
      '-new',
      '-key',
      'root.key',
      '-subj',
      '/CN=Fake TSA Root',
      '-days',
      '30',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
      '-out',
      'root.pem',
    );
    await newKey(at('leaf.key'), options.keyType ?? 'ec');
    await openssl('req', '-new', '-key', 'leaf.key', '-subj', '/CN=Fake TSA', '-out', 'leaf.csr');
    await writeFile(
      at('leaf.ext'),
      'basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = critical,timeStamping\n',
    );
    await openssl(
      'x509',
      '-req',
      '-in',
      'leaf.csr',
      '-CA',
      'root.pem',
      '-CAkey',
      'root.key',
      '-CAcreateserial',
      '-days',
      '30',
      '-extfile',
      'leaf.ext',
      '-out',
      'leaf.pem',
    );
    await writeFile(at('serial'), '01\n');
    await writeFile(
      at('tsa.cnf'),
      `[tsa]
default_tsa = tsa_config
[tsa_config]
serial = ${at('serial')}
crypto_device = builtin
signer_cert = ${at('leaf.pem')}
signer_key = ${at('leaf.key')}
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = no
`,
    );
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }

  // openssl keeps the serial in a file, so one answer at a time.
  let queue: Promise<unknown> = Promise.resolve();
  const answer = async (request: Uint8Array): Promise<Uint8Array> => {
    await writeFile(at('req.tsq'), request);
    await openssl(
      'ts',
      '-reply',
      '-queryfile',
      'req.tsq',
      '-config',
      'tsa.cnf',
      '-section',
      'tsa_config',
      '-out',
      'resp.tsr',
    );
    return new Uint8Array(await readFile(at('resp.tsr')));
  };
  const fakeFetch = (async (_url: unknown, init?: RequestInit) => {
    const body = init?.body;
    if (!(body instanceof Uint8Array)) throw new Error('fakeTsa: expected a Uint8Array body');
    const result = queue.then(() => answer(body));
    queue = result.catch(() => undefined);
    return new Response(new Uint8Array(await result), {
      headers: { 'content-type': 'application/timestamp-reply' },
    });
  }) as typeof fetch;

  let forged = 0;
  const forge = async (tstInfo: Uint8Array, usage?: string): Promise<Uint8Array> => {
    forged += 1;
    let leaf = 'leaf';
    if (usage !== undefined) {
      leaf = `forged${forged}`;
      await newKey(at(`${leaf}.key`), 'ec');
      await openssl(
        'req',
        '-new',
        '-key',
        `${leaf}.key`,
        '-subj',
        '/CN=Forged',
        '-out',
        `${leaf}.csr`,
      );
      await writeFile(
        at(`${leaf}.ext`),
        `basicConstraints = CA:FALSE\nextendedKeyUsage = ${usage}\n`,
      );
      await openssl(
        'x509',
        '-req',
        '-in',
        `${leaf}.csr`,
        '-CA',
        'root.pem',
        '-CAkey',
        'root.key',
        '-CAcreateserial',
        '-days',
        '30',
        '-extfile',
        `${leaf}.ext`,
        '-out',
        `${leaf}.pem`,
      );
    }
    await writeFile(at('tst.der'), tstInfo);
    await openssl(
      'cms',
      '-sign',
      '-binary',
      '-in',
      'tst.der',
      '-signer',
      `${leaf}.pem`,
      '-inkey',
      `${leaf}.key`,
      '-nodetach',
      '-outform',
      'DER',
      '-econtent_type',
      '1.2.840.113549.1.9.16.1.4',
      '-md',
      'sha256',
      '-out',
      'forged.tsr',
    );
    return new Uint8Array(await readFile(at('forged.tsr')));
  };

  return {
    fetch: fakeFetch,
    forge,
    rootsPem: await readFile(at('root.pem'), 'utf8'),
    leafPem: await readFile(at('leaf.pem'), 'utf8'),
    close: () => rm(dir, { recursive: true, force: true }),
  };
}
