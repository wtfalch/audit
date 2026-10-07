import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  type Fixture,
  type FixtureOptions,
  canonical,
  newKey,
  shaHex,
  writeFixture,
} from '../test/bundle-fixture.js';
import { BundleError, main, verifyBundle } from './verify-bundle.js';

type Obj = Record<string, unknown>;
const made: Fixture[] = [];
afterEach(() => {
  for (const fx of made.splice(0)) rmSync(dirname(fx.dir), { recursive: true, force: true });
  vi.restoreAllMocks();
});
function make(options?: FixtureOptions): Fixture {
  const fx = writeFixture(options);
  made.push(fx);
  return fx;
}
const verify = (fx: Fixture, extra: Obj = {}) =>
  verifyBundle(fx.dir, { keys: fx.keysFile, ...extra });

function editJson(fx: Fixture, file: string, edit: (json: Obj) => void): void {
  const path = join(fx.dir, file);
  const json = JSON.parse(readFileSync(path, 'utf8')) as Obj;
  edit(json);
  writeFileSync(path, JSON.stringify(json));
}
function editLines(fx: Fixture, edit: (lines: string[]) => string[]): void {
  const path = join(fx.dir, 'events.ndjson');
  const lines = readFileSync(path, 'utf8').split('\n').slice(0, -1);
  writeFileSync(
    path,
    edit(lines)
      .map((l) => `${l}\n`)
      .join(''),
  );
}
/** Rewrites one event (canonically, so only the hashes can catch it). */
function editEvent(fx: Fixture, seq: number, edit: (ev: Obj) => void): void {
  editLines(fx, (lines) =>
    lines.map((line) => {
      const ev = JSON.parse(line) as Obj;
      if (ev.seq !== seq) return line;
      edit(ev);
      return canonical(ev);
    }),
  );
}
describe('verifyBundle: a good bundle', () => {
  it('passes with --keys', () => {
    const result = verify(make());
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe('PASS');
    expect(result.lines).toContain('events: ok');
    expect(result.lines).toContain('checkpoints: ok');
  });

  it('is UNCONFIRMED when the keys come only from the manifest', () => {
    const fx = make();
    const result = verifyBundle(fx.dir);
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe('UNCONFIRMED');
  });

  it('passes a range that starts after 1, with a base', () => {
    const fx = make({ from: 4, count: 5, sizes: [6, 8] });
    expect(JSON.parse(readFileSync(join(fx.dir, 'manifest.json'), 'utf8')).base.tree_size).toBe(3);
    const result = verify(fx);
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe('PASS');
  });

  it('passes a range whose base size is a power of two and a size with several set bits', () => {
    const fx = make({ from: 5, count: 3, sizes: [7] });
    expect(verify(fx).failures).toEqual([]);
    const fx2 = make({ count: 11, sizes: [7, 11] });
    expect(verify(fx2).failures).toEqual([]);
  });

  it('passes a single-event range', () => {
    expect(verify(make({ count: 1, sizes: [1] })).failures).toEqual([]);
  });
});

describe('verifyBundle: every failure', () => {
  it('an edited event field fails the row hash, naming the seq', () => {
    const fx = make();
    editEvent(fx, 2, (ev) => {
      ev.action = 'invoice.refunded';
    });
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toContain('seq 2: row_hash does not match the row');
  });

  it('edited content fails the content hash', () => {
    const fx = make();
    editEvent(fx, 3, (ev) => {
      ev.after = { n: 99 };
    });
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toContain('seq 3: content_hash does not match the content');
  });

  it('a dropped event fails the count, the seq and the root', () => {
    const fx = make();
    editLines(fx, (lines) => lines.filter((_, i) => i !== 1));
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toContain(
      'manifest: event_count does not match the range and the events',
    );
    expect(result.failures).toContain('seq 3: seq is not 2');
    expect(result.failures.some((f) => f.endsWith('root does not match the events'))).toBe(true);
  });

  it('swapped events fail the seq and the link', () => {
    const fx = make();
    editLines(fx, (lines) => {
      const [a, b, ...rest] = lines;
      return [b ?? '', a ?? '', ...rest];
    });
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toContain('seq 2: seq is not 1');
    expect(result.failures).toContain('seq 1: seq is not 2');
  });

  it('a prev_hash that is not the row before fails, even when the row hash is redone', () => {
    const fx = make();
    editEvent(fx, 3, (ev) => {
      ev.prev_hash = shaHex('elsewhere');
      // Redo the row hash so only the link is wrong.
      const hashed: Obj = { v: 2 };
      for (const key of [
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
      ])
        hashed[key] = ev[key];
      ev.row_hash = shaHex(canonical(hashed));
    });
    const result = verify(fx);
    expect(result.failures).toContain('seq 3: prev_hash is not the row before');
    expect(result.failures).not.toContain('seq 3: row_hash does not match the row');
  });

  it('a bad base frontier fails', () => {
    const fx = make({ from: 4, count: 3, sizes: [6] });
    editJson(fx, 'manifest.json', (m) => {
      (m.base as { frontier: string[] }).frontier[0] = shaHex('other');
    });
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toContain(
      'manifest: base frontier does not fold to the base checkpoint root',
    );
  });

  it('a base frontier of the wrong length fails', () => {
    const fx = make({ from: 4, count: 3, sizes: [6] });
    editJson(fx, 'manifest.json', (m) => {
      (m.base as { frontier: string[] }).frontier.pop();
    });
    expect(verify(fx).failures).toContain(
      'manifest: base is not a frontier of the tree before the range',
    );
  });

  it('an edited checkpoint field fails the checkpoint hash', () => {
    const fx = make();
    editJson(fx, 'checkpoints.json', (j) => {
      Object.assign((j.checkpoints as Obj[])[0] ?? {}, { created_at: '2026-10-03T00:00:09.000Z' });
    });
    const hash = String(fx.checkpoints[0]?.checkpoint_hash);
    expect(verify(fx).failures).toContain(`checkpoint ${hash}: checkpoint_hash does not match`);
  });

  it('a broken prev_checkpoint fails', () => {
    const fx = make({
      tweakCheckpoint: (cp, i) => {
        if (i === 1) cp.prev_checkpoint = shaHex('not the one');
      },
    });
    const hash = String(fx.checkpoints[1]?.checkpoint_hash);
    expect(verify(fx).failures).toEqual([
      `checkpoint ${hash}: prev_checkpoint is not the checkpoint before`,
    ]);
  });

  it('a wrong root fails, though the checkpoint is signed over it', () => {
    const fx = make({
      tweakCheckpoint: (cp, i) => {
        if (i === 0) cp.root = shaHex('wrong');
      },
    });
    const hash = String(fx.checkpoints[0]?.checkpoint_hash);
    expect(verify(fx).failures).toEqual([`checkpoint ${hash}: root does not match the events`]);
  });

  it('a bad signature fails', () => {
    const fx = make();
    editJson(fx, 'checkpoints.json', (j) => {
      const cp = (j.checkpoints as Obj[])[1] as Obj;
      const sig = String(cp.signature);
      cp.signature = `${sig[0] === 'a' ? 'b' : 'a'}${sig.slice(1)}`;
    });
    const hash = String(fx.checkpoints[1]?.checkpoint_hash);
    expect(verify(fx).failures).toEqual([`checkpoint ${hash}: signature does not verify`]);
  });

  it('a key that is not trusted fails', () => {
    const fx = make();
    const other = make({ key: newKey() });
    const result = verifyBundle(fx.dir, { keys: other.keysFile });
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toHaveLength(2);
    expect(result.failures.every((f) => f.endsWith('signing key is not trusted'))).toBe(true);
  });

  it('a checkpoint dated after its key was retired fails', () => {
    const fx = make();
    writeFileSync(
      fx.keysFile,
      JSON.stringify([
        {
          public_key: fx.key.publicKey,
          created_at: '2026-09-01T00:00:00.000Z',
          retired_at: '2026-10-03T00:00:00.500Z',
        },
      ]),
    );
    const late = String(fx.checkpoints[1]?.checkpoint_hash);
    expect(verify(fx).failures).toEqual([
      `checkpoint ${late}: dated outside its signing key's window`,
    ]);
  });

  it('a checkpoint dated before its key existed fails', () => {
    const fx = make();
    writeFileSync(
      fx.keysFile,
      JSON.stringify([
        { public_key: fx.key.publicKey, created_at: '2026-10-03T00:00:00.500Z', retired_at: null },
      ]),
    );
    const first = String(fx.checkpoints[0]?.checkpoint_hash);
    expect(verify(fx).failures).toEqual([
      `checkpoint ${first}: dated outside its signing key's window`,
    ]);
  });

  it('a last checkpoint short of range.to fails', () => {
    const fx = make({ sizes: [3] });
    expect(verify(fx).failures).toEqual(['the last checkpoint is not at the end of the range']);
  });

  it('a checkpoint outside the range fails', () => {
    const fx = make({ from: 4, count: 3, sizes: [5, 6] });
    // Move the range start so the size-5 checkpoint is fine, then cut the end.
    editJson(fx, 'manifest.json', (m) => {
      (m.range as Obj).to = 5;
      m.event_count = 2;
    });
    expect(verify(fx).verdict).toBe('FAIL');
  });

  it('an erased row with a valid erasure_hash passes', () => {
    const fx = make({ erase: [2] });
    const line = readFileSync(join(fx.dir, 'events.ndjson'), 'utf8').split('\n')[1] ?? '';
    expect(JSON.parse(line).content_salt).toBeNull();
    expect(verify(fx).failures).toEqual([]);
  });

  it('an erased row with a wrong erasure_hash fails', () => {
    const fx = make({ erase: [2] });
    editEvent(fx, 2, (ev) => {
      ev.erasure_hash = shaHex('forged');
    });
    expect(verify(fx).failures).toEqual(['seq 2: erased row without a valid erasure_hash']);
  });

  it('an erased row with no erasure_hash or no erased_at fails', () => {
    const a = make({ erase: [2] });
    editEvent(a, 2, (ev) => {
      ev.erasure_hash = null;
    });
    expect(verify(a).failures).toEqual(['seq 2: erased row without a valid erasure_hash']);
    const b = make({ erase: [2] });
    editEvent(b, 2, (ev) => {
      ev.erased_at = null;
    });
    expect(verify(b).failures).toContain('seq 2: erased row without a valid erasure_hash');
  });

  it('erasure fields on a row that still has its salt fail', () => {
    const fx = make();
    editEvent(fx, 2, (ev) => {
      ev.erased_at = '2026-10-02T00:00:00.000Z';
    });
    expect(verify(fx).failures).toContain('seq 2: erasure fields on a row that still has its salt');
  });

  it('a float in an event is a failure', () => {
    const fx = make();
    const path = join(fx.dir, 'events.ndjson');
    const text = readFileSync(path, 'utf8');
    expect(text).toContain('"n":2,');
    writeFileSync(path, text.replace('"n":2,', '"n":2.5,'));
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toContain('seq 2: not canonical JSON (a float or a malformed string)');
  });

  it('a number past the safe range is a failure', () => {
    const fx = make();
    const path = join(fx.dir, 'events.ndjson');
    writeFileSync(path, readFileSync(path, 'utf8').replace('"n":2,', '"n":99999999999999999999,'));
    expect(verify(fx).failures).toContain(
      'seq 2: not canonical JSON (a float or a malformed string)',
    );
  });

  it('a line that is JSON but not canonical fails', () => {
    const fx = make();
    editLines(fx, (lines) =>
      lines.map((l, i) => (i === 0 ? l.replace('"action":', '"action": ') : l)),
    );
    expect(verify(fx).failures).toContain('seq 1: line is not canonical JSON');
  });

  it('an extra field in an event fails', () => {
    const fx = make();
    editEvent(fx, 1, (ev) => {
      ev.extra = 1;
    });
    expect(verify(fx).failures).toContain('seq 1: wrong set of fields');
  });
});

describe('verifyBundle: --extends', () => {
  it('passes when the older bundle is a prefix', () => {
    const key = newKey();
    const older = make({ count: 3, sizes: [3], key });
    const fx = make({ count: 6, sizes: [3, 6], key });
    const result = verify(fx, { extends: older.dir });
    expect(result.failures).toEqual([]);
    expect(result.verdict).toBe('PASS');
    expect(result.lines).toContain('extends: ok');
  });

  it('fails when the history diverged', () => {
    const key = newKey();
    const older = make({ count: 3, sizes: [3], key, variant: 'x' });
    const fx = make({ count: 6, sizes: [3, 6], key });
    const result = verify(fx, { extends: older.dir });
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toEqual([
      'extends: the older bundle is not a prefix of this one (the roots differ)',
    ]);
  });

  it('fails when a bundle does not start at 1', () => {
    const key = newKey();
    const older = make({ count: 3, sizes: [3], key });
    const fx = make({ from: 4, count: 3, sizes: [6], key });
    expect(verify(fx, { extends: older.dir }).failures).toEqual([
      'extends: both bundles must start at row 1',
    ]);
  });

  it('fails when the older bundle is itself broken', () => {
    const key = newKey();
    const older = make({ count: 3, sizes: [3], key });
    editEvent(older, 1, (ev) => {
      ev.action = 'x';
    });
    const fx = make({ count: 6, sizes: [3, 6], key });
    const result = verify(fx, { extends: older.dir });
    expect(result.verdict).toBe('FAIL');
    expect(result.failures.some((f) => f.startsWith('older bundle: seq 1'))).toBe(true);
  });
});

describe('verifyBundle: hostile input', () => {
  it('an unknown format is an error, not a verdict', () => {
    const fx = make();
    editJson(fx, 'manifest.json', (m) => {
      m.format = 'wtfalch-audit-evidence/2';
    });
    expect(() => verify(fx)).toThrow(new BundleError('unknown bundle format'));
  });

  it('a missing file is an error', () => {
    const fx = make();
    rmSync(join(fx.dir, 'anchors.json'));
    expect(() => verify(fx)).toThrow(new BundleError('cannot read anchors.json'));
  });

  it('a manifest that is not JSON is an error', () => {
    const fx = make();
    writeFileSync(join(fx.dir, 'manifest.json'), '{"format":');
    expect(() => verify(fx)).toThrow(new BundleError('manifest.json is not JSON'));
  });

  it.each([
    ['a huge range', { from: 1, to: 1e308 }],
    ['a negative start', { from: -5, to: 3 }],
    ['an inverted range', { from: 5, to: 2 }],
    ['a fraction', { from: 1.5, to: 3 }],
  ])('%s in the manifest is an error', (_name, range) => {
    const fx = make();
    editJson(fx, 'manifest.json', (m) => {
      m.range = range;
    });
    expect(() => verify(fx)).toThrow(new BundleError('manifest.json is malformed'));
  });

  it('events that are not JSON, not objects, or truncated fail without throwing', () => {
    const fx = make();
    editLines(fx, (lines) => ['{"seq":', '[1]', 'null', ...lines.slice(3)]);
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toContain('event line 1: not a JSON object');
    expect(result.failures).toContain('event line 2: not a JSON object');
    expect(result.failures).toContain('event line 3: not a JSON object');
  });

  it('an events file with no final newline fails', () => {
    const fx = make();
    const path = join(fx.dir, 'events.ndjson');
    writeFileSync(path, readFileSync(path, 'utf8').slice(0, -1));
    expect(verify(fx).failures).toContain('events.ndjson: the last line has no newline');
  });

  it('an empty events file fails', () => {
    const fx = make();
    writeFileSync(join(fx.dir, 'events.ndjson'), '');
    expect(verify(fx).verdict).toBe('FAIL');
  });

  it('wrong types inside checkpoints fail without throwing', () => {
    const fx = make();
    editJson(fx, 'checkpoints.json', (j) => {
      const list = j.checkpoints as Obj[];
      list[0] = { ...list[0], tree_size: '3', root: 7 };
      list[1] = { ...list[1], tree_size: 1e308, signature: null };
    });
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures.some((f) => f.endsWith('malformed, or not for this ledger'))).toBe(true);
  });

  it('checkpoints that are not objects are an error', () => {
    const fx = make();
    writeFileSync(join(fx.dir, 'checkpoints.json'), '{"checkpoints":[1]}');
    expect(() => verify(fx)).toThrow(BundleError);
  });

  it('a bad keys file is an error', () => {
    const fx = make();
    writeFileSync(fx.keysFile, '[{"public_key":"zz"}]');
    expect(() => verify(fx)).toThrow(BundleError);
  });

  it('a manifest with no base but a range after 1 fails', () => {
    const fx = make({ from: 4, count: 3, sizes: [6] });
    editJson(fx, 'manifest.json', (m) => {
      m.base = null;
    });
    expect(verify(fx).failures).toContain(
      'manifest: base is not a frontier of the tree before the range',
    );
  });

  it('a base on a range from 1 fails', () => {
    const fx = make();
    editJson(fx, 'manifest.json', (m) => {
      m.base = { tree_size: 0, frontier: [] };
    });
    expect(verify(fx).failures).toContain('manifest: base must be null when the range starts at 1');
  });
});

describe('main', () => {
  function run(...args: string[]): { code: number; out: string; err: string } {
    const out: string[] = [];
    const err: string[] = [];
    vi.spyOn(console, 'log').mockImplementation((line) => void out.push(String(line)));
    vi.spyOn(console, 'error').mockImplementation((line) => void err.push(String(line)));
    const code = main(args);
    return { code, out: out.join('\n'), err: err.join('\n') };
  }

  it('exits 0 on PASS, 3 on UNCONFIRMED, 1 on FAIL', () => {
    const fx = make();
    expect(run(fx.dir, '--keys', fx.keysFile).code).toBe(0);
    const unconfirmed = run(fx.dir);
    expect(unconfirmed.code).toBe(3);
    expect(unconfirmed.out).toContain('UNCONFIRMED');
    editEvent(fx, 1, (ev) => {
      ev.action = 'x';
    });
    const failed = run(fx.dir, '--keys', fx.keysFile);
    expect(failed.code).toBe(1);
    expect(failed.err).toContain('FAIL seq 1: row_hash does not match the row');
  });

  it('exits 2 on an unknown format, a missing directory and bad arguments', () => {
    const fx = make();
    editJson(fx, 'manifest.json', (m) => {
      m.format = 'other/1';
    });
    expect(run(fx.dir).code).toBe(2);
    expect(run(join(fx.dir, 'nowhere')).code).toBe(2);
    expect(run().code).toBe(2);
    expect(run(fx.dir, '--nope', 'x').code).toBe(2);
    expect(run(fx.dir, '--keys').code).toBe(2);
    const message = run(fx.dir).err;
    expect(message).toContain('error: unknown bundle format');
  });
});

describe('the verifier source', () => {
  it('imports only node: modules', () => {
    const source = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), 'verify-bundle.ts'),
      'utf8',
    );
    const specifiers = [
      ...[...source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)].map((m) => m[1]),
      ...[...source.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]/g)].map((m) => m[1]),
      ...[...source.matchAll(/\brequire\s*\(\s*['"]([^'"]+)['"]/g)].map((m) => m[1]),
      ...[...source.matchAll(/^import\s+['"]([^'"]+)['"]/gm)].map((m) => m[1]),
    ];
    expect(specifiers.length).toBeGreaterThan(0);
    for (const specifier of specifiers) expect(specifier).toMatch(/^node:/);
    expect(source.startsWith('#!/usr/bin/env node\n')).toBe(true);
  });
});
