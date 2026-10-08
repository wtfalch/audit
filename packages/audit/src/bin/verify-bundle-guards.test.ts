import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  type Fixture,
  type FixtureOptions,
  canonical,
  newKey,
  shaHex,
  writeFixture,
} from '../test/bundle-fixture.js';
import { verifyBundle } from './verify-bundle.js';

/**
 * One test per check of the verifier, each built so that only that check can
 * report it: remove the check and the test goes red. The expected texts are
 * exact on purpose, so another check cannot stand in.
 */
type Obj = Record<string, unknown>;
const made: Fixture[] = [];
afterEach(() => {
  for (const fx of made.splice(0)) rmSync(dirname(fx.dir), { recursive: true, force: true });
});
function make(options?: FixtureOptions): Fixture {
  const fx = writeFixture(options);
  made.push(fx);
  return fx;
}
const verify = (fx: Fixture, keysFile = fx.keysFile) => verifyBundle(fx.dir, { keys: keysFile });

function editJson(fx: Fixture, file: string, edit: (json: Obj) => void): void {
  const path = join(fx.dir, file);
  const json = JSON.parse(readFileSync(path, 'utf8')) as Obj;
  edit(json);
  writeFileSync(path, JSON.stringify(json));
}
function editEvent(fx: Fixture, seq: number, edit: (ev: Obj) => void): void {
  const path = join(fx.dir, 'events.ndjson');
  const lines = readFileSync(path, 'utf8').split('\n').slice(0, -1);
  const out = lines.map((line) => {
    const ev = JSON.parse(line) as Obj;
    if (ev.seq !== seq) return line;
    edit(ev);
    return canonical(ev);
  });
  writeFileSync(path, out.map((l) => `${l}\n`).join(''));
}
const keysWith = (fx: Fixture, window: { created_at?: string; retired_at?: string | null }) => {
  const path = join(dirname(fx.dir), 'window-keys.json');
  const [key] = fx.keys;
  writeFileSync(path, JSON.stringify([{ ...key, ...window }]));
  return path;
};

describe('event checks, one at a time', () => {
  it('a row whose v is not 2 is named', () => {
    const fx = make();
    editEvent(fx, 2, (ev) => {
      ev.v = 3;
    });
    expect(verify(fx).failures).toContain('seq 2: field v is not 2');
  });

  it('an erased row whose erased_at is null fails even with an erasure_hash made for null', () => {
    const fx = make({ erase: [2] });
    editEvent(fx, 2, (ev) => {
      ev.erased_at = null;
      ev.erasure_hash = shaHex(canonical({ row_hash: ev.row_hash, erased_at: null }));
    });
    expect(verify(fx).failures).toEqual(['seq 2: erased row without a valid erasure_hash']);
  });

  it('an erasure_hash made for another row_hash fails', () => {
    const fx = make({ erase: [2] });
    editEvent(fx, 2, (ev) => {
      ev.erasure_hash = shaHex(canonical({ row_hash: shaHex('other'), erased_at: ev.erased_at }));
    });
    expect(verify(fx).failures).toEqual(['seq 2: erased row without a valid erasure_hash']);
  });

  it('a lone surrogate in a string is refused, though JSON.stringify writes it', () => {
    const fx = make();
    const path = join(fx.dir, 'events.ndjson');
    const lines = readFileSync(path, 'utf8').split('\n').slice(0, -1);
    lines[1] = (lines[1] ?? '').replace('"Ada 2"', '"Ada \\ud800"');
    writeFileSync(path, lines.map((l) => `${l}\n`).join(''));
    expect(verify(fx).failures).toContain(
      'seq 2: not canonical JSON (a float or a malformed string)',
    );
  });
});

describe('manifest checks, one at a time', () => {
  it('an event_count that does not match the events fails', () => {
    const fx = make();
    editJson(fx, 'manifest.json', (m) => {
      m.event_count = 5;
    });
    expect(verify(fx).failures).toEqual([
      'manifest: event_count does not match the range and the events',
    ]);
  });

  it('a range wider than the events fails, though event_count matches the events', () => {
    const fx = make();
    editJson(fx, 'manifest.json', (m) => {
      (m.range as { to: number }).to = 7;
    });
    const failures = verify(fx).failures;
    expect(failures).toContain('manifest: event_count does not match the range and the events');
  });

  it('a base for another size fails, though its frontier folds to the base root', () => {
    const fx = make({ from: 4, count: 3, sizes: [6] });
    editJson(fx, 'manifest.json', (m) => {
      (m.base as { tree_size: number }).tree_size = 2;
    });
    expect(verify(fx).failures).toContain(
      'manifest: base is not a frontier of the tree before the range',
    );
  });

  it('a base frontier entry that is not 64 hex digits fails', () => {
    const fx = make({ from: 4, count: 3, sizes: [6] });
    editJson(fx, 'manifest.json', (m) => {
      (m.base as { frontier: string[] }).frontier[0] = 'zz';
    });
    expect(verify(fx).failures).toContain(
      'manifest: base is not a frontier of the tree before the range',
    );
  });

  it('a first checkpoint of another size than the base fails with its own message', () => {
    // The base frontier (size 3) is right; checkpoints.json starts with a checkpoint at size 2.
    const fx = make({ from: 4, count: 3, sizes: [6] });
    const other = make({ from: 3, count: 4, sizes: [6] });
    const cps = JSON.parse(readFileSync(join(other.dir, 'checkpoints.json'), 'utf8')) as {
      checkpoints: Obj[];
    };
    const mine = JSON.parse(readFileSync(join(fx.dir, 'checkpoints.json'), 'utf8')) as {
      checkpoints: Obj[];
    };
    // Same key, same ledger: the wrong-size checkpoint is valid in itself; only the size is wrong.
    mine.checkpoints[0] = { ...(cps.checkpoints[0] as Obj) };
    writeFileSync(join(fx.dir, 'checkpoints.json'), JSON.stringify(mine));
    expect(verify(fx).failures).toContain('checkpoints.json: no checkpoint at the base size');
  });
});

describe('checkpoint checks, one at a time', () => {
  // `tweakCheckpoint` runs before the hash and the signature, so these are signed and hashed right.
  it('a checkpoint with v 2 is refused', () => {
    const fx = make({
      tweakCheckpoint: (cp, i) => {
        if (i === 0) cp.v = 2;
      },
    });
    expect(verify(fx).failures).toEqual([
      expect.stringMatching(/^checkpoint [0-9a-f]{64}: malformed, or not for this ledger$/),
    ]);
  });

  it('a checkpoint of another ledger under the same trusted key is refused', () => {
    const fx = make({
      tweakCheckpoint: (cp, i) => {
        if (i === 1) cp.ledger = 'other-ledger';
      },
    });
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(
      result.failures.filter((f) => f.endsWith(': malformed, or not for this ledger')),
    ).toHaveLength(1);
  });

  it('a checkpoint of size 0 is refused as malformed', () => {
    const fx = make({
      sizes: [3, 6],
      tweakCheckpoint: (cp, i) => {
        if (i === 0) cp.tree_size = 0;
      },
    });
    expect(verify(fx).failures).toContain(
      `checkpoint ${(JSON.parse(readFileSync(join(fx.dir, 'checkpoints.json'), 'utf8')) as { checkpoints: Obj[] }).checkpoints[0]?.checkpoint_hash}: malformed, or not for this ledger`,
    );
  });

  it('a first checkpoint that has a prev_checkpoint fails', () => {
    const fx = make({
      tweakCheckpoint: (cp, i) => {
        if (i === 0) cp.prev_checkpoint = shaHex('earlier');
      },
    });
    const failures = verify(fx).failures;
    expect(failures.some((f) => f.endsWith(': the first checkpoint has a prev_checkpoint'))).toBe(
      true,
    );
  });

  it('a checkpoint that does not grow fails, though link, root and signature are right', () => {
    const fx = make({ sizes: [3, 3, 6] });
    const failures = verify(fx).failures;
    expect(failures).toEqual([expect.stringMatching(/: tree_size does not grow$/)]);
  });

  it('a checkpoint past range.to fails with its own message', () => {
    // Size 9 is out of the range; its root also differs, so look for the range message itself.
    const fx = make({ sizes: [3, 6, 9] });
    expect(verify(fx).failures.some((f) => f.endsWith(': tree_size is outside the range'))).toBe(
      true,
    );
  });

  it('a checkpoint before range.from fails with its own message', () => {
    const fx = make({ from: 4, count: 3, sizes: [3, 6] });
    expect(verify(fx).failures.some((f) => f.endsWith(': tree_size is outside the range'))).toBe(
      true,
    );
  });

  it('a checkpoint dated exactly at its key retirement passes, a millisecond later fails', () => {
    const fx = make();
    const last = fx.checkpoints.at(-1)?.created_at as string;
    expect(verify(fx, keysWith(fx, { retired_at: last })).failures).toEqual([]);
    const before = new Date(Date.parse(last) - 1).toISOString();
    expect(verify(fx, keysWith(fx, { retired_at: before })).failures).toEqual([
      expect.stringMatching(/: dated outside its signing key's window$/),
    ]);
  });

  it('a checkpoint dated exactly when its key began passes, a millisecond earlier fails', () => {
    const fx = make();
    const first = fx.checkpoints[0]?.created_at as string;
    expect(verify(fx, keysWith(fx, { created_at: first })).failures).toEqual([]);
    const after = new Date(Date.parse(first) + 1).toISOString();
    expect(verify(fx, keysWith(fx, { created_at: after })).failures).toEqual([
      expect.stringMatching(/: dated outside its signing key's window$/),
    ]);
  });

  it('a bundle with no checkpoints fails', () => {
    const fx = make();
    editJson(fx, 'checkpoints.json', (c) => {
      c.checkpoints = [];
    });
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toEqual(['the last checkpoint is not at the end of the range']);
  });
});

describe('what a truncated or relabelled bundle shows', () => {
  it('a bundle cut to an earlier checkpoint, range.to lowered to match, passes by itself', () => {
    // The bundle proves only the rows it holds. That it stops early is for --extends or a
    // bundle kept from before to show (README: "does not prove that the range is the whole history").
    const full = make({ count: 6, sizes: [3, 6] });
    const cut = make({ count: 3, sizes: [3], key: full.key });
    expect(verify(cut).verdict).toBe('PASS');
    // ... and --extends of the cut bundle by the full one is what shows the difference.
    const result = verifyBundle(cut.dir, { keys: cut.keysFile, extends: full.dir });
    expect(result.verdict).toBe('FAIL');
  });

  it('a rewritten event with every later row hash redone fails on the root and the signature', () => {
    const fx = make({ count: 6, sizes: [3, 6] });
    const path = join(fx.dir, 'events.ndjson');
    const lines = readFileSync(path, 'utf8').split('\n').slice(0, -1);
    // Rebuild rows 2..6 with another variant: all hashes and links are self-consistent.
    const forged = make({ count: 6, sizes: [3, 6], key: newKey(), variant: 'x' });
    const forgedLines = readFileSync(join(forged.dir, 'events.ndjson'), 'utf8')
      .split('\n')
      .slice(0, -1);
    writeFileSync(path, [lines[0], ...forgedLines.slice(1)].map((l) => `${l}\n`).join(''));
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    // Row 2 is the first forged row: its prev_hash is the forger's, not row 1's.
    expect(result.failures).toContain('seq 2: prev_hash is not the row before');
    expect(result.failures.some((f) => f.endsWith(': root does not match the events'))).toBe(true);
  });

  it('every later row redone and linked still fails on the root', () => {
    const fx = make({ count: 6, sizes: [3, 6], variant: '' });
    // The same rows in a second bundle with a different variant from seq 1: fully linked.
    const forged = make({ count: 6, sizes: [3, 6], key: fx.key, variant: 'x' });
    writeFileSync(
      join(fx.dir, 'events.ndjson'),
      readFileSync(join(forged.dir, 'events.ndjson'), 'utf8'),
    );
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures.every((f) => f.endsWith(': root does not match the events'))).toBe(true);
    expect(result.failures).toHaveLength(2);
  });
});

describe('inputs an attacker would try', () => {
  it('a repeated event line fails on seq and on the count', () => {
    const fx = make();
    const path = join(fx.dir, 'events.ndjson');
    const lines = readFileSync(path, 'utf8').split('\n').slice(0, -1);
    lines.splice(2, 0, lines[1] ?? '');
    writeFileSync(path, lines.map((l) => `${l}\n`).join(''));
    const result = verify(fx);
    expect(result.verdict).toBe('FAIL');
    expect(result.failures).toContain('seq 2: seq is not 3');
    expect(result.failures).toContain(
      'manifest: event_count does not match the range and the events',
    );
  });

  it('a number written as 2.0 is not canonical, though it parses to the integer 2', () => {
    const fx = make();
    const path = join(fx.dir, 'events.ndjson');
    const text = readFileSync(path, 'utf8');
    expect(text).toContain('"n":2,');
    writeFileSync(path, text.replace('"n":2,', '"n":2.0,'));
    expect(verify(fx).failures).toContain('seq 2: line is not canonical JSON');
  });

  it('trusts the keys file alone: a bundle signed by a key only its own manifest lists fails', () => {
    const fx = make({ key: newKey() });
    const other = make();
    // The auditor's file names a different key than the one that signed.
    const result = verifyBundle(fx.dir, { keys: other.keysFile });
    expect(result.verdict).toBe('FAIL');
    expect(result.failures.some((f) => f.endsWith(': signing key is not trusted'))).toBe(true);
  });

  it('ignores a key in the keys file that signed nothing in the bundle', () => {
    const fx = make();
    const path = join(dirname(fx.dir), 'two-keys.json');
    writeFileSync(
      path,
      JSON.stringify([
        ...fx.keys,
        {
          public_key: newKey().publicKey,
          created_at: '2026-01-01T00:00:00.000Z',
          retired_at: null,
        },
      ]),
    );
    expect(verify(fx, path).verdict).toBe('PASS');
  });
});
