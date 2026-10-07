import { describe, expect, it } from 'vitest';
import { canonicalJsonV2 } from './canonical.js';

describe('canonicalJsonV2', () => {
  it('writes known vectors', () => {
    expect(canonicalJsonV2(null)).toBe('null');
    expect(canonicalJsonV2(true)).toBe('true');
    expect(canonicalJsonV2(false)).toBe('false');
    expect(canonicalJsonV2(0)).toBe('0');
    expect(canonicalJsonV2(-12)).toBe('-12');
    expect(canonicalJsonV2(Number.MAX_SAFE_INTEGER)).toBe('9007199254740991');
    expect(canonicalJsonV2('a"b\\c\n')).toBe('"a\\"b\\\\c\\n"');
    expect(canonicalJsonV2('é\u{1f600}')).toBe('"é\u{1f600}"');
    expect(canonicalJsonV2({ b: 1, a: [true, null, 'x'] })).toBe('{"a":[true,null,"x"],"b":1}');
    expect(canonicalJsonV2({})).toBe('{}');
    expect(canonicalJsonV2([])).toBe('[]');
  });

  it('sorts keys by UTF-16 code units, at every depth', () => {
    // U+FFFF (one unit, 0xFFFF) sorts after U+1F600 (surrogate pair, first unit 0xD83D).
    expect(canonicalJsonV2({ '￿': 1, '\u{1f600}': 2, B: 3, a: 4, '': 5 })).toBe(
      '{"":5,"B":3,"a":4,"\u{1f600}":2,"￿":1}',
    );
    expect(canonicalJsonV2({ z: { y: 1, x: [{ d: 1, c: 2 }] } })).toBe(
      '{"z":{"x":[{"c":2,"d":1}],"y":1}}',
    );
  });

  it('keeps array order', () => {
    expect(canonicalJsonV2([3, 1, 2])).toBe('[3,1,2]');
  });

  it('writes -0 as 0', () => {
    expect(canonicalJsonV2(-0)).toBe('0');
    expect(canonicalJsonV2({ n: -0 })).toBe('{"n":0}');
  });

  it('refuses a float, NaN, Infinity and an unsafe integer', () => {
    expect(() => canonicalJsonV2(1.5)).toThrow(/safe integers only/);
    expect(() => canonicalJsonV2({ a: [0.1] })).toThrow(/safe integers only/);
    expect(() => canonicalJsonV2(Number.NaN)).toThrow(/safe integers only/);
    expect(() => canonicalJsonV2(Number.POSITIVE_INFINITY)).toThrow(/safe integers only/);
    expect(() => canonicalJsonV2(2 ** 53)).toThrow(/safe integers only/);
    expect(() => canonicalJsonV2(-(2 ** 53))).toThrow(/safe integers only/);
  });

  it('refuses a lone surrogate in a string or a key', () => {
    expect(() => canonicalJsonV2('\ud800')).toThrow(/lone surrogate/);
    expect(() => canonicalJsonV2(['ok', { a: 'x\udc00y' }])).toThrow(/lone surrogate/);
    expect(() => canonicalJsonV2({ '\ud800': 1 })).toThrow(/lone surrogate/);
  });

  it('refuses undefined and other non-JSON values', () => {
    expect(() => canonicalJsonV2(undefined)).toThrow(/undefined/);
    expect(() => canonicalJsonV2({ a: undefined })).toThrow(/undefined/);
    expect(() => canonicalJsonV2([1, undefined])).toThrow(/undefined/);
    expect(() => canonicalJsonV2(() => 1)).toThrow(/function/);
    expect(() => canonicalJsonV2(1n)).toThrow(/bigint/);
  });
});
