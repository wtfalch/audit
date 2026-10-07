// `String#isWellFormed` is ES2024; the package compiles to ES2022. A surrogate half with no partner.
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const isWellFormed = (s: string): boolean => !LONE_SURROGATE.test(s);

/**
 * Canonical JSON, version 2: RFC 8785, restricted to what a hash needs and a
 * second program can reproduce byte for byte. `null`, booleans, strings,
 * arrays and objects as JSON writes them; keys sorted by UTF-16 code units
 * (the default `Array#sort`), no whitespace. A number must be a safe integer
 * (`-0` writes `0`): a float has no one spelling across languages, so it is
 * refused rather than guessed at. A string that is not well formed (a lone
 * surrogate) and `undefined` anywhere are refused too.
 *
 * Throws; never returns a string it would not hash the same way twice.
 */
export function canonicalJsonV2(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) {
        throw new Error(`audit: canonical JSON v2 takes safe integers only, got ${value}`);
      }
      // String(-0) is '0', which is what RFC 8785 writes.
      return String(value);
    case 'string':
      if (!isWellFormed(value)) {
        throw new Error('audit: canonical JSON v2 refuses a string with a lone surrogate');
      }
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(canonicalJsonV2).join(',')}]`;
      const obj = value as Record<string, unknown>;
      const parts = Object.keys(obj)
        .sort()
        .map((key) => {
          if (!isWellFormed(key)) {
            throw new Error('audit: canonical JSON v2 refuses a key with a lone surrogate');
          }
          return `${JSON.stringify(key)}:${canonicalJsonV2(obj[key])}`;
        });
      return `{${parts.join(',')}}`;
    }
    default:
      throw new Error(`audit: canonical JSON v2 cannot write a ${typeof value}`);
  }
}
