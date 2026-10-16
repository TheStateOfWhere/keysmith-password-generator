import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizePolicy, analyzePolicy, countValidPasswords, countCompletions, assessEntropy,
  AMBIGUOUS_CHARACTERS, MAX_POLICY_LENGTH, MAX_POLICY_RAW_INPUT_LENGTH, CATEGORIES } from '../dist/policy.js';
import { DEFAULTS, generatePassword, PROHIBITED } from '../dist/core.js';
import { generateProfilePassword, UnsupportedProfileError } from '../dist/profiles.js';

const ids = ['uppercase', 'lowercase', 'digits', 'symbols'];
const lettersDigits = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const zero = () => ({ uppercase: 0, lowercase: 0, digits: 0, symbols: 0 });
function input(overrides = {}) {
  return { length: 20, allowed: { uppercase: true, lowercase: true, digits: true, symbols: true },
    minimumCounts: { uppercase: 1, lowercase: 1, digits: 1, symbols: 1 },
    permittedSymbols: '-_@#%*+', excludedCharacters: '', excludeAmbiguous: true, ...overrides };
}
function small(alphabet, length, minima = zero()) {
  return input({ length, minimumCounts: minima, excludeAmbiguous: false,
    permittedSymbols: [...alphabet].filter(c => !/[A-Za-z0-9]/.test(c)).join(''),
    excludedCharacters: [...lettersDigits].filter(c => !alphabet.includes(c)).join('') });
}
function policy(value) {
  const result = normalizePolicy(value);assert.equal(result.ok, true);return result.policy;
}
function category(c) { return /[A-Z]/.test(c) ? 'uppercase' : /[a-z]/.test(c) ? 'lowercase' : /[0-9]/.test(c) ? 'digits' : 'symbols'; }
function enumerate(alphabet, length, minima) {
  let total = 0n;
  function walk(remaining, counts) {
    if (!remaining) { if (ids.every(id => counts[id] >= minima[id])) total++; return; }
    for (const c of alphabet) walk(remaining - 1, { ...counts, [category(c)]: counts[category(c)] + 1 });
  }
  walk(length, zero());return total;
}
const factorial = n => { let value = 1n;for (let i = 2n; i <= BigInt(n); i++) value *= i;return value; };
function hasError(value, code, field) {
  const result = normalizePolicy(value);assert.equal(result.ok, false);
  assert.ok(result.errors.some(e => e.code === code && (!field || e.field === field)));
  for (const e of result.errors) { assert.equal(typeof e.message, 'string');assert.ok(e.message.length > 0); }
}

test('policy counts match exhaustive enumeration for small alphabets and category minima', () => {
  const minima = [zero(), { ...zero(), uppercase: 1 }, { ...zero(), uppercase: 2 },
    { ...zero(), lowercase: 2, digits: 1 }, { uppercase: 1, lowercase: 1, digits: 1, symbols: 1 },
    { ...zero(), symbols: 2 }];
  for (const alphabet of ['AB', 'Aa', '2!', 'Aa2!', 'Aab2!']) for (let length = 1; length <= 5; length++) for (const required of minima) {
    const expected = enumerate(alphabet, length, required);
    const result = normalizePolicy(small(alphabet, length, required));
    assert.equal(result.ok ? countValidPasswords(result.policy) : 0n, expected);
    if (expected > 0n) assert.equal(result.ok, true);
  }
});

test('category minima allow additional category characters; allowed does not mean required', () => {
  assert.equal(countValidPasswords(policy(small('A!', 3))), 8n);
  assert.equal(countValidPasswords(policy(small('A!', 3, { ...zero(), uppercase: 1 }))), 7n);
  assert.equal(countValidPasswords(policy(small('A!', 3, { ...zero(), uppercase: 2 }))), 4n);
  assert.equal(countValidPasswords(policy(small('A!', 3, { ...zero(), uppercase: 1, symbols: 1 }))), 6n);
});

test('duplicates normalize once without alphabet or entropy inflation', () => {
  const plain = policy(input({ permittedSymbols: '!@', excludedCharacters: 'AB', excludeAmbiguous: false }));
  const duplicated = policy(input({ permittedSymbols: '@!!!@@', excludedCharacters: 'AABABB', excludeAmbiguous: false }));
  assert.equal(duplicated.permittedSymbols, '!@');assert.equal(duplicated.excludedCharacters, 'AB');
  assert.equal(new Set(duplicated.alphabet).size, duplicated.alphabet.length);
  assert.equal(duplicated.alphabet, plain.alphabet);assert.equal(countValidPasswords(duplicated), countValidPasswords(plain));
});

test('symbol letters/digits and overlapping category attempts are explicitly rejected', () => {
  for (const symbols of ['A!', 'a!', '0!', 'AAaa00']) hasError(input({ permittedSymbols: symbols }), 'SYMBOL_CATEGORY_OVERLAP', 'permittedSymbols');
  // An excluded letter may not be reintroduced through the symbol field.
  hasError(input({ permittedSymbols: 'l!', excludedCharacters: 'l' }), 'SYMBOL_CATEGORY_OVERLAP');
});

test('global exclusions apply after every allowed category is constructed', () => {
  const result = policy(input({ excludedCharacters: 'Aa2-@', excludeAmbiguous: false }));
  for (const c of 'Aa2-@') assert.ok(!result.alphabet.includes(c));
  for (const group of result.categories) for (const c of 'Aa2-@') assert.ok(!group.characters.includes(c));
  assert.equal(result.minimumCounts.uppercase, 1);assert.equal(result.allowed.uppercase, true);
});

test('ambiguous exclusions preserve the exact Readable set and are explicit', () => {
  assert.equal([...AMBIGUOUS_CHARACTERS].sort().join(''), [...lettersDigits].filter(c => PROHIBITED.test(c)).sort().join(''));
  const excluded = policy(input());const allowed = policy(input({ excludeAmbiguous: false }));
  for (const c of AMBIGUOUS_CHARACTERS) { assert.ok(!excluded.alphabet.includes(c));assert.ok(allowed.alphabet.includes(c)); }
  assert.ok(countValidPasswords(excluded) < countValidPasswords(allowed));
});

test('normalization is immutable and never modifies requested settings', () => {
  assert.equal(Object.isFrozen(CATEGORIES), true);
  assert.throws(() => { CATEGORIES.push('other'); }, TypeError);
  const value = input({ permittedSymbols: '@@!!' });const original = JSON.stringify(value);const result = policy(value);
  assert.equal(JSON.stringify(value), original);
  for (const object of [result, result.allowed, result.minimumCounts, result.categories, ...result.categories]) assert.equal(Object.isFrozen(object), true);
  assert.throws(() => { result.minimumCounts.uppercase = 0; }, TypeError);
  assert.throws(() => { result.categories[0].characters = '!'; }, TypeError);
});

test('printable ASCII includes explicit space while controls and Unicode are rejected', () => {
  const result = policy(input({ permittedSymbols: ' !' }));assert.ok(result.alphabet.includes(' '));
  for (const c of ['\n', '\r', '\t', '\0', String.fromCharCode(127), 'é', '😀']) {
    hasError(input({ permittedSymbols: '!' + c }), 'INVALID_SYMBOLS');
    hasError(input({ excludedCharacters: c }), 'INVALID_EXCLUSIONS');
  }
});

test('length limits and exact JSON-like input types fail closed', () => {
  for (const length of [0, -1, 129, 1.5, NaN, Infinity, '20', true]) hasError(input({ length }), 'INVALID_LENGTH');
  for (const value of [null, false, [], {}, { ...input(), regex: 'unapproved' }]) hasError(value, 'INVALID_POLICY');
  for (const value of ['false', 0, null]) hasError(input({ excludeAmbiguous: value }), 'INVALID_AMBIGUOUS');
  for (const value of ['true', 1, null]) hasError(input({ allowed: { ...input().allowed, digits: value } }), 'INVALID_ALLOWED');
  for (const value of [null, false, 'all', {}, { ...input().allowed, other: true }]) hasError(input({ allowed: value }), 'INVALID_ALLOWED');
  for (const value of [false, [], {}]) hasError(input({ minimumCounts: value }), 'INVALID_MINIMUM');
});

test('required counts must be explicit nonnegative integers and supported categories only', () => {
  for (const value of [-1, 129, 1.5, NaN, Infinity, '1', true]) hasError(input({ minimumCounts: { ...zero(), uppercase: value } }), 'INVALID_MINIMUM', 'minimumCounts.uppercase');
  hasError(input({ minimumCounts: { ...zero(), other: 1 } }), 'INVALID_MINIMUM');
  const missing = { ...zero() };delete missing.digits;hasError(input({ minimumCounts: missing }), 'INVALID_MINIMUM');
});

test('disabled required categories and exclusions removing required groups are actionable errors', () => {
  hasError(input({ allowed: { ...input().allowed, digits: false } }), 'DISABLED_REQUIRED_CATEGORY', 'minimumCounts.digits');
  hasError(input({ excludedCharacters: '0123456789' }), 'EMPTY_REQUIRED_CATEGORY', 'minimumCounts.digits');
  hasError(input({ permittedSymbols: '' }), 'EMPTY_REQUIRED_CATEGORY', 'minimumCounts.symbols');
  hasError(input({ permittedSymbols: '!!!', excludedCharacters: '!' }), 'EMPTY_REQUIRED_CATEGORY', 'minimumCounts.symbols');
});

test('empty alphabets and sum-of-minima contradictions stop before analysis', () => {
  hasError(input({ allowed: { uppercase: false, lowercase: false, digits: false, symbols: false }, minimumCounts: zero() }), 'EMPTY_ALPHABET');
  hasError(small('', 20), 'EMPTY_ALPHABET');
  hasError(input({ length: 3 }), 'INSUFFICIENT_LENGTH', 'length');
  assert.equal(analyzePolicy(input({ length: 3 })).kind, 'invalid');
});

test('insufficient entropy does not silently change a feasible policy', () => {
  const value = small('A', 128);const result = analyzePolicy(value);
  assert.equal(result.kind, 'ineligible');assert.equal(result.validPasswordCount, 1n);
  assert.equal(result.entropy.estimatedBitsText, '0.00');assert.equal(result.policy.length, 128);
  assert.ok(result.errors.some(e => e.code === 'INSUFFICIENT_ENTROPY'));
});

test('exact 64-bit boundary is enforced even when floating-point conversion loses the distinction', () => {
  const threshold = 1n << 64n;
  const at = analyzePolicy(small('Aa', 64));
  const below = analyzePolicy(small('Aa', 64, { ...zero(), uppercase: 1 }));
  assert.equal(at.validPasswordCount, threshold);assert.equal(at.kind, 'eligible');
  assert.equal(at.entropy.estimatedBitsText, '64.00');
  assert.equal(below.validPasswordCount, threshold - 1n);assert.equal(below.kind, 'ineligible');
  assert.equal(Number(below.validPasswordCount), Number(threshold));
  assert.equal(below.entropy.estimatedBitsText, '63.99');
  assert.equal(assessEntropy(threshold + 1n).meetsMinimum, true);
});

test('entropy estimates are exact downward decimal bounds and eligibility uses integers only', () => {
  for (const count of [1n, 2n, 3n, 7n, 8n, 999n, (1n << 64n) - 1n, 1n << 64n, 95n ** 128n]) {
    const result = assessEntropy(count);const hundredths = Number(result.estimatedBitsText.replace('.', ''));
    const powered = count ** 100n;
    assert.ok((1n << BigInt(hundredths)) <= powered);
    assert.ok((1n << BigInt(hundredths + 1)) > powered);
    assert.equal(result.meetsMinimum, count >= (1n << 64n));
    assert.match(result.description, /rounded down.*uniform sampling.*Not an offline-attack guarantee/);
  }
  for (const count of [0n, -1n, 2 ** 64, (95n ** 128n) + 1n]) assert.throws(() => assessEntropy(count), RangeError);
});

test('completion counts partition the full space by the next character category', () => {
  for (const value of [small('Aa2!', 4, { uppercase: 1, lowercase: 1, digits: 1, symbols: 1 }), small('Aab!', 6, { ...zero(), uppercase: 2, symbols: 1 })]) {
    const p = policy(value);let sum = 0n;
    for (const group of p.categories) {
      const remaining = { ...p.minimumCounts, [group.id]: Math.max(0, p.minimumCounts[group.id] - 1) };
      sum += BigInt(group.characters.length) * countCompletions(p, p.length - 1, remaining);
    }
    assert.equal(sum, countValidPasswords(p));
  }
});

test('terminal and impossible suffix completions are exact and counting arguments remain bounded', () => {
  const p = policy(small('Aa', 4, { ...zero(), uppercase: 2 }));
  assert.equal(countCompletions(p, 0, zero()), 1n);
  assert.equal(countCompletions(p, 0), 0n);assert.equal(countCompletions(p, 1), 0n);
  for (const length of [-1, 5, 129, Infinity, 1.5, '1']) assert.throws(() => countCompletions(p, length), RangeError);
  for (const minima of [{ ...zero(), uppercase: 3 }, { ...zero(), uppercase: -1 }, { ...zero(), uppercase: '1' }, {}]) assert.throws(() => countCompletions(p, 2, minima), RangeError);
  assert.throws(() => countValidPasswords({ ...p }), RangeError);
});

test('maximum-length one-per-category count agrees with independent inclusion-exclusion', () => {
  const p = policy(input({ length: MAX_POLICY_LENGTH }));const sizes = p.categories.map(c => BigInt(c.characters.length));
  let expected = 0n;
  for (let mask = 0; mask < 16; mask++) {
    let size = BigInt(p.alphabet.length), parity = 0;
    for (let i = 0; i < 4; i++) if (mask & (1 << i)) { size -= sizes[i];parity++; }
    expected += (parity % 2 ? -1n : 1n) * size ** 128n;
  }
  assert.equal(countValidPasswords(p), expected);
});

test('large category minima use a bounded polynomial count rather than count-state explosion', () => {
  const start = performance.now();
  const p = policy(input({ length: 128, minimumCounts: { uppercase: 32, lowercase: 32, digits: 32, symbols: 32 } }));
  const expected = factorial(128) / (factorial(32) ** 4n) * p.categories.reduce((n, group) => n * BigInt(group.characters.length) ** 32n, 1n);
  assert.equal(countValidPasswords(p), expected);
  const skew = policy(input({ length: 128, minimumCounts: { uppercase: 125, lowercase: 1, digits: 1, symbols: 1 } }));
  const sizes = skew.categories.map(c => BigInt(c.characters.length));
  assert.equal(countValidPasswords(skew), 128n * 127n * 126n * sizes[0] ** 125n * sizes[1] * sizes[2] * sizes[3]);
  assert.ok(performance.now() - start < 2000, 'Bounded 128-character counts must finish in less than two seconds');
});

test('full printable ASCII and length-one boundaries have exact counts', () => {
  const symbols = Array.from({ length: 95 }, (_, i) => String.fromCharCode(i + 32)).filter(c => !/[A-Za-z0-9]/.test(c)).join('');
  const p = policy(input({ length: 128, minimumCounts: zero(), permittedSymbols: symbols, excludeAmbiguous: false }));
  assert.equal(p.alphabet.length, 95);assert.equal(countValidPasswords(p), 95n ** 128n);
  assert.equal(countValidPasswords(policy(small('AB', 1))), 2n);
});

test('policy analysis leaves Readable output and unknown-profile rejection unchanged', () => {
  assert.equal(analyzePolicy(input()).kind, 'eligible');
  const settings = { ...DEFAULTS, suffixLength: 20 };const dictionary = ['abacus', 'banner', 'cactus'];
  const random = () => { let n = 0;return buffer => { buffer[0] = n++ === 22 ? 8 : 0;return buffer; }; };
  const expected = generatePassword(dictionary, settings, random());
  assert.equal(generateProfilePassword({ profile: 'readable', settings }, dictionary, random()), expected);
  assert.throws(() => generateProfilePassword({ profile: 'unknown-public-fixture' }, dictionary), UnsupportedProfileError);
});

test('raw policy limits accept boundary duplicates and the complete ASCII symbol set', () => {
  assert.equal(MAX_POLICY_RAW_INPUT_LENGTH, 256);
  const p = policy(input({ permittedSymbols: '!'.repeat(256), excludedCharacters: '~'.repeat(256) }));
  assert.equal(p.permittedSymbols, '!');assert.equal(p.excludedCharacters.includes('~'), true);
  const symbols = Array.from({ length: 95 }, (_, i) => String.fromCharCode(i + 32)).filter(c => !/[A-Za-z0-9]/.test(c)).join('');
  const full = policy(input({ length: 128, minimumCounts: zero(), permittedSymbols: symbols, excludeAmbiguous: false }));
  assert.equal(full.alphabet.length, 95);assert.equal(countValidPasswords(full), 95n ** 128n);
});

test('oversized fields reject before character iteration without truncation', () => {
  for (const field of ['permittedSymbols', 'excludedCharacters']) for (const length of [257, 16_000_000]) {
    const value = input({ [field]: '!'.repeat(length) });let result, iterations = 0;
    const original = String.prototype[Symbol.iterator];
    try {
      String.prototype[Symbol.iterator] = function () {
        if (this.length > MAX_POLICY_RAW_INPUT_LENGTH) { iterations++;throw Error('Oversized input was iterated'); }
        return original.call(this);
      };
      result = normalizePolicy(value);
    } finally { String.prototype[Symbol.iterator] = original; }
    assert.equal(iterations, 0);assert.equal(result.ok, false);
    assert.ok(result.errors.some(e => e.code === 'RAW_INPUT_TOO_LONG' && e.field === field && /256/.test(e.message)));
    assert.equal(value[field].length, length);
  }
});

test('completion minima reject changing getters without executing them', () => {
  const p = policy(small('Aa', 2, { ...zero(), uppercase: 1 }));let reads = 0;
  const changing = { ...zero() };
  Object.defineProperty(changing, 'uppercase', { enumerable: true, get() { return reads++ < 3 ? 1 : 0; } });
  assert.throws(() => countCompletions(p, 2, changing), RangeError);assert.equal(reads, 0);
  const supplied = { ...zero(), uppercase: 1 };
  assert.equal(countCompletions(p, 2, supplied), 3n);supplied.uppercase = 0;
  assert.equal(countCompletions(p, 2), 3n);assert.equal(countCompletions(p, 2, supplied), 4n);
});

test('completion arguments are captured once and malformed metadata fails closed', () => {
  const p = policy(small('Aa', 2, { ...zero(), uppercase: 1 })), reads = Object.fromEntries(CATEGORIES.map(id => [id, 0]));
  const external = new Proxy({ ...zero(), uppercase: 1 }, { get() { throw Error('Caller property read'); },
    getOwnPropertyDescriptor(target, key) { if (Object.hasOwn(reads, key)) reads[key]++;return Reflect.getOwnPropertyDescriptor(target, key); } });
  assert.equal(countCompletions(p, 2, external), 3n);assert.deepEqual(Object.values(reads), [1, 1, 1, 1]);
  const revoked = Proxy.revocable({}, {});revoked.revoke();
  for (const value of [revoked.proxy, [], { ...zero(), extra: 0 }, Object.create({ uppercase: 1 }),
    { ...zero(), uppercase: NaN }, { ...zero(), uppercase: Infinity }, { ...zero(), uppercase: '1' }])
    assert.throws(() => countCompletions(p, 2, value), RangeError);
  assert.throws(() => countCompletions(revoked.proxy, 2), RangeError);
});

test('revoked root and nested policy proxies produce structured failures', () => {
  const revoked = Proxy.revocable({}, {});revoked.revoke();
  for (const [value, code] of [[revoked.proxy, 'INVALID_POLICY'], [input({ allowed: revoked.proxy }), 'INVALID_ALLOWED'],
    [input({ minimumCounts: revoked.proxy }), 'INVALID_MINIMUM']]) {
    const result = normalizePolicy(value);assert.equal(result.ok, false);assert.ok(result.errors.some(e => e.code === code));
    assert.equal(analyzePolicy(value).kind, 'invalid');
  }
});

test('arrays, array-like records and throwing descriptor traps are structured invalid inputs', () => {
  for (const value of [[], { 0: input(), length: 1 }, new Proxy({}, { getPrototypeOf() { throw Error('Public malformed metadata'); } })])
    hasError(value, 'INVALID_POLICY');
  hasError(input({ allowed: { 0: true, length: 1 } }), 'INVALID_ALLOWED');
  hasError(input({ minimumCounts: [1, 1, 1, 1] }), 'INVALID_MINIMUM');
});
