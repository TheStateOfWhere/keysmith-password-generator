import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { normalizePolicy, countValidPasswords, buildPolicyCountingTable } from '../dist/policy.js';
import { randomBigIntBelow, passwordAtRank, validatePolicyPassword, prepareRandomPasswordGenerator,
  generateRandomPassword, PolicyGenerationError } from '../dist/random-password.js';
import { generateProfilePassword, STRONG_RANDOM_DEFAULTS } from '../dist/profiles.js';

const ids = ['uppercase', 'lowercase', 'digits', 'symbols'];
const alphanumerics = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const zero = () => ({ uppercase: 0, lowercase: 0, digits: 0, symbols: 0 });
const input = (override = {}) => ({ length: 20, allowed: { uppercase: true, lowercase: true, digits: true, symbols: true },
  minimumCounts: { uppercase: 1, lowercase: 1, digits: 1, symbols: 1 }, permittedSymbols: '-_@#%*+',
  excludedCharacters: '', excludeAmbiguous: true, ...override });
function small(alphabet, length, minimumCounts = zero()) {
  return input({ length, minimumCounts, excludeAmbiguous: false,
    permittedSymbols: [...alphabet].filter(c => !/[A-Za-z0-9]/.test(c)).join(''),
    excludedCharacters: [...alphanumerics].filter(c => !alphabet.includes(c)).join('') });
}
function norm(value) { const r = normalizePolicy(value);assert.equal(r.ok, true);return r.policy; }
const category = c => /[A-Z]/.test(c) ? 'uppercase' : /[a-z]/.test(c) ? 'lowercase' : /[0-9]/.test(c) ? 'digits' : 'symbols';
function enumerate(alphabet, length, minima) {
  const result = [];
  function walk(prefix, counts) {
    if (prefix.length === length) { if (ids.every(id => counts[id] >= minima[id])) result.push(prefix);return; }
    for (const c of alphabet) walk(prefix + c, { ...counts, [category(c)]: counts[category(c)] + 1 });
  }
  walk('', zero());return result.sort();
}
function bytesForRank(rank, byteLength) {
  const bytes = new Uint8Array(byteLength);
  for (let i = byteLength - 1; i >= 0; i--) { bytes[i] = Number(rank & 255n);rank >>= 8n; }
  assert.equal(rank, 0n);return bytes;
}
function sourceForRank(rank) {
  return buffer => { buffer.set(bytesForRank(rank, buffer.length));return buffer; };
}

test('every small-space rank maps bijectively to exactly the independently enumerated valid strings', () => {
  const minima = [zero(), { ...zero(), uppercase: 1 }, { ...zero(), uppercase: 2 },
    { ...zero(), symbols: 1 }, { uppercase: 1, lowercase: 1, digits: 1, symbols: 1 }];
  for (const alphabet of ['AB', 'Aa', 'A2!', 'Aa2!']) for (let length = 1; length <= 4; length++) for (const required of minima) {
    const expected = enumerate(alphabet, length, required), r = normalizePolicy(small(alphabet, length, required));
    if (!expected.length) { assert.equal(r.ok, false);continue; }
    const actual = [];
    for (let rank = 0n; rank < countValidPasswords(r.policy); rank++) {
      const value = passwordAtRank(r.policy, rank);assert.equal(validatePolicyPassword(value, r.policy), true);actual.push(value);
    }
    assert.equal(new Set(actual).size, expected.length);assert.deepEqual(actual.sort(), expected);
  }
});

test('rank selection is exactly uniform over all accepted two-byte controlled draw pairs', () => {
  const counts = Array(5).fill(0);
  for (let first = 0; first < 256; first++) for (let second = 0; second < 256; second++) {
    if ((first & 7) >= 5 && (second & 7) >= 5) continue;
    let draws = 0;
    const rank = randomBigIntBelow(5n, buffer => { assert.equal(buffer.length, 1);buffer[0] = draws++ ? second : first;return buffer; });
    counts[Number(rank)]++;
    assert.equal(draws, (first & 7) < 5 ? 1 : 2);
  }
  assert.deepEqual(counts, Array(5).fill(11264));
});

test('rejection boundaries and high-bit masking do not use modulo reduction', () => {
  const draws = [255, 10, 9];let n = 0;
  assert.equal(randomBigIntBelow(10n, buffer => { buffer[0] = draws[n++];return buffer; }), 9n);assert.equal(n, 3);
  assert.equal(randomBigIntBelow(256n, buffer => { buffer[0] = 255;return buffer; }), 255n);
  assert.equal(randomBigIntBelow(257n, buffer => { buffer.set([255, 0]);return buffer; }), 256n);
  assert.equal(randomBigIntBelow(1n, () => { throw Error('Singleton consumed randomness'); }), 0n);
  for (const bound of [0n, -1n, 10, 95n ** 128n + 1n]) assert.throws(() => randomBigIntBelow(bound), RangeError);
});

test('multi-byte ranks retain bits above the JavaScript Number precision limit', () => {
  const bound = (1n << 80n) + 17n, target = (1n << 79n) + 11n;
  assert.equal(randomBigIntBelow(bound, sourceForRank(target)), target);
});

test('failed random providers and repeated rejections fail closed without fallback', () => {
  let calls = 0;
  assert.throws(() => randomBigIntBelow(5n, buffer => { calls++;buffer.fill(255);return buffer; }), /rejection limit/);
  assert.equal(calls, 128);
  assert.throws(() => randomBigIntBelow(5n, () => new Uint8Array(1)), /unexpected buffer/);
  const failure = new Error('Public provider failure');
  assert.throws(() => randomBigIntBelow(5n, () => { throw failure; }), error => error === failure);
});

test('production generation selects one exact rank and validates its complete mapped output', () => {
  const generator = prepareRandomPasswordGenerator(input());
  for (const rank of [0n, 1n, generator.validPasswordCount / 2n, generator.validPasswordCount - 1n]) {
    let calls = 0;
    const value = generator.generate(buffer => { calls++;return sourceForRank(rank)(buffer); });
    assert.equal(calls, 1);assert.equal(value, passwordAtRank(generator.policy, rank));
    assert.equal(validatePolicyPassword(value, generator.policy), true);
  }
});

test('required categories are minima and extra category characters remain reachable', () => {
  const p = norm(small('A!', 3, { ...zero(), uppercase: 2 }));
  const values = Array.from({ length: Number(countValidPasswords(p)) }, (_, i) => passwordAtRank(p, BigInt(i)));
  assert.ok(values.includes('AAA'));assert.equal(values.length, 4);
});

test('exclusions apply across every category and cannot be introduced via duplicated symbols', () => {
  const generator = prepareRandomPasswordGenerator(input({ excludedCharacters: 'Aa2-@', permittedSymbols: '--__@@##%%**++' }));
  for (const rank of [0n, generator.validPasswordCount / 2n, generator.validPasswordCount - 1n]) {
    const value = generator.generate(sourceForRank(rank));
    assert.ok(!/[Aa2@lLiIoO01-]/.test(value));assert.equal(validatePolicyPassword(value, generator.policy), true);
  }
});

test('invalid, impossible and below-entropy policies reject before consuming randomness', () => {
  let calls = 0;const random = buffer => { calls++;return buffer; };
  for (const value of [null, {}, input({ length: 0 }), input({ length: 129 }), input({ length: 3 }),
    input({ permittedSymbols: 'A!' }), input({ excludedCharacters: '0123456789' }),
    small('Aa', 64, { ...zero(), uppercase: 1 }), small('A', 128), input({ excludeAmbiguous: 'false' })]) {
    assert.throws(() => generateRandomPassword(value, random), PolicyGenerationError);
    assert.equal(calls, 0);
  }
  assert.equal(generateRandomPassword(small('Aa', 64), sourceForRank(0n)).length, 64);
});

test('serialized raw policies are re-normalized while fabricated analysis/normalized records are rejected', () => {
  const raw = input(), copied = JSON.parse(JSON.stringify(raw));
  assert.equal(generateRandomPassword(raw, sourceForRank(0n)), generateRandomPassword(copied, sourceForRank(0n)));
  const p = norm(raw);
  for (const fake of [{ ...p }, { ...raw, eligible: true, validPasswordCount: '99999999999999999999' }]) {
    assert.throws(() => generateRandomPassword(fake, () => { throw Error('Untrusted record consumed randomness'); }), PolicyGenerationError);
  }
  assert.throws(() => passwordAtRank({ ...p }, 0n), RangeError);
});

test('accessor policy fields cannot swap alphabets/minima after validation', () => {
  const raw = input();let calls = 0;
  Object.defineProperty(raw, 'permittedSymbols', { enumerable: true, get() { calls++;return calls === 1 ? '!' : 'A'; } });
  assert.throws(() => generateRandomPassword(raw), PolicyGenerationError);assert.equal(calls, 0);
  const nested = input();Object.defineProperty(nested.minimumCounts, 'uppercase', { enumerable: true, get() { calls++;return 0; } });
  assert.throws(() => generateRandomPassword(nested), PolicyGenerationError);assert.equal(calls, 0);
});

test('final validator rejects wrong length, forbidden characters and missing minimum counts', () => {
  const p = norm(small('Aa2!', 4, { uppercase: 1, lowercase: 1, digits: 1, symbols: 1 }));
  assert.equal(validatePolicyPassword('Aa2!', p), true);
  for (const value of ['Aa2', 'Aa2!!', 'AAA!', 'Aa0!', 'Aa2\n', 'Aa2😀', null]) assert.equal(validatePolicyPassword(value, p), false);
  assert.equal(validatePolicyPassword('Aa2!', { ...p }), false);
});

test('invalid rank inputs and tampered counting tables cannot bypass the mapping interface', () => {
  const p = norm(small('Aa', 2));
  for (const rank of [-1n, 4n, 1, null]) assert.throws(() => passwordAtRank(p, rank), RangeError);
  const table = buildPolicyCountingTable(p);
  for (const object of [table, table.levels, table.powers, table.binomial, ...table.levels, ...table.powers, ...table.binomial]) assert.equal(Object.isFrozen(object), true);
  assert.throws(() => { table.levels[4][2] = 100n; }, TypeError);
});

test('prepared handles retain only immutable public counting state and support repeated independent draws', () => {
  const raw = input(), generator = prepareRandomPasswordGenerator(raw);
  raw.length = 1;raw.allowed.uppercase = false;raw.minimumCounts.uppercase = 0;
  assert.equal(Object.isFrozen(generator), true);assert.deepEqual(Object.keys(generator).sort(), ['generate', 'policy', 'validPasswordCount']);
  let calls = 0;const random = buffer => { calls++;buffer.fill(0);return buffer; };
  const first = generator.generate(random), second = generator.generate(random);
  assert.equal(calls, 2);assert.equal(first, second);assert.equal(first.length, 20);
  assert.equal(validatePolicyPassword(first, generator.policy), true);
});

test('default browser crypto uses byte buffers and missing crypto never falls back', () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  let calls = 0;
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { getRandomValues(buffer) {
      assert.ok(buffer instanceof Uint8Array);calls++;buffer.fill(0);return buffer;
    } } });
    assert.equal(generateRandomPassword(input()).length, 20);assert.equal(calls, 1);
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    assert.throws(() => generateRandomPassword(input()), /Secure browser randomness is unavailable/);
  } finally { if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor);else delete globalThis.crypto; }
});

test('final validation failure exposes no partial password', async () => {
  let source = await readFile(new URL('../dist/random-password.js', import.meta.url), 'utf8');
  for (const name of ['core', 'policy']) source = source.replace("'./" + name + ".js'", JSON.stringify(new URL('../dist/' + name + '.js', import.meta.url).href));
  const target = 'const password = decode(4, table.policy.length, initialRank);';assert.ok(source.includes(target));
  source = source.replace(target, "const password = 'invalid-public-fixture';");
  const injected = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.throws(() => injected.generateRandomPassword(input(), sourceForRank(0n)), /failed final policy validation/);
});

test('Strong Random dispatcher defaults and enabled-category requirements are enforced', () => {
  const dictionary = new Proxy([], { get() { throw Error('Random profile touched dictionary'); } });
  const value = generateProfilePassword({ profile: 'strong-random' }, dictionary, sourceForRank(0n));
  assert.equal(value.length, 20);assert.ok(!/[lLiIoO01]/.test(value));
  for (const pattern of [/[A-Z]/, /[a-z]/, /[2-9]/, /[-_@#%*+]/]) assert.ok(pattern.test(value));
  const settings = { ...STRONG_RANDOM_DEFAULTS, length: 64, allowed: { uppercase: true, lowercase: true, digits: false, symbols: false } };
  const changed = generateProfilePassword({ profile: 'strong-random', settings }, dictionary, sourceForRank(0n));
  assert.match(changed, /^[A-Za-z]{64}$/);assert.ok(/[A-Z]/.test(changed) && /[a-z]/.test(changed));
});

test('Custom Policy dispatcher preserves counts and literal symbols, including optional explicit space', () => {
  const settings = input({ length: 64, minimumCounts: { uppercase: 8, lowercase: 9, digits: 10, symbols: 11 }, permittedSymbols: ' ![]\\' });
  const value = generateProfilePassword({ profile: 'custom-policy', settings }, [], sourceForRank(0n));
  assert.equal(validatePolicyPassword(value, norm(settings)), true);
});

test('dispatcher rejects malformed settings, overrides and weak policies before random consumption', () => {
  const random = () => { throw Error('Invalid settings consumed randomness'); };
  for (const settings of [null, {}, { ...STRONG_RANDOM_DEFAULTS, minimumCounts: zero() },
    { ...STRONG_RANDOM_DEFAULTS, allowed: { ...STRONG_RANDOM_DEFAULTS.allowed, symbols: 'false' } },
    { ...STRONG_RANDOM_DEFAULTS, length: 3 }, { ...STRONG_RANDOM_DEFAULTS, excludedCharacters: alphanumerics + '-_@#%*+' }]) {
    assert.throws(() => generateProfilePassword({ profile: 'strong-random', settings }, [], random), PolicyGenerationError);
  }
  assert.throws(() => generateProfilePassword({ profile: 'custom-policy' }, [], random), PolicyGenerationError);
  const proxy = new Proxy({}, { ownKeys() { throw new Error('Untrusted fixture exception'); } });
  assert.throws(() => generateProfilePassword({ profile: 'strong-random', settings: proxy }, [], random), PolicyGenerationError);
});

test('worst constrained and maximum-length outputs all pass final validation', () => {
  for (const minima of [{ uppercase: 16, lowercase: 16, digits: 16, symbols: 16 },
    { uppercase: 32, lowercase: 32, digits: 32, symbols: 32 }, { uppercase: 125, lowercase: 1, digits: 1, symbols: 1 }]) {
    const generator = prepareRandomPasswordGenerator(input({ length: 128, minimumCounts: minima }));
    for (const rank of [0n, generator.validPasswordCount / 2n, generator.validPasswordCount - 1n]) {
      const value = generator.generate(sourceForRank(rank));assert.equal(value.length, 128);assert.equal(validatePolicyPassword(value, generator.policy), true);
    }
  }
});

test('repeated maximum-length generation reuses public tables without expensive recounting', () => {
  const start = performance.now();
  const generator = prepareRandomPasswordGenerator(input({ length: 128, minimumCounts: { uppercase: 16, lowercase: 16, digits: 16, symbols: 16 } }));
  for (let i = 0; i < 20; i++) {
    const value = generator.generate(sourceForRank(generator.validPasswordCount * BigInt(i) / 20n));
    assert.equal(validatePolicyPassword(value, generator.policy), true);
  }
  assert.ok(performance.now() - start < 1000, 'Repeated generation must remain bounded and responsive');
});

test('generation has no logging, storage, URL, network or insecure-random side effects', async () => {
  const names = ['fetch', 'localStorage', 'sessionStorage', 'indexedDB', 'location', 'navigator'];
  const saved = new Map(names.map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const originalRandom = Math.random, originalLog = console.log, originalError = console.error;
  try {
    for (const name of names) Object.defineProperty(globalThis, name, { configurable: true, get() { throw Error('Generation touched forbidden surface'); } });
    Math.random = console.log = console.error = () => { throw Error('Generation used forbidden surface'); };
    const generator = prepareRandomPasswordGenerator(input());const value = generator.generate(sourceForRank(0n));
    assert.equal(validatePolicyPassword(value, generator.policy), true);
  } finally {
    Math.random = originalRandom;console.log = originalLog;console.error = originalError;
    for (const [name, descriptor] of saved) if (descriptor) Object.defineProperty(globalThis, name, descriptor);else delete globalThis[name];
  }
  const source = await readFile(new URL('../src/random-password.ts', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /Math\.random|console\.|localStorage|sessionStorage|indexedDB|fetch\(|sendBeacon|XMLHttpRequest|WebSocket/);
});

test('oversized policies fail with structured errors before consuming randomness', () => {
  let calls = 0;const random = buffer => { calls++;return buffer; };
  for (const field of ['permittedSymbols', 'excludedCharacters']) for (const length of [257, 16_000_000])
    assert.throws(() => generateRandomPassword(input({ [field]: '!'.repeat(length) }), random), error =>
      error instanceof PolicyGenerationError && error.errors.some(e => e.code === 'RAW_INPUT_TOO_LONG' && e.field === field));
  assert.equal(calls, 0);
});

test('malformed custom and Strong Random settings reject safely before randomness', () => {
  const revoked = Proxy.revocable({}, {});revoked.revoke();let calls = 0;
  const random = buffer => { calls++;return buffer; };
  for (const value of [revoked.proxy, [], { 0: input(), length: 1 }, input({ allowed: revoked.proxy }), input({ minimumCounts: revoked.proxy })])
    assert.throws(() => generateRandomPassword(value, random), PolicyGenerationError);
  for (const settings of [revoked.proxy, [], { ...STRONG_RANDOM_DEFAULTS, allowed: revoked.proxy }])
    assert.throws(() => generateProfilePassword({ profile: 'strong-random', settings }, [], random), PolicyGenerationError);
  assert.equal(calls, 0);
});
