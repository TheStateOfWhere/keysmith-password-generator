import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateProfilePassword, UnsupportedProfileError } from '../dist/profiles.js';
import { DEFAULTS, generatePassword } from '../dist/core.js';
import { WORDS } from '../dist/dictionary.js';

// Only deterministic, public fixtures are compared or included in diagnostics.
const words = Object.freeze(['abacus', 'banner', 'cactus']);
const fixtureSettings = Object.freeze({ ...DEFAULTS, suffixLength: 20 });
function sequence(values) {
  let calls = 0;
  return {
    random(buffer) {
      assert.ok(calls < values.length, 'Public random fixture exhausted');
      buffer[0] = values[calls++]; return buffer;
    },
    calls: () => calls,
  };
}

test('Readable dispatcher returns the existing fixed-format public fixture', () => {
  const source = sequence([0, 0, 0, ...Array(19).fill(0), 8]);
  const value = generateProfilePassword({ profile: 'readable', settings: fixtureSettings }, words, source.random);
  assert.equal(value, 'Abacus.BANNER.Cactus.' + '2'.repeat(19) + '-');
  assert.equal(source.calls(), 23);
  assert.deepEqual(fixtureSettings, { minWordLength: 4, maxWordLength: 12, suffixLength: 20 });
  assert.deepEqual(words, ['abacus', 'banner', 'cactus']);
});

test('Readable dispatch is byte-equivalent and consumes identical rejection-sampling inputs', () => {
  for (const settings of [fixtureSettings, { ...DEFAULTS, suffixLength: 64 }]) {
    const values = [0, 0, 0, ...Array(settings.suffixLength).fill(0),
      ...Array(settings.suffixLength).fill(8), ...Array(settings.suffixLength - 1).fill(0), 8];
    const original = sequence(values), dispatched = sequence(values);
    const expected = generatePassword(words, settings, original.random);
    const actual = generateProfilePassword({ profile: 'readable', settings }, words, dispatched.random);
    assert.equal(actual, expected); assert.equal(dispatched.calls(), original.calls());
  }
});

test('Readable dispatch uses the existing defaults supplied by the application', () => {
  const random = sequence([0, 0, 0, 0, 8, 0, 8, 0, 8]);
  const value = generateProfilePassword({ profile: 'readable', settings: DEFAULTS }, WORDS, random.random);
  const direct = sequence([0, 0, 0, 0, 8, 0, 8, 0, 8]);
  assert.equal(value, generatePassword(WORDS, DEFAULTS, direct.random));
});

test('unknown profiles reject before dictionary access or randomness', () => {
  const dictionary = new Proxy([], { get() { throw new Error('Unsupported profile touched dictionary'); } });
  const random = () => { throw new Error('Unsupported profile touched randomness'); };
  for (const profile of ['unknown-public-fixture', '', null, undefined]) {
    assert.throws(() => generateProfilePassword({ profile }, dictionary, random), error =>
      error instanceof UnsupportedProfileError && error.name === 'UnsupportedProfileError' &&
      error.message === 'Selected password profile is not implemented.');
  }
});

test('Readable settings errors are unchanged and occur before randomness', () => {
  for (const settings of [
    { ...DEFAULTS, minWordLength: 3 }, { ...DEFAULTS, maxWordLength: 13 },
    { ...DEFAULTS, minWordLength: 8, maxWordLength: 4 },
    { ...DEFAULTS, suffixLength: 3 }, { ...DEFAULTS, suffixLength: 65 },
    { ...DEFAULTS, suffixLength: NaN }, { ...DEFAULTS, suffixLength: 6.5 },
  ]) {
    let calls = 0;
    const random = () => { calls++; throw new Error('Validation consumed randomness'); };
    let original;
    try { generatePassword(words, settings, random); } catch (error) { original = error; }
    assert.ok(original instanceof Error);
    assert.throws(() => generateProfilePassword({ profile: 'readable', settings }, words, random), error => error.message === original.message);
    assert.equal(calls, 0);
  }
});

test('Readable dispatcher preserves eligible-word and minimum-entropy errors', () => {
  const random = () => { throw new Error('Blocked policy consumed randomness'); };
  for (const dictionary of [[], ['abacus', 'banner'], words]) {
    let original;
    try { generatePassword(dictionary, DEFAULTS, random); } catch (error) { original = error; }
    assert.ok(original instanceof Error);
    assert.throws(() => generateProfilePassword({ profile: 'readable', settings: DEFAULTS }, dictionary, random), error => error.message === original.message);
  }
});

test('Readable dispatcher propagates provider errors and fails closed without browser crypto', () => {
  const failure = new Error('Public fixture randomness failure');
  assert.throws(() => generateProfilePassword({ profile: 'readable', settings: fixtureSettings }, words, () => { throw failure; }), error => error === failure);
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    assert.throws(() => generateProfilePassword({ profile: 'readable', settings: fixtureSettings }, words), /Secure browser randomness is unavailable/);
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor); else delete globalThis.crypto;
  }
});
