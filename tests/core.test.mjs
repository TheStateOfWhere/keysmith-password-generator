import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { WORDS } from '../dist/dictionary.js';
import { ALPHABET, SYMBOLS, DEFAULTS, meetsEntropyPolicy, MIN_ENTROPY_BITS, assertEntropyPolicy, minimumSuffixLength, eligibleWords, entropyBits, generatePassword, randomInt, suffixPossibilities, validatePassword } from '../dist/core.js';
const pool = eligibleWords(WORDS, DEFAULTS);
// Format validation remains independently testable for historic 8-character fixtures.
const formatSettings = { ...DEFAULTS, suffixLength: 8 };
const good = 'Abacus.BANNER.Cactus.234567-_';
const fixture = ['abacus', 'banner', 'cactus'];
const sequence = values => buffer => { assert.ok(values.length, 'Random fixture exhausted'); buffer[0] = values.shift(); return buffer; };

test('bundled dictionary: provenance, ASCII, exclusions, lengths and case-insensitive uniqueness', async () => {
  const original = await readFile(new URL('../data/esdb-en_US-large.txt', import.meta.url), 'utf8');
  assert.equal(original.trim().split(/\r?\n/).length, 168608);
  const originalWords = new Set(original.trim().split(/\r?\n/));
  const approved = JSON.parse(await readFile(new URL('../data/readability-overrides.json', import.meta.url), 'utf8'));
  for (const { add } of approved.replacements) originalWords.add(add);
  assert.equal(new Set(WORDS.map(w => w.toLowerCase())).size, WORDS.length);
  const deny = (await readFile(new URL('../data/exclusions.txt', import.meta.url), 'utf8')).split(/\r?\n/).filter(x => x && !x.startsWith('#'));
  for (const word of WORDS) { assert.match(word, /^[a-z]{4,12}$/); assert.doesNotMatch(word, /[lio]/i); assert.ok(originalWords.has(word)); assert.ok(!deny.includes(word)); }
  const report = JSON.parse(await readFile(new URL('../data/dictionary-report.json', import.meta.url), 'utf8'));
  assert.equal(report.eligible4to7, WORDS.filter(w => w.length <= 7).length); assert.equal(pool.length, WORDS.length);
  const hash = text => createHash('sha256').update(text).digest('hex');
  assert.equal(hash(original), report.sourceSha256);
  assert.equal(hash(await readFile(new URL('../data/exclusions.txt', import.meta.url))), report.exclusionsSha256);
  assert.equal(hash(await readFile(new URL('../data/ESDB-Copyright.txt', import.meta.url))), report.licenseSha256);
  assert.equal(hash(WORDS.join('\n') + '\n'), report.eligibleSha256);
  assert.deepEqual(WORDS, [...WORDS].sort()); assert.equal(report.eligible4to12, WORDS.length);
});
test('default generation fails closed without browser crypto and propagates provider failure', () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined });
    assert.throws(() => generatePassword(WORDS), /Secure browser randomness is unavailable/);
    assert.throws(() => randomInt(15), /Secure browser randomness is unavailable/);
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: { getRandomValues() { throw new Error('Public fixture provider failure'); } } });
    assert.throws(() => generatePassword(WORDS), /Public fixture provider failure/);
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor); else delete globalThis.crypto;
  }
});
test('dictionary filtering normalizes case, deduplicates and excludes every ambiguous letter', () => {
  assert.deepEqual(eligibleWords(['BANNER', 'banner', 'cactus', 'Abacus', 'lamb', 'Lamb', 'iris', 'Iris', 'open', 'Open', 'abc0', 'abc1', 'bad-', 'abc', 'extraextraextra'], DEFAULTS), ['banner', 'cactus', 'abacus']);
});
test('valid fixed structure accepted', () => assert.ok(validatePassword(good, fixture, formatSettings)));
test('every prohibited character rejected in every password position', () => {
  for (const char of 'lLiIoO01') for (let i = 0; i < good.length; i++) assert.equal(validatePassword(good.slice(0, i) + char + good.slice(i + 1), fixture, formatSettings), false);
});
test('all capitalization rules enforced', () => {
  for (const password of ['abacus.BANNER.Cactus.234567-_', 'ABacus.BANNER.Cactus.234567-_', 'ABACUS.BANNER.Cactus.234567-_', 'Abacus.Banner.Cactus.234567-_', 'Abacus.BANNER.cactus.234567-_', 'Abacus.BANNER.CACTUS.234567-_']) assert.equal(validatePassword(password, fixture, formatSettings), false);
});
test('exactly three separators and no separator in suffix', () => {
  for (const password of [good.replace('.', ''), good + '.', good.replace('234567-_', '23456.-_'), good.replaceAll('.', '-')]) assert.equal(validatePassword(password, fixture, formatSettings), false);
});
test('dictionary membership and duplicate words enforced', () => {
  assert.equal(validatePassword(good, ['banner', 'cactus'], formatSettings), false);
  assert.equal(validatePassword('Abacus.ABACUS.Cactus.234567-_', fixture, formatSettings), false);
});
test('numeric and symbol presence and alphabet enforced, including final newline', () => {
  for (const suffix of ['23456789', '-_-_-_-_', '234567-$', '234567-\n', '234567- ', '234567-\t', '234567-\r']) assert.equal(validatePassword('Abacus.BANNER.Cactus.' + suffix, fixture, formatSettings), false);
  for (const char of '$"\'`/\\|[]{}&<>;!^()=?:,~') assert.equal(validatePassword('Abacus.BANNER.Cactus.234567-' + char, fixture, formatSettings), false);
});
test('unbiased random boundary handling, including rejection threshold', () => {
  assert.equal(randomInt(10, sequence([4294967295, 4294967290, 4294967289])), 9);
  assert.equal(randomInt(10, sequence([0])), 0);
  assert.equal(randomInt(1, sequence([4294967295])), 0);
  assert.equal(randomInt(2 ** 32, sequence([4294967295])), 4294967295);
  for (const bound of [0, -1, 1.5, NaN, Infinity, 2 ** 32 + 1]) assert.throws(() => randomInt(bound));
});
test('selection removes chosen words and rejects whole invalid suffixes', () => {
  const s = { ...DEFAULTS, suffixLength: 20 };
  // Indices 0, 0, 0 select distinct words from shrinking pools;
  // reject all digits, then all symbols, then accept number+symbol.
  const p = generatePassword(fixture, s, sequence([0, 0, 0, ...Array(20).fill(0), ...Array(20).fill(8), ...Array(19).fill(0), 8]));
  assert.equal(p, 'Abacus.BANNER.Cactus.' + '2'.repeat(19) + '-');
});
test('suffix entropy uses exact valid sequence counts', () => {
  for (const length of [2, 3, 4, 5]) {
    let count = 0;
    function enumerate(prefix) {
      if (prefix.length === length) { if (/[23456789]/.test(prefix) && /[-_@#%*+]/.test(prefix) && !/([-_@#%*+])\1/.test(prefix)) count++; return; }
      for (const c of ALPHABET) enumerate(prefix + c);
    }
    enumerate(''); assert.equal(suffixPossibilities(length), BigInt(count));
  }
  assert.equal(suffixPossibilities(2), 112n);
  assert.equal(suffixPossibilities(3), 2408n);
  // Independent per-character DP verifies all supported lengths, including 64.
  let states = new Map([['', 1n]]);
  for (let length = 1; length <= 64; length++) {
    const next = new Map();
    for (const [state, count] of states) {
      const [last, hasDigit = '0', hasSymbol = '0'] = state.split(':');
      for (const char of ALPHABET) {
        const symbol = SYMBOLS.includes(char);
        if (symbol && char === last) continue;
        const key = [char, symbol ? hasDigit : '1', symbol ? '1' : hasSymbol].join(':');
        next.set(key, (next.get(key) ?? 0n) + count);
      }
    }
    states = next;
    if (length >= 2) {
      const count = [...states].filter(([state]) => state.endsWith(':1:1')).reduce((sum, [, value]) => sum + value, 0n);
      assert.equal(suffixPossibilities(length), count);
    }
  }
  assert.equal(entropyBits(3, 2), Math.log2(6 * 112));
  assert.ok(Math.abs(entropyBits(pool.length, 8) - Math.log2(Number(BigInt(pool.length) * BigInt(pool.length - 1) * BigInt(pool.length - 2) * suffixPossibilities(8)))) < 1e-10);
});
test('configurable word/suffix lengths and final validation across 2000 real secure generations', () => {
  for (const s of [DEFAULTS, { ...DEFAULTS, suffixLength: minimumSuffixLength(pool.length) }, { minWordLength: 4, maxWordLength: 4, suffixLength: 20 }, { minWordLength: 8, maxWordLength: 12, suffixLength: 64 }]) {
    const selectedPool = eligibleWords(WORDS, s);
    for (let i = 0; i < 500; i++) {
      const password = generatePassword(WORDS, s);
      assert.ok(validatePassword(password, selectedPool, s));
      const [a, b, c, suffix] = password.split('.');
      assert.equal(suffix.length, s.suffixLength);
      assert.ok(!/([-_@#%*+])\1/.test(suffix), 'Suffix adjacency check failed; value omitted.');
      assert.ok(/^[23456789_@#%*+-]+$/.test(suffix), 'Suffix alphabet check failed; value omitted.');
      assert.ok(/[23456789]/.test(suffix), 'Suffix digit check failed; value omitted.');
      assert.ok(/[-_@#%*+]/.test(suffix), 'Suffix symbol check failed; value omitted.');
      assert.equal(password.length, a.length + b.length + c.length + 3 + s.suffixLength);
      assert.equal(new Set([a, b, c].map(w => w.toLowerCase())).size, 3);
    }
  }
});
test('default policy is six suffix characters and at least 64 bits', async () => {
  assert.equal(DEFAULTS.suffixLength, 6); assert.equal(MIN_ENTROPY_BITS, 64);
  assert.ok(entropyBits(pool.length, DEFAULTS.suffixLength) >= 64);
  assert.doesNotThrow(() => assertEntropyPolicy(pool.length, DEFAULTS.suffixLength));
  const html = await readFile(new URL('../dist/index.html', import.meta.url), 'utf8');
  assert.match(html, /id="suffix"[^>]+value="6"/);
});
test('below-policy generation is blocked before consuming randomness, even without the UI', () => {
  for (const suffixLength of [4, 5]) {
    let calls = 0;
    assert.throws(() => generatePassword(WORDS, { ...DEFAULTS, suffixLength }, buffer => { calls++; return buffer; }), /Generation blocked.*at least 6/);
    assert.equal(calls, 0);
  }
  assert.ok(validatePassword(generatePassword(WORDS, { ...DEFAULTS, suffixLength: 6 }), pool, { ...DEFAULTS, suffixLength: 6 }));
});
test('policy uses actual filtered pool and rejects the setting just below each exact threshold', () => {
  for (let minWordLength = 4; minWordLength <= 12; minWordLength++) {
    const s = { ...DEFAULTS, minWordLength, maxWordLength: minWordLength };
    const actual = eligibleWords(WORDS, s).length;
    if (actual < 3) { assert.throws(() => generatePassword(WORDS, s)); continue; }
    const required = minimumSuffixLength(actual);
    assert.equal(eligibleWords([...WORDS, ...WORDS, 'invalid', 'abc0'], s).length, actual);
    assert.doesNotThrow(() => assertEntropyPolicy(actual, required));
    assert.throws(() => assertEntropyPolicy(actual, required - 1), /Generation blocked/);
    const n = BigInt(actual);
    assert.ok(n * (n - 1n) * (n - 2n) * suffixPossibilities(required) >= 2n ** 64n);
    assert.ok(n * (n - 1n) * (n - 2n) * suffixPossibilities(required - 1) < 2n ** 64n);
    assert.throws(() => generatePassword(WORDS, { ...s, suffixLength: required - 1 }), /Generation blocked/);
    assert.ok(validatePassword(generatePassword(WORDS, { ...s, suffixLength: required }), eligibleWords(WORDS, s), { ...s, suffixLength: required }));
  }
});
test('entropy excludes fixed case/separators and reflects all counted combinations', () => {
  assert.equal(ALPHABET, '23456789-_@#%*+');
  const n = BigInt(pool.length), length = DEFAULTS.suffixLength;
  const exact = n * (n - 1n) * (n - 2n) * suffixPossibilities(length);
  assert.ok(Math.abs(entropyBits(pool.length, length) - Math.log2(Number(exact))) < 1e-10);
  assert.ok(entropyBits(pool.length, length) < Math.log2(pool.length ** 3 * 15 ** length));
});
test('invalid settings and insufficient dictionary fail closed', () => {
  for (const s of [{ ...DEFAULTS, minWordLength: 3 }, { ...DEFAULTS, maxWordLength: 13 }, { ...DEFAULTS, minWordLength: 8, maxWordLength: 7 }, { ...DEFAULTS, suffixLength: 1 }, { ...DEFAULTS, suffixLength: 65 }, { ...DEFAULTS, suffixLength: 2.5 }, { ...DEFAULTS, suffixLength: NaN }]) {
    assert.throws(() => generatePassword(WORDS, s)); assert.equal(validatePassword(good, fixture, s), false);
  }
  assert.throws(() => generatePassword(['abacus', 'banner']));
  assert.throws(() => entropyBits(2, 8)); assert.throws(() => suffixPossibilities(0));
});
test('static app avoids persistence, network requests, HTML injection and insecure randomness', async () => {
  const files = await Promise.all(['core.js', 'app.js'].map(f => readFile(new URL('../dist/' + f, import.meta.url), 'utf8')));
  const source = files.join('\n');
  assert.doesNotMatch(source, /Math\.random|localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML|outerHTML|fetch\(|XMLHttpRequest|sendBeacon|console\./);
  const html = await readFile(new URL('../dist/index.html', import.meta.url), 'utf8');
  assert.match(html, /connect-src 'none'/); assert.match(html, /form-action 'none'/);
  assert.doesNotMatch(html, /(?:src|href)="https?:/);
});


test('dictionary cleanup explicitly excludes all four requested words', async () => {
  const deny = (await readFile(new URL('../data/exclusions.txt', import.meta.url), 'utf8')).split(/\r?\n/);
  for (const word of ['badass', 'freebase', 'humped', 'nutcase']) {
    assert.ok(deny.includes(word)); assert.ok(!WORDS.includes(word));
  }
  assert.equal(pool.length, 17195); assert.equal(WORDS.length, 17195); assert.ok(pool.length >= 12498);
  for (const word of ['fuck', 'fucker', 'cunt', 'badasses', 'bugger', 'dumbass', 'jackass', 'twat', 'wanker', 'spaz', 'retarded']) assert.ok(!WORDS.includes(word));
  for (const word of ['grass', 'assess', 'asset', 'butter', 'drape', 'debugger']) assert.ok(WORDS.includes(word));
});

test('identical adjacent symbols rejected anywhere; alternating pairs remain valid', () => {
  for (const pair of [...SYMBOLS].map(c => c + c)) {
    for (let index = 0; index <= 6; index++) {
      const suffix = '23456789'.slice(0, index) + pair + '23456789'.slice(index + 2);
      assert.equal(validatePassword('Abacus.BANNER.Cactus.' + suffix, fixture, formatSettings), false);
    }
  }
  for (const suffix of ['234567-_', '234567_-', '-_234567', '_-234567', '2-_-_-_3']) {
    assert.ok(validatePassword('Abacus.BANNER.Cactus.' + suffix, fixture, formatSettings));
  }
  for (const suffix of ['222-', '-222', '222_', '_222']) {
    assert.ok(validatePassword('Abacus.BANNER.Cactus.' + suffix, fixture, { ...DEFAULTS, suffixLength: 4 }));
  }
  assert.throws(() => generatePassword(WORDS, { ...DEFAULTS, suffixLength: 4 }), /Generation blocked/);
});

test('whole suffix rejection removes repeated symbols without repairing or biasing candidates', () => {
  const s = { ...DEFAULTS, suffixLength: 20 };
  for (const accepted of ['2'.repeat(18) + '-_', '2'.repeat(18) + '_-']) {
    const candidates = ['2'.repeat(18) + '__', '--' + '2'.repeat(18), '2'.repeat(9) + '--' + '2'.repeat(9), accepted];
    const values = [0, 0, 0, ...candidates.flatMap(suffix => [...suffix].map(c => ALPHABET.indexOf(c)))];
    assert.equal(generatePassword(fixture, s, sequence(values)), 'Abacus.BANNER.Cactus.' + accepted);
    assert.equal(values.length, 0);
  }
});

test('invalid direct policy parameters cannot bypass the entropy threshold', () => {
  for (const length of [NaN, Infinity, -Infinity, undefined, null, '12', 1, 65, 12.5]) {
    assert.throws(() => assertEntropyPolicy(pool.length, length));
    let calls = 0;
    assert.throws(() => generatePassword(WORDS, { ...DEFAULTS, suffixLength: length }, buffer => { calls++; return buffer; }));
    assert.equal(calls, 0);
  }
  for (const count of [NaN, Infinity, 2, 3.5, '1205']) assert.throws(() => assertEntropyPolicy(count, 12));
});


test('exact v0.2 suffix counts and 64-bit dictionary boundaries', () => {
  for (const [length, count, minimum] of [[4, 40544n, 76914], [5, 629664n, 30829], [6, 9453696n, 12498]]) {
    assert.equal(suffixPossibilities(length), count);
    assert.equal(meetsEntropyPolicy(minimum, length), true);
    assert.equal(meetsEntropyPolicy(minimum - 1, length), false);
    assert.doesNotThrow(() => assertEntropyPolicy(minimum, length));
    assert.throws(() => assertEntropyPolicy(minimum - 1, length), /Generation blocked/);
    assert.equal(entropyBits(minimum, length).toFixed(1), entropyBits(minimum - 1, length).toFixed(1));
  }
});

test('every different adjacent symbol pair stays valid in validation and generation', () => {
  const s = { ...DEFAULTS, suffixLength: 20 };
  for (const a of SYMBOLS) for (const b of SYMBOLS) {
    if (a === b) continue;
    const suffix = '2'.repeat(18) + a + b;
    assert.ok(validatePassword('Abacus.BANNER.Cactus.' + suffix, fixture, s));
    assert.equal(generatePassword(fixture, s, sequence([0, 0, 0, ...[...suffix].map(c => ALPHABET.indexOf(c))])), 'Abacus.BANNER.Cactus.' + suffix);
  }
});

test('unbiased 15-character alphabet rejection and whole-suffix rejection for every symbol', () => {
  assert.equal(randomInt(15, sequence([4294967295, 4294967294])), 14);
  for (let index = 0; index < 15; index++) assert.equal(randomInt(15, sequence([index])), index);
  const s = { ...DEFAULTS, suffixLength: 20 };
  for (const c of SYMBOLS) {
    const bad = '2'.repeat(9) + c + c + '2'.repeat(9), good = '2'.repeat(19) + c;
    const values = [0, 0, 0, ...[...bad + good].map(char => ALPHABET.indexOf(char))];
    assert.equal(generatePassword(fixture, s, sequence(values)), 'Abacus.BANNER.Cactus.' + good);
    assert.equal(values.length, 0);
  }
});

test('all 45 word-length intervals enforce their actual pool and minimum suffix', () => {
  for (let minWordLength = 4; minWordLength <= 12; minWordLength++) for (let maxWordLength = minWordLength; maxWordLength <= 12; maxWordLength++) {
    const s = { minWordLength, maxWordLength, suffixLength: 6 };
    const words = eligibleWords(WORDS, s), n = BigInt(words.length);
    const required = minimumSuffixLength(words.length);
    assert.equal(meetsEntropyPolicy(words.length, 6), n * (n - 1n) * (n - 2n) * 9453696n >= 2n ** 64n);
    let calls = 0;
    if (!meetsEntropyPolicy(words.length, 6)) {
      assert.throws(() => generatePassword(WORDS, s, buffer => { calls++; return buffer; }), /Generation blocked/);
      assert.equal(calls, 0);
    }
    const adjusted = { ...s, suffixLength: required };
    assert.ok(validatePassword(generatePassword(WORDS, adjusted), words, adjusted));
  }
});


test('all six ordered distinct triples are reachable with shrinking-pool selection', () => {
  const passwords = new Set(), s = { ...DEFAULTS, suffixLength: 20 };
  for (let first = 0; first < 3; first++) for (let second = 0; second < 2; second++) {
    const values = [first, second, 0, ...Array(19).fill(0), 8];
    passwords.add(generatePassword(fixture, s, sequence(values)));
    assert.equal(values.length, 0);
  }
  assert.equal(passwords.size, 6);
  for (const password of passwords) assert.ok(validatePassword(password, fixture, s));
  for (const bound of [pool.length, pool.length - 1, pool.length - 2]) {
    const limit = 2 ** 32 - (2 ** 32 % bound);
    assert.equal(randomInt(bound, sequence([limit, 2 ** 32 - 1, limit - 1])), bound - 1);
  }
});
