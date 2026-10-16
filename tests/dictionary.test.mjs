import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { sensitiveWords } from '../scripts/suitability.mjs';
import { eligibleWords, meetsEntropyPolicy, minimumSuffixLength, suffixPossibilities, entropyBits } from '../dist/core.js';
import { WORDS } from '../dist/dictionary.js';

test('suitability extraction excludes marked complete forms without treating tags or fragments as words', () => {
  const sample = '60 [ukfreq] [upper]: fuck <n> (vulgar-1): fucks, fuck\'s #! unmarked variants\n60: _?: shit-faced <aj> (vulgar-1)\n60: shithead <n> (vulgar-1): shitheads\n60: head <n>: heads\n60: asset <n>: assets';
  assert.deepEqual(sensitiveWords(sample), ['fuck', 'fucks']);
});

test('every pinned ESDB offensive/vulgar form is absent and source/license/annotation hashes match', async () => {
  const read = f => readFile(new URL('../data/' + f, import.meta.url));
  const pinned = JSON.parse(await read('esdb-provenance.json'));
  for (const [file, field] of [['esdb-en_US-large.txt', 'sourceSha256'], ['ESDB-Copyright.txt', 'licenseSha256'], ['exclusions.txt', 'exclusionsSha256'], ['esdb-annotations.txt', 'annotationsSha256'], ['esdb-sensitive-words.txt', 'sensitiveWordsSha256'], ['eligible-words.txt', 'eligibleSha256'], ['readability-overrides.json', 'readabilityOverridesSha256'], ['eff_large_wordlist.txt', 'effSha256']]) {
    assert.equal(createHash('sha256').update(await read(file)).digest('hex'), pinned[field]);
  }
  const flagged = sensitiveWords((await read('esdb-annotations.txt')).toString('utf8'));
  assert.equal(flagged.join('\n') + '\n', (await read('esdb-sensitive-words.txt')).toString('utf8'));
  for (const word of flagged) assert.ok(!WORDS.includes(word));
  for (const word of ['head', 'faced', 'upper', 'unmarked']) assert.ok(WORDS.includes(word));
  assert.equal(pinned.approvedEligibleWords, WORDS.length);
});


test('packaged entropy report matches the actual pool and every supported word interval', async () => {
  const report = JSON.parse(await readFile(new URL('../data/entropy-report.json', import.meta.url), 'utf8'));
  assert.equal(report.eligibleWords, WORDS.length);
  assert.equal(report.defaultValidSuffixes, String(suffixPossibilities(6)));
  const n = BigInt(WORDS.length);
  assert.equal(report.defaultCombinations, String(n * (n - 1n) * (n - 2n) * suffixPossibilities(6)));
  assert.equal(report.defaultEntropyBits, entropyBits(WORDS.length, 6));
  assert.equal(report.wordLengthRanges.length, 45);
  for (const range of report.wordLengthRanges) {
    const actual = eligibleWords(WORDS, { ...range, suffixLength: 6 }).length;
    assert.equal(range.eligibleWords, actual);
    assert.equal(range.minimumSuffixLength, minimumSuffixLength(actual));
    assert.equal(range.sixCharacterSuffixAllowed, meetsEntropyPolicy(actual, 6));
  }
});
