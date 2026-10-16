import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { WORDS } from '../dist/dictionary.js';
import { entropyBits, minimumSuffixLength, meetsEntropyPolicy } from '../dist/core.js';

// Independent per-character DP: track last symbol and presence of each class.
function counts() {
  let states = new Map([[':0:0', 1n]]);
  const results = [];
  for (let length = 1; length <= 64; length++) {
    const next = new Map();
    for (const [key, count] of states) {
      const [last, digit, symbol] = key.split(':');
      for (const char of '23456789-_@#%*+') {
        const isSymbol = !/[2-9]/.test(char);
        if (isSymbol && last === char) continue;
        const key = `${isSymbol ? char : ''}:${isSymbol ? digit : '1'}:${isSymbol ? '1' : symbol}`;
        next.set(key, (next.get(key) ?? 0n) + count);
      }
    }
    states = next;
    results[length] = [...states].filter(([key]) => key.endsWith(':1:1')).reduce((sum, [, count]) => sum + count, 0n);
  }
  return results;
}

test('approved ten-for-ten dictionary is exact, licensed, and safe after capitalization', async () => {
  const overrides = JSON.parse(await readFile(new URL('../data/readability-overrides.json', import.meta.url)));
  const additions = overrides.replacements.map(row => row.add);
  const removals = overrides.replacements.map(row => row.remove);
  assert.equal(WORDS.length, 17195);
  assert.equal(new Set(additions).size, 10); assert.equal(new Set(removals).size, 10);
  for (const word of additions) {
    assert.ok(WORDS.includes(word));
    for (const capitalized of [word[0].toUpperCase() + word.slice(1), word.toUpperCase()]) assert.doesNotMatch(capitalized, /[lLiIoO01]/);
  }
  for (const word of removals) assert.ok(!WORDS.includes(word));
  const previous = WORDS.filter(word => !additions.includes(word)).concat(removals).sort().join('\n') + '\n';
  assert.equal(createHash('sha256').update(previous).digest('hex'), overrides.previousEligibleSha256);
  const notice = await readFile(new URL('../data/NOTICE.md', import.meta.url), 'utf8');
  assert.match(notice, /CC BY 4.0/); assert.match(notice, /Joseph Bonneau/);
});

test('independent entropy review covers every interval and supported suffix length', async () => {
  const overrides = JSON.parse(await readFile(new URL('../data/readability-overrides.json', import.meta.url)));
  const additions = new Set(overrides.replacements.map(row => row.add));
  const previous = WORDS.filter(word => !additions.has(word)).concat(overrides.replacements.map(row => row.remove));
  const suffixCounts = counts(), threshold = 1n << 64n, ranges = [];
  for (let min = 4; min <= 12; min++) for (let max = min; max <= 12; max++) {
    const count = words => words.filter(word => word.length >= min && word.length <= max).length;
    const oldN = count(previous), newN = count(WORDS);
    const combinations = (n, length) => BigInt(n) * BigInt(n - 1) * BigInt(n - 2) * suffixCounts[length];
    const minimum = n => Array.from({length:61}, (_,i) => i+4).find(length => combinations(n,length) >= threshold);
    for (let length = 4; length <= 64; length++) {
      assert.equal(meetsEntropyPolicy(newN, length), combinations(newN,length) >= threshold);
      assert.ok(Math.abs(entropyBits(newN,length) - Math.log2(Number(combinations(newN,length)))) < 1e-10);
    }
    assert.equal(minimumSuffixLength(newN), minimum(newN));
    assert.equal(minimum(newN), minimum(oldN), 'Approved replacement unexpectedly changes a suffix threshold.');
    ranges.push({minWordLength:min,maxWordLength:max,previousWords:oldN,eligibleWords:newN,
      minimumSuffixLength:minimum(newN),sixCharacterSuffixAllowed:combinations(newN,6)>=threshold,
      sixCharacterCombinations:String(combinations(newN,6)),entropyBits:Math.log2(Number(combinations(newN,6))),
      entropyChangeBits:Math.log2(Number(combinations(newN,6)))-Math.log2(Number(combinations(oldN,6)))});
  }
  assert.equal(ranges.length,45);
  const computedReview = {
    method:'Independent per-character BigInt DP; ordered distinct dictionary selection; fixed capitalization/separators contribute zero bits.',
    eligibleWords:WORDS.length, ranges,
    capitalizationReview:overrides.replacements.map(row => ({...row,titlecase:row.add[0].toUpperCase()+row.add.slice(1),uppercase:row.add.toUpperCase()}))
  };
  const approvedReview = JSON.parse(await readFile(new URL('../data/readability-review.json', import.meta.url), 'utf8'));
  assert.deepEqual(computedReview, approvedReview, 'Computed readability review differs from the approved fixture; review changes separately, never regenerate it during tests.');
});
