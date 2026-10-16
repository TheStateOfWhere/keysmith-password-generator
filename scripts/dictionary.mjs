import { sensitiveWords } from './suitability.mjs';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const sha = value => createHash('sha256').update(value).digest('hex');
const read = name => readFile(new URL('../data/' + name, import.meta.url), 'utf8');
const pinned = JSON.parse(await read('esdb-provenance.json'));
const source = await read('esdb-en_US-large.txt');
const license = await read('ESDB-Copyright.txt');
const exclusions = await read('exclusions.txt');
const annotations = await read('esdb-annotations.txt');
const sensitive = await read('esdb-sensitive-words.txt');
for (const [name, content, expected] of [['source', source, pinned.sourceSha256], ['license', license, pinned.licenseSha256], ['exclusions', exclusions, pinned.exclusionsSha256], ['annotations', annotations, pinned.annotationsSha256], ['sensitive words', sensitive, pinned.sensitiveWordsSha256]]) {
  if (sha(content) !== expected) throw new Error(`Pinned ${name} checksum mismatch. Review changes before updating provenance.`);
}
const entries = source.trim().split(/\r?\n/);
if (entries.length !== pinned.sourceEntries) throw new Error('Unexpected source entry count.');
const flagged = sensitiveWords(annotations);
if (flagged.join('\n') + '\n' !== sensitive) throw new Error('ESDB suitability annotation extraction mismatch.');
const denied = new Set([...exclusions.split(/\r?\n/).filter(x => x && !x.startsWith('#')), ...flagged]);
let words = [...new Set(entries.filter(w => /^[a-z]{4,12}$/.test(w) && !/[lio]/i.test(w) && !denied.has(w)))].sort();
const overridesText = await read('readability-overrides.json');
const eff = await read('eff_large_wordlist.txt');
if (sha(overridesText) !== pinned.readabilityOverridesSha256 || sha(eff) !== pinned.effSha256) throw new Error('Readability override provenance mismatch.');
const overrides = JSON.parse(overridesText);
if (sha(words.join('\n') + '\n') !== overrides.previousEligibleSha256) throw new Error('Unexpected pre-override dictionary.');
const effWords = new Set(eff.trim().split(/\r?\n/).map(line => line.split(/\s+/)[1]));
if (overrides.replacements.length !== 10) throw new Error('Exactly ten approved replacements required.');
for (const { remove, add } of overrides.replacements) {
  if (!words.includes(remove) || words.includes(add) || !effWords.has(add) || !/^[a-z]{4,12}$/.test(add) || /[lio]/i.test(add) || denied.has(add)) throw new Error('Invalid approved replacement.');
  words = words.filter(word => word !== remove).concat(add);
}
words.sort();
const eligibleText = words.join('\n') + '\n';
if (words.length !== pinned.approvedEligibleWords || sha(eligibleText) !== pinned.eligibleSha256) throw new Error('Approved eligible dictionary mismatch.');
const n = BigInt(words.length);
if (words.length < 12498 || n * (n - 1n) * (n - 2n) * 9453696n < (1n << 64n)) throw new Error('Approved dictionary cannot meet the 64-bit policy with a six-character suffix.');
const countsByLength = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [i + 4, words.filter(w => w.length === i + 4).length]));
await writeFile(new URL('../src/dictionary.ts', import.meta.url), `// Generated from pinned ESDB US-large. See data/NOTICE.md and esdb-provenance.json.\nexport const WORDS: readonly string[] = Object.freeze(${JSON.stringify(words)});\n`);
await writeFile(new URL('../data/eligible-words.txt', import.meta.url), eligibleText);
await writeFile(new URL('../data/dictionary-report.json', import.meta.url), JSON.stringify({ ...pinned, eligible4to12: words.length, eligible4to7: words.filter(w => w.length <= 7).length, countsByLength }, null, 2) + '\n');
console.log(`Dictionary: ${words.length} approved eligible words (default 4–12); offline pinned hashes verified.`);
