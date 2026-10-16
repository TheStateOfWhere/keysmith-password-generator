export const DIGITS = '23456789';
export const SYMBOLS = '-_@#%*+';
export const ALPHABET = DIGITS + SYMBOLS;
export const PROHIBITED = /[lLiIoO01]/;
export const MIN_ENTROPY_BITS = 64;
export const DEFAULTS = Object.freeze({ minWordLength: 4, maxWordLength: 12, suffixLength: 6 });
export interface Settings { minWordLength: number; maxWordLength: number; suffixLength: number }
export type RandomSource = (buffer: Uint32Array<ArrayBuffer>) => Uint32Array<ArrayBuffer>;
const secureRandom: RandomSource = buffer => {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') throw new Error('Secure browser randomness is unavailable.');
  return globalThis.crypto.getRandomValues(buffer);
};
export function randomInt(bound: number, random: RandomSource = secureRandom): number {
  const size = 2 ** 32;
  if (!Number.isSafeInteger(bound) || bound < 1 || bound > size) throw new Error('Invalid random bound.');
  const limit = size - (size % bound);
  const buffer = new Uint32Array(1);
  let value: number;
  do { random(buffer); value = buffer[0]!; } while (value >= limit);
  return value % bound;
}
export function assertSettings(s: Settings): void {
  if (![s.minWordLength, s.maxWordLength, s.suffixLength].every(Number.isInteger) ||
      s.minWordLength < 4 || s.maxWordLength > 12 || s.minWordLength > s.maxWordLength ||
      s.suffixLength < 4 || s.suffixLength > 64) throw new Error('Use word lengths 4–12 and a suffix of 4–64 characters. Minimum must not exceed maximum.');
}
export function eligibleWords(dictionary: readonly string[], s: Settings): string[] {
  assertSettings(s);
  return [...new Set(dictionary.map(w => w.toLowerCase()).filter(w =>
    /^[a-z]+$/.test(w) && !PROHIBITED.test(w) && w.length >= s.minWordLength && w.length <= s.maxWordLength))];
}
export function suffixPossibilities(length: number): bigint {
  if (!Number.isInteger(length) || length < 2 || length > 64) throw new Error('Invalid suffix length.');
  // Count strings by final character category. After a symbol only the other
  // six symbols are allowed; after a digit all seven symbols are allowed.
  let digitEnding = 1n; // Empty prefix, permitting all fifteen first characters.
  let symbolEnding = 0n;
  for (let i = 0; i < length; i++) {
    [digitEnding, symbolEnding] = [8n * (digitEnding + symbolEnding), 7n * digitEnding + 6n * symbolEnding];
  }
  // All-symbol strings have seven first choices and six choices thereafter.
  return digitEnding + symbolEnding - 8n ** BigInt(length) - 7n * 6n ** BigInt(length - 1);
}
export function entropyBits(wordCount: number, suffixLength: number): number {
  if (!Number.isSafeInteger(wordCount) || wordCount < 3) throw new Error('At least three distinct eligible words are required.');
  return Math.log2(wordCount) + Math.log2(wordCount - 1) + Math.log2(wordCount - 2) + Math.log2(Number(suffixPossibilities(suffixLength)));
}
export function minimumSuffixLength(wordCount: number): number {
  if (!Number.isSafeInteger(wordCount) || wordCount < 3) throw new Error('At least three distinct eligible words are required.');
  const n = BigInt(wordCount);
  const orderedWords = n * (n - 1n) * (n - 2n);
  // Compare exact counts to 2^64, avoiding display-rounding at the policy boundary.
  for (let length = 4; length <= 64; length++) {
    if (orderedWords * suffixPossibilities(length) >= (1n << BigInt(MIN_ENTROPY_BITS))) return length;
  }
  throw new Error('No permitted suffix length meets the standard entropy policy.');
}
export function meetsEntropyPolicy(wordCount: number, suffixLength: number): boolean {
  // Validate both inputs even when one fails; counts alone authorize generation.
  const suffixes = suffixPossibilities(suffixLength);
  if (!Number.isSafeInteger(wordCount) || wordCount < 3) throw new Error('At least three distinct eligible words are required.');
  const n = BigInt(wordCount);
  return n * (n - 1n) * (n - 2n) * suffixes >= (1n << BigInt(MIN_ENTROPY_BITS));
}
export function assertEntropyPolicy(wordCount: number, suffixLength: number): void {
  if (meetsEntropyPolicy(wordCount, suffixLength)) return;
  const required = minimumSuffixLength(wordCount);
  throw new Error(`Generation blocked: this configuration estimates ${entropyBits(wordCount, suffixLength).toFixed(2)} bits, below the ${MIN_ENTROPY_BITS}-bit standard policy. Increase suffix length to at least ${required} characters for the current ${wordCount} eligible words, or broaden the word range.`);
}
export function validSuffix(suffix: string): boolean {
  // Alphabet membership uses literal string checks, avoiding regex metacharacters.
  return [...suffix].every(char => ALPHABET.includes(char)) &&
    [...suffix].some(char => DIGITS.includes(char)) &&
    [...suffix].some(char => SYMBOLS.includes(char)) &&
    ![...suffix].some((char, index) => index > 0 && SYMBOLS.includes(char) && char === suffix[index - 1]);
}
export function validatePassword(password: string, pool: readonly string[], s: Settings): boolean {
  try { assertSettings(s); } catch { return false; }
  if (PROHIBITED.test(password)) return false;
  const parts = password.split('.');
  if (parts.length !== 4) return false;
  const [first, second, third, suffix] = parts as [string, string, string, string];
  if (!/^[A-Z][a-z]+$/.test(first) || !/^[A-Z]+$/.test(second) || !/^[A-Z][a-z]+$/.test(third)) return false;
  const words = [first, second, third].map(w => w.toLowerCase());
  if (new Set(words).size !== 3 || words.some(w => !pool.includes(w) || w.length < s.minWordLength || w.length > s.maxWordLength)) return false;
  return suffix.length === s.suffixLength && validSuffix(suffix);
}
export function generatePassword(dictionary: readonly string[], s: Settings = DEFAULTS, random: RandomSource = secureRandom): string {
  const pool = eligibleWords(dictionary, s);
  if (pool.length < 3) throw new Error('At least three distinct eligible words are required. Broaden the word length range.');
  assertEntropyPolicy(pool.length, s.suffixLength);
  const available = [...pool];
  const selected = Array.from({ length: 3 }, () => available.splice(randomInt(available.length, random), 1)[0]!);
  let suffix: string;
  // Rejection of whole suffixes makes every valid suffix equally probable.
  // Forcing one number and symbol then shuffling would bias the distribution.
  do { suffix = Array.from({ length: s.suffixLength }, () => ALPHABET[randomInt(ALPHABET.length, random)]!).join(''); }
  while (!validSuffix(suffix));
  const title = (word: string) => word[0]!.toUpperCase() + word.slice(1);
  const password = `${title(selected[0]!)}.${selected[1]!.toUpperCase()}.${title(selected[2]!)}.${suffix}`;
  if (!validatePassword(password, pool, s)) throw new Error('Generated password failed validation.');
  return password;
}
