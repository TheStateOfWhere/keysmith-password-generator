import { MIN_ENTROPY_BITS } from './core.js';

export const MAX_POLICY_LENGTH = 128;
// Each raw symbol/exclusion field permits 256 ASCII characters: enough for all
// 95 printable characters plus duplicate-entry headroom. Reject, never truncate,
// before scanning strings; normalized sets cannot exceed the ASCII alphabet.
export const MAX_POLICY_RAW_INPUT_LENGTH = 256;
export const AMBIGUOUS_CHARACTERS = 'lLiIoO01';
export const CATEGORIES = Object.freeze(['uppercase', 'lowercase', 'digits', 'symbols'] as const);
export type Category = typeof CATEGORIES[number];
export type CategoryCounts = Readonly<Record<Category, number>>;
export type AllowedCategories = Readonly<Record<Category, boolean>>;
export interface PasswordPolicyInput {
  readonly length: number;
  readonly allowed: AllowedCategories;
  readonly minimumCounts: CategoryCounts;
  readonly permittedSymbols: string;
  readonly excludedCharacters: string;
  readonly excludeAmbiguous: boolean;
}
export interface NormalizedCategory {
  readonly id: Category;
  readonly characters: string;
}
export interface NormalizedPolicy extends PasswordPolicyInput {
  readonly categories: readonly NormalizedCategory[];
  readonly alphabet: string;
}
export type PolicyErrorCode = 'INVALID_POLICY' | 'INVALID_LENGTH' | 'INVALID_ALLOWED'
  | 'INVALID_MINIMUM' | 'INVALID_SYMBOLS' | 'SYMBOL_CATEGORY_OVERLAP'
  | 'INVALID_EXCLUSIONS' | 'RAW_INPUT_TOO_LONG' | 'INVALID_AMBIGUOUS' | 'DISABLED_REQUIRED_CATEGORY'
  | 'EMPTY_REQUIRED_CATEGORY' | 'EMPTY_ALPHABET' | 'INSUFFICIENT_LENGTH' | 'INSUFFICIENT_ENTROPY';
export interface PolicyError {
  readonly code: PolicyErrorCode;
  readonly field: string;
  readonly message: string;
}
export type NormalizationResult = { readonly ok: true; readonly policy: NormalizedPolicy }
  | { readonly ok: false; readonly errors: readonly PolicyError[] };
export interface EntropyAssessment {
  readonly meetsMinimum: boolean;
  readonly floorBits: number;
  readonly estimatedBitsText: string;
  readonly description: string;
}
export type PolicyAnalysis = { readonly kind: 'invalid'; readonly errors: readonly PolicyError[] }
  | { readonly kind: 'eligible' | 'ineligible'; readonly policy: NormalizedPolicy;
      readonly validPasswordCount: bigint; readonly entropy: EntropyAssessment;
      readonly errors: readonly PolicyError[] };

const LETTERS = { uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', lowercase: 'abcdefghijklmnopqrstuvwxyz', digits: '0123456789' };
const MINIMUM_COUNT = 1n << BigInt(MIN_ENTROPY_BITS);
const MAXIMUM_COUNT = 95n ** BigInt(MAX_POLICY_LENGTH);
// Only immutable normalization outputs are accepted by the counting API. A
// serialized original inputs must be normalized again, not trusted as prevalidated.
const normalizedPolicies = new WeakSet<object>();
const unique = (text: string): string => [...new Set(text)].sort().join('');
const printable = (text: string): boolean => [...text].every(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126);
const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

// Detach JSON-like data once. Accessors/custom prototypes are not policy data;
// never validate one getter value and then count a different getter value.
function dataSnapshot(value: unknown): Record<string, unknown> | undefined {
  try {
    if (!record(value)) return undefined;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).some(key => typeof key !== 'string')
      || Object.values(descriptors).some(d => !Object.hasOwn(d, 'value'))) return undefined;
    return Object.fromEntries(Object.entries(descriptors).map(([key, d]) => [key, d.value]));
  } catch { return undefined; }
}

export function normalizePolicy(input: PasswordPolicyInput): NormalizationResult {
  const errors: PolicyError[] = [];
  const error = (code: PolicyErrorCode, field: string, message: string): void => { errors.push({ code, field, message }); };
  const raw = dataSnapshot(input);
  const keys = ['length', 'allowed', 'minimumCounts', 'permittedSymbols', 'excludedCharacters', 'excludeAmbiguous'];
  if (!raw || !exactKeys(raw, keys)) {
    return { ok: false, errors: [{ code: 'INVALID_POLICY', field: 'policy', message: 'Supply all supported policy fields; remove unknown constraints.' }] };
  }
  raw.allowed = dataSnapshot(raw.allowed) ?? null;
  raw.minimumCounts = dataSnapshot(raw.minimumCounts) ?? null;
  if (!Number.isInteger(raw.length) || typeof raw.length !== 'number' || raw.length < 1 || raw.length > MAX_POLICY_LENGTH)
    error('INVALID_LENGTH', 'length', 'Choose an integer password length from 1 to 128.');
  const allowed = raw.allowed;
  if (!record(allowed) || !exactKeys(allowed, CATEGORIES) || CATEGORIES.some(id => typeof allowed[id] !== 'boolean'))
    error('INVALID_ALLOWED', 'allowed', 'Explicitly enable or disable each of the four character categories with booleans.');
  if (!record(raw.minimumCounts) || !exactKeys(raw.minimumCounts, CATEGORIES))
    error('INVALID_MINIMUM', 'minimumCounts', 'Supply an integer minimum count for each character category.');
  else for (const id of CATEGORIES) {
    const n = raw.minimumCounts[id];
    if (typeof n !== 'number' || !Number.isInteger(n) || n < 0 || n > MAX_POLICY_LENGTH)
      error('INVALID_MINIMUM', 'minimumCounts.' + id, 'Choose an integer minimum count from 0 to 128.');
  }
  if (typeof raw.permittedSymbols === 'string' && raw.permittedSymbols.length > MAX_POLICY_RAW_INPUT_LENGTH)
    error('RAW_INPUT_TOO_LONG', 'permittedSymbols', 'Limit permitted symbols to 256 raw characters; remove repeated entries. No input is truncated.');
  else if (typeof raw.permittedSymbols !== 'string' || !printable(raw.permittedSymbols))
    error('INVALID_SYMBOLS', 'permittedSymbols', 'Permitted symbols must be printable ASCII; remove control or Unicode characters.');
  else if (/[A-Za-z0-9]/.test(raw.permittedSymbols))
    error('SYMBOL_CATEGORY_OVERLAP', 'permittedSymbols', 'Use letters and digits through their own categories, not as symbols.');
  if (typeof raw.excludedCharacters === 'string' && raw.excludedCharacters.length > MAX_POLICY_RAW_INPUT_LENGTH)
    error('RAW_INPUT_TOO_LONG', 'excludedCharacters', 'Limit exclusions to 256 raw characters; remove repeated entries. No input is truncated.');
  else if (typeof raw.excludedCharacters !== 'string' || !printable(raw.excludedCharacters))
    error('INVALID_EXCLUSIONS', 'excludedCharacters', 'Exclusions must be printable ASCII; remove control or Unicode characters.');
  if (typeof raw.excludeAmbiguous !== 'boolean')
    error('INVALID_AMBIGUOUS', 'excludeAmbiguous', 'Explicitly enable or disable ambiguous-character exclusions with a boolean.');
  if (errors.length) return { ok: false, errors };

  // Runtime fields above have been checked exactly; do not coerce or fill defaults.
  const checked = raw as unknown as PasswordPolicyInput;
  const symbols = unique(checked.permittedSymbols);
  const exclusions = unique(checked.excludedCharacters + (checked.excludeAmbiguous ? AMBIGUOUS_CHARACTERS : ''));
  const excluded = new Set(exclusions);
  const categories = CATEGORIES.map(id => Object.freeze({ id, characters: checked.allowed[id]
    ? (id === 'symbols' ? symbols : LETTERS[id]).split('').filter(c => !excluded.has(c)).join('') : '' }));
  for (const category of categories) {
    if (checked.minimumCounts[category.id] > 0 && !checked.allowed[category.id])
      error('DISABLED_REQUIRED_CATEGORY', 'minimumCounts.' + category.id, 'Enable ' + category.id + ' or set its required minimum to zero.');
    else if (checked.minimumCounts[category.id] > 0 && !category.characters.length)
      error('EMPTY_REQUIRED_CATEGORY', 'minimumCounts.' + category.id, 'Permit some ' + category.id + ', remove conflicting exclusions, or lower its required minimum.');
  }
  const alphabet = categories.map(c => c.characters).join('');
  if (!alphabet.length) error('EMPTY_ALPHABET', 'allowed', 'Enable a category and permit at least one character after exclusions.');
  const required = CATEGORIES.reduce((total, id) => total + checked.minimumCounts[id], 0);
  if (required > checked.length)
    error('INSUFFICIENT_LENGTH', 'length', 'Increase length to at least ' + required + ' or lower the required category counts.');
  if (errors.length) return { ok: false, errors };
  const policy: NormalizedPolicy = Object.freeze({ length: checked.length, allowed: Object.freeze({ ...checked.allowed }),
    minimumCounts: Object.freeze({ ...checked.minimumCounts }), permittedSymbols: symbols,
    excludedCharacters: exclusions, excludeAmbiguous: checked.excludeAmbiguous,
    categories: Object.freeze(categories), alphabet });
  normalizedPolicies.add(policy);
  return { ok: true, policy };
}

// C(n,k) counts ways to interleave a new category's k characters with n-k
// previously counted characters. The table is fixed-size, exact and reused.
const choose: bigint[][] = [[1n]];
for (let n = 1; n <= MAX_POLICY_LENGTH; n++) {
  const previous = choose[n - 1]!;
  choose.push(Array.from({ length: n + 1 }, (_, k) => k === 0 || k === n ? 1n : previous[k - 1]! + previous[k]!));
}

export function countCompletions(policy: NormalizedPolicy, remainingLength: number,
  remainingMinimumCounts?: CategoryCounts): bigint {
  if (!normalizedPolicies.has(policy) || !Number.isInteger(remainingLength) || remainingLength < 0 || remainingLength > policy.length)
    throw new RangeError('Use a normalized policy and a remaining length from zero to its original length.');
  // Read external descriptors once, rejecting accessors/proxies that cannot be
  // inspected. Only detached, validated numeric values reach the convolution.
  const raw = dataSnapshot(remainingMinimumCounts === undefined ? policy.minimumCounts : remainingMinimumCounts);
  if (!raw || !exactKeys(raw, CATEGORIES)
      || CATEGORIES.some(id => typeof raw[id] !== 'number' || !Number.isInteger(raw[id]) || raw[id] < 0
        || raw[id] > policy.minimumCounts[id]))
    throw new RangeError('Remaining category minima must be integers from zero to their original required counts.');
  const minima = Object.freeze(raw) as unknown as CategoryCounts;
  if (CATEGORIES.reduce((total, id) => total + minima[id], 0) > remainingLength) return 0n;
  return convolution(policy, remainingLength, minima).levels[4]![remainingLength]!;
}

export interface PolicyCountingTable {
  readonly policy: NormalizedPolicy;
  readonly levels: readonly (readonly bigint[])[];
  readonly powers: readonly (readonly bigint[])[];
  readonly binomial: readonly (readonly bigint[])[];
  readonly totalCount: bigint;
}
// Fixed, public combinatorial numbers are immutable when shared with ranking.
for (const row of choose) Object.freeze(row);
Object.freeze(choose);
function convolution(policy: NormalizedPolicy, remainingLength: number, remainingMinimumCounts: CategoryCounts): PolicyCountingTable {
  let counts: bigint[] = Array(remainingLength + 1).fill(0n); counts[0] = 1n;
  const levels: (readonly bigint[])[] = [Object.freeze(counts)];
  const allPowers: (readonly bigint[])[] = [];
  for (const category of policy.categories) {
    const size = BigInt(category.characters.length), minimum = remainingMinimumCounts[category.id];

    const powers = [1n];
    for (let k = 1; k <= remainingLength; k++) powers.push(powers[k - 1]! * size);
    const next: bigint[] = Array(remainingLength + 1).fill(0n);
    for (let used = 0; used <= remainingLength; used++) {
      if (counts[used] === 0n) continue;
      const maximum = size === 0n ? 0 : remainingLength - used;
      for (let k = minimum; k <= maximum; k++) {
        next[used + k] = next[used + k]! + counts[used]! * choose[used + k]![k]! * powers[k]!;
      }
    }
    allPowers.push(Object.freeze(powers));
    counts = next; levels.push(Object.freeze(counts));
  }
  return Object.freeze({ policy, levels: Object.freeze(levels), powers: Object.freeze(allPowers),
    binomial: choose, totalCount: counts[remainingLength]! });
}

export function buildPolicyCountingTable(policy: NormalizedPolicy): PolicyCountingTable {
  if (!normalizedPolicies.has(policy)) throw new RangeError('Use an immutable normalized policy from this module.');
  return convolution(policy, policy.length, policy.minimumCounts);
}

export function countValidPasswords(policy: NormalizedPolicy): bigint {
  return countCompletions(policy, policy.length);
}

export function assessEntropy(count: bigint): EntropyAssessment {
  if (typeof count !== 'bigint' || count < 1n || count > MAXIMUM_COUNT)
    throw new RangeError('Entropy assessment requires a positive exact count within the printable-ASCII/128-character limit.');
  const floorBits = count.toString(2).length - 1;
  // floor(log2(N^100)) = floor(100*log2(N)): exact downward rounding to
  // hundredths without floating-point logarithms, including the 2^64 boundary.
  const hundredths = (count ** 100n).toString(2).length - 1;
  return Object.freeze({ meetsMinimum: count >= MINIMUM_COUNT, floorBits,
    estimatedBitsText: Math.floor(hundredths / 100) + '.' + String(hundredths % 100).padStart(2, '0'),
    description: 'Estimated entropy derived from the exact count, rounded down to 0.01 bits; assumes uniform sampling. Not an offline-attack guarantee.' });
}

export function analyzePolicy(input: PasswordPolicyInput): PolicyAnalysis {
  const normalized = normalizePolicy(input);
  if (!normalized.ok) return { kind: 'invalid', errors: normalized.errors };
  const validPasswordCount = countValidPasswords(normalized.policy);
  const entropy = assessEntropy(validPasswordCount);
  const errors: PolicyError[] = entropy.meetsMinimum ? [] : [{ code: 'INSUFFICIENT_ENTROPY', field: 'policy',
    message: 'Fewer than 2^64 valid passwords remain. Increase length or permit more characters without weakening required categories.' }];
  return { kind: entropy.meetsMinimum ? 'eligible' : 'ineligible', policy: normalized.policy, validPasswordCount, entropy, errors };
}
