import { MIN_ENTROPY_BITS } from './core.js';
import { analyzePolicy, buildPolicyCountingTable, countCompletions, type PasswordPolicyInput,
  type NormalizedPolicy, type PolicyCountingTable, type PolicyError } from './policy.js';

export type ByteRandomSource = (buffer: Uint8Array<ArrayBuffer>) => Uint8Array<ArrayBuffer>;
const secureBytes: ByteRandomSource = buffer => {
  if (typeof globalThis.crypto?.getRandomValues !== 'function') throw new Error('Secure browser randomness is unavailable.');
  return globalThis.crypto.getRandomValues(buffer);
};
const MAXIMUM_COUNT = 95n ** 128n;
const ZERO_COUNTS = Object.freeze({ uppercase: 0, lowercase: 0, digits: 0, symbols: 0 });

export class PolicyGenerationError extends Error {
  readonly errors: readonly PolicyError[];
  constructor(errors: readonly PolicyError[]) {
    super('Password policy is invalid or below the 64-bit minimum.');
    this.name = 'PolicyGenerationError';
    this.errors = Object.freeze(errors.map(error => Object.freeze({ ...error })));
  }
}

export function randomBigIntBelow(bound: bigint, random: ByteRandomSource = secureBytes): bigint {
  if (typeof bound !== 'bigint' || bound < 1n || bound > MAXIMUM_COUNT) throw new RangeError('Use a positive supported exact rank bound.');
  if (bound === 1n) return 0n; // Mathematical singleton; never an eligible generator.
  const bits = (bound - 1n).toString(2).length;
  const bytes = new Uint8Array(Math.ceil(bits / 8));
  const mask = (1 << ((bits - 1) % 8 + 1)) - 1;
  // Mask unused high bits, then reject the entire out-of-range rank. A bounded
  // failure never substitutes/modulos a rejected value. Success stays uniform.
  for (let attempt = 0; attempt < 128; attempt++) {
    if (random(bytes) !== bytes) throw new Error('Secure random provider returned an unexpected buffer.');
    bytes[0] = bytes[0]! & mask;
    let rank = 0n;
    for (const byte of bytes) rank = (rank << 8n) | BigInt(byte);
    if (rank < bound) return rank;
  }
  throw new Error('Secure rank sampling exhausted its rejection limit.');
}

export function validatePolicyPassword(password: string, policy: NormalizedPolicy): boolean {
  try { countCompletions(policy, 0, ZERO_COUNTS); } catch { return false; }
  if (typeof password !== 'string' || password.length !== policy.length) return false;
  const counts = { ...ZERO_COUNTS };
  for (const character of password) {
    const category = policy.categories.find(group => group.characters.includes(character));
    if (!category || policy.excludedCharacters.includes(character)) return false;
    counts[category.id]++;
  }
  return policy.categories.every(group => counts[group.id] >= policy.minimumCounts[group.id]);
}

function mapRank(table: PolicyCountingTable, initialRank: bigint): string {
  if (typeof initialRank !== 'bigint' || initialRank < 0n || initialRank >= table.totalCount)
    throw new RangeError('Rank is outside the exact valid-password space.');
  // Decompose each convolution block into: prior-category string rank,
  // interleaving-position rank, and base-alphabet character rank. These are
  // exact suffix-completion counts; no prefix-state cache or shuffling is used.
  function decode(level: number, length: number, rank: bigint): string {
    if (!level) {
      if (length !== 0 || rank !== 0n) throw new Error('Rank mapping invariant failed.');
      return '';
    }
    const group = table.policy.categories[level - 1]!;
    for (let k = table.policy.minimumCounts[group.id]; k <= length; k++) {
      const prior = table.levels[level - 1]![length - k]!;
      const positions = table.binomial[length]![k]!;
      const characters = table.powers[level - 1]![k]!;
      const block = prior * positions * characters;
      if (rank >= block) { rank -= block; continue; }
      const characterRank = rank % characters;
      const quotient = rank / characters;
      let positionRank = quotient % positions;
      const previous = decode(level - 1, length - k, quotient / positions);
      const selectedCharacters: string[] = Array(k);
      let digits = characterRank;
      const base = BigInt(group.characters.length);
      for (let i = k - 1; i >= 0; i--) {
        selectedCharacters[i] = group.characters[Number(digits % base)]!;
        digits /= base;
      }
      let selected = 0, previousIndex = 0, required = k;
      const result: string[] = [];
      for (let position = 0; position < length; position++) {
        const choices = required ? table.binomial[length - position - 1]![required - 1] ?? 0n : 0n;
        if (required && positionRank < choices) {
          result.push(selectedCharacters[selected++]!); required--;
        } else {
          positionRank -= choices; result.push(previous[previousIndex++]!);
        }
      }
      if (required || positionRank || digits || previousIndex !== previous.length)
        throw new Error('Rank mapping invariant failed.');
      return result.join('');
    }
    throw new Error('Rank mapping invariant failed.');
  }
  const password = decode(4, table.policy.length, initialRank);
  if (!validatePolicyPassword(password, table.policy)) throw new Error('Generated password failed final policy validation.');
  return password;
}

// Deterministic counting/ranking primitive for exhaustive verification. It is
// not a secure-generation entry point and does not make an entropy claim.
export function passwordAtRank(policy: NormalizedPolicy, rank: bigint): string {
  return mapRank(buildPolicyCountingTable(policy), rank);
}

export interface RandomPasswordGenerator {
  readonly policy: NormalizedPolicy;
  readonly validPasswordCount: bigint;
  generate(random?: ByteRandomSource): string;
}
export function prepareRandomPasswordGenerator(input: PasswordPolicyInput): RandomPasswordGenerator {
  // Always re-normalize original inputs; never trust serialized assessment,
  // normalized output, alphabet, count or eligibility flags from a caller.
  const analysis = analyzePolicy(input);
  if (analysis.kind !== 'eligible') throw new PolicyGenerationError(analysis.errors);
  const table = buildPolicyCountingTable(analysis.policy);
  if (table.totalCount !== analysis.validPasswordCount || table.totalCount < (1n << BigInt(MIN_ENTROPY_BITS)))
    throw new Error('Exact policy-count verification failed.');
  // This handle retains only immutable public counts/settings, never output,
  // ranks, random buffers or providers. Reuse it for a batch; no global cache.
  return Object.freeze({ policy: table.policy, validPasswordCount: table.totalCount,
    generate(random: ByteRandomSource = secureBytes): string {
      return mapRank(table, randomBigIntBelow(table.totalCount, random));
    } });
}
export function generateRandomPassword(input: PasswordPolicyInput, random?: ByteRandomSource): string {
  return prepareRandomPasswordGenerator(input).generate(random);
}
