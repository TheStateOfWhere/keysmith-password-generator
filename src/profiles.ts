import { generatePassword, SYMBOLS, type Settings, type RandomSource } from './core.js';
import { CATEGORIES, type AllowedCategories, type PasswordPolicyInput } from './policy.js';
import { generateRandomPassword, PolicyGenerationError, type ByteRandomSource } from './random-password.js';

export type ProfileId = 'readable' | 'strong-random' | 'custom-policy';
export type ReadableProfileSettings = Settings;
export interface StrongRandomProfileSettings {
  readonly length: number;
  readonly allowed: AllowedCategories;
  readonly excludedCharacters: string;
  readonly excludeAmbiguous: boolean;
}
export const STRONG_RANDOM_DEFAULTS: StrongRandomProfileSettings = Object.freeze({ length: 20,
  allowed: Object.freeze({ uppercase: true, lowercase: true, digits: true, symbols: true }),
  excludedCharacters: '', excludeAmbiguous: true });
type ReadableRequest = { profile: 'readable'; settings: ReadableProfileSettings };
type RandomRequest = { profile: 'strong-random'; settings?: StrongRandomProfileSettings }
  | { profile: 'custom-policy'; settings: PasswordPolicyInput };
export type ProfileRequest = ReadableRequest | RandomRequest;
export interface ProfileDispatcher {
  (request: ReadableRequest, dictionary: readonly string[], random?: RandomSource): string;
  (request: RandomRequest, dictionary: readonly string[], random?: ByteRandomSource): string;
}
export class UnsupportedProfileError extends Error {
  constructor() { super('Selected password profile is not implemented.'); this.name = 'UnsupportedProfileError'; }
}
function strongPolicy(settings: StrongRandomProfileSettings): PasswordPolicyInput {
  const invalid = () => { throw new PolicyGenerationError([{ code: 'INVALID_POLICY', field: 'settings',
    message: 'Supply only Strong Random length, allowed categories, exclusions and ambiguity settings as data fields.' }]); };
  const data = (value: unknown, keys: readonly string[]): Record<string, unknown> => {
    try {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) return invalid();
      const prototype = Object.getPrototypeOf(value);
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if ((prototype !== Object.prototype && prototype !== null) || Reflect.ownKeys(descriptors).length !== keys.length
        || keys.some(key => !descriptors[key] || !Object.hasOwn(descriptors[key], 'value'))) return invalid();
      return Object.fromEntries(keys.map(key => [key, descriptors[key]!.value]));
    } catch { return invalid(); }
  };
  const raw = data(settings, ['length', 'allowed', 'excludedCharacters', 'excludeAmbiguous']);
  const groups = data(raw.allowed, CATEGORIES);
  if (CATEGORIES.some(id => typeof groups[id] !== 'boolean')) return invalid();
  const allowed = groups as unknown as AllowedCategories;
  return { length: raw.length as number, allowed, permittedSymbols: SYMBOLS,
    minimumCounts: { uppercase: allowed.uppercase ? 1 : 0, lowercase: allowed.lowercase ? 1 : 0,
      digits: allowed.digits ? 1 : 0, symbols: allowed.symbols ? 1 : 0 },
    excludedCharacters: raw.excludedCharacters as string, excludeAmbiguous: raw.excludeAmbiguous as boolean };
}
// Shared conversion for interface analysis and generation; category minima
// remain a generator policy rule rather than a second DOM implementation.
export function policyForProfile(request: Exclude<ProfileRequest, { profile: 'readable' }>): PasswordPolicyInput {
  return request.profile === 'strong-random'
    ? strongPolicy(request.settings === undefined ? STRONG_RANDOM_DEFAULTS : request.settings) : request.settings;
}
export const generateProfilePassword: ProfileDispatcher = (request: ProfileRequest, dictionary: readonly string[], random?: RandomSource | ByteRandomSource) => {
  switch (request.profile) {
    case 'readable': return generatePassword(dictionary, request.settings, random as RandomSource | undefined);
    case 'strong-random':
    case 'custom-policy': return generateRandomPassword(policyForProfile(request), random as ByteRandomSource | undefined);
    default: throw new UnsupportedProfileError();
  }
};
