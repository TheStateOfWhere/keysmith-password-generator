import { assertSettings, assertEntropyPolicy, eligibleWords, validatePassword } from './core.js';
import { generateProfilePassword, policyForProfile, type ProfileRequest, type ProfileId,
  type ReadableProfileSettings } from './profiles.js';
import { prepareRandomPasswordGenerator, validatePolicyPassword } from './random-password.js';
import type { NormalizedPolicy } from './policy.js';

export interface ProfileOutput {
  readonly profile: ProfileId;
  readonly settings: ReadableProfileSettings | NormalizedPolicy;
  generate(): string;
  validate(password: string): boolean;
}
// Each output context owns an immutable settings snapshot. Random contexts
// reuse public counting tables for a batch; no passwords/randomness are cached.
export function prepareProfileOutput(request: ProfileRequest, dictionary: readonly string[]): ProfileOutput {
  if (request.profile === 'readable') {
    const settings = Object.freeze({ ...request.settings });
    assertSettings(settings);
    const pool = Object.freeze(eligibleWords(dictionary, settings));
    assertEntropyPolicy(pool.length, settings.suffixLength);
    return Object.freeze({ profile: request.profile, settings,
      generate: () => generateProfilePassword({ profile: 'readable', settings }, dictionary),
      validate: (password: string) => validatePassword(password, pool, settings) });
  }
  const generator = prepareRandomPasswordGenerator(policyForProfile(request));
  return Object.freeze({ profile: request.profile, settings: generator.policy,
    generate: () => generator.generate(),
    validate: (password: string) => validatePolicyPassword(password, generator.policy) });
}
