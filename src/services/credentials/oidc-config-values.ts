import { WrapperConfig } from '../../types';
import { getConfigEnvValue } from '../../env-utils';

/**
 * Resolve an OIDC setting in the same order used by api-proxy env forwarding:
 * explicit config field, config-provided env value (--env/--env-file), then
 * host process env. Blank values are treated as unset.
 */
export function resolveConfigOrEnvValue(
  config: WrapperConfig,
  configKey: keyof WrapperConfig,
  envVar: string,
): string | undefined {
  const configValue = config[configKey];
  if (typeof configValue === 'string' && configValue.trim()) {
    return configValue.trim();
  }
  const configEnvValue = getConfigEnvValue(config, envVar)?.trim();
  if (configEnvValue) {
    return configEnvValue;
  }
  return process.env[envVar]?.trim() || undefined;
}
