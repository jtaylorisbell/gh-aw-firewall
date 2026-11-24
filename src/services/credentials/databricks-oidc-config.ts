import { WrapperConfig } from '../../types';
import { ANTHROPIC_ENV, OPENAI_ENV } from '../../api-proxy-env-constants';
import { resolveConfigOrEnvValue } from './oidc-config-values';

/**
 * Returns true when Databricks OAuth token federation is fully configured:
 * github-oidc auth type, databricks auth provider, a workspace host, and an
 * OIDC audience (Databricks has no default audience, so it must be explicit).
 * Values resolve in the same order used by api-proxy env forwarding.
 */
export function isDatabricksOidcConfigured(config: WrapperConfig): boolean {
  const authType = resolveConfigOrEnvValue(config, 'authType', 'AWF_AUTH_TYPE')?.toLowerCase();
  const authProvider = resolveConfigOrEnvValue(config, 'authProvider', 'AWF_AUTH_PROVIDER')?.toLowerCase();
  return authType === 'github-oidc'
    && authProvider === 'databricks'
    && !!resolveConfigOrEnvValue(config, 'authDatabricksHost', 'AWF_AUTH_DATABRICKS_HOST')
    && !!resolveConfigOrEnvValue(config, 'authOidcAudience', 'AWF_AUTH_OIDC_AUDIENCE');
}

/**
 * Returns true when Databricks OIDC alone (no static key) should route the
 * agent's `provider` client to the api-proxy sidecar.
 *
 * The sidecar binds cloud OIDC tokens only to an explicitly configured
 * upstream, so routing is enabled only when that provider's target is set.
 * If the sidecar still refuses the binding (e.g. conflicting target origins),
 * requests fail closed there with a Databricks-specific error.
 */
export function isDatabricksOidcRoutedFor(config: WrapperConfig, provider: 'openai' | 'anthropic'): boolean {
  if (!isDatabricksOidcConfigured(config)) return false;
  if (provider === 'openai') {
    return !!(resolveConfigOrEnvValue(config, 'openaiApiTarget', OPENAI_ENV.TARGET)
      || config.openaiBaseUrlEnv?.trim()
      || config.openaiTrustedService);
  }
  return !!(resolveConfigOrEnvValue(config, 'anthropicApiTarget', ANTHROPIC_ENV.TARGET)
    || config.anthropicTrustedService);
}
