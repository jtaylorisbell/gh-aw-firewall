import { isDatabricksOidcConfigured, isDatabricksOidcRoutedFor } from './databricks-oidc-config';
import type { WrapperConfig } from '../../types';

const DATABRICKS_CONFIG = {
  authType: 'github-oidc',
  authProvider: 'databricks',
  authDatabricksHost: 'https://dbc-1234.cloud.databricks.com',
  authOidcAudience: 'databricks-account-id',
} as WrapperConfig;

const ENV_NAMES = [
  'AWF_AUTH_TYPE',
  'AWF_AUTH_PROVIDER',
  'AWF_AUTH_DATABRICKS_HOST',
  'AWF_AUTH_OIDC_AUDIENCE',
  'OPENAI_API_TARGET',
  'ANTHROPIC_API_TARGET',
];

describe('databricks-oidc-config', () => {
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    for (const name of ENV_NAMES) {
      saved[name] = process.env[name];
      delete process.env[name];
    }
  });

  afterEach(() => {
    for (const name of ENV_NAMES) {
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
    }
  });

  describe('isDatabricksOidcConfigured', () => {
    it('is true when auth type, provider, host, and audience are set', () => {
      expect(isDatabricksOidcConfigured(DATABRICKS_CONFIG)).toBe(true);
    });

    it.each(['authDatabricksHost', 'authOidcAudience'] as const)('is false without %s', (key) => {
      expect(isDatabricksOidcConfigured({ ...DATABRICKS_CONFIG, [key]: '  ' })).toBe(false);
    });

    it('is false for other providers', () => {
      expect(isDatabricksOidcConfigured({ ...DATABRICKS_CONFIG, authProvider: 'azure' })).toBe(false);
    });

    it('resolves values from --env and host env like the sidecar forwarding does', () => {
      process.env.AWF_AUTH_TYPE = 'github-oidc';
      process.env.AWF_AUTH_PROVIDER = 'Databricks';
      const config = {
        additionalEnv: {
          AWF_AUTH_DATABRICKS_HOST: 'dbc-1234.cloud.databricks.com',
          AWF_AUTH_OIDC_AUDIENCE: 'databricks-account-id',
        },
      } as unknown as WrapperConfig;
      expect(isDatabricksOidcConfigured(config)).toBe(true);
    });
  });

  describe('isDatabricksOidcRoutedFor', () => {
    it('routes only providers whose upstream target is explicit', () => {
      const config = { ...DATABRICKS_CONFIG, anthropicApiTarget: 'dbc-1234.cloud.databricks.com' } as WrapperConfig;
      expect(isDatabricksOidcRoutedFor(config, 'anthropic')).toBe(true);
      expect(isDatabricksOidcRoutedFor(config, 'openai')).toBe(false);
    });

    it('treats a secret-backed OpenAI base URL as an explicit target', () => {
      const config = { ...DATABRICKS_CONFIG, openaiBaseUrlEnv: 'DATABRICKS_SERVING_URL' } as WrapperConfig;
      expect(isDatabricksOidcRoutedFor(config, 'openai')).toBe(true);
    });

    it('reads explicit targets from the host environment', () => {
      process.env.OPENAI_API_TARGET = 'dbc-1234.cloud.databricks.com';
      expect(isDatabricksOidcRoutedFor(DATABRICKS_CONFIG, 'openai')).toBe(true);
    });

    it('does not route when Databricks OIDC is incomplete', () => {
      const config = {
        ...DATABRICKS_CONFIG,
        authOidcAudience: undefined,
        anthropicApiTarget: 'dbc-1234.cloud.databricks.com',
      } as WrapperConfig;
      expect(isDatabricksOidcRoutedFor(config, 'anthropic')).toBe(false);
    });
  });
});
