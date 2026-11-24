jest.mock('../../logger', () => ({
  logger: { debug: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn() },
}));

jest.mock('../../env-utils', () => ({
  getLowerCaseProcessEnvValue: jest.fn(),
  getConfigEnvValue: jest.fn(),
}));

import { buildAnthropicCredentialEnv } from './anthropic-credential-env';
import type { WrapperConfig } from '../../types';
import { getLowerCaseProcessEnvValue } from '../../env-utils';

const mockGetLowerCaseProcessEnvValue = getLowerCaseProcessEnvValue as jest.MockedFunction<
  typeof getLowerCaseProcessEnvValue
>;

const baseConfig = {} as WrapperConfig;
const proxyIp = '172.30.0.30';

describe('buildAnthropicCredentialEnv', () => {
  beforeEach(() => {
    mockGetLowerCaseProcessEnvValue.mockReturnValue('');
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('returns empty object when no anthropic credentials configured', () => {
    const result = buildAnthropicCredentialEnv({ config: baseConfig, proxyIp });
    expect(result).toEqual({});
  });

  it('routes through the proxy for Databricks OIDC with an explicit Anthropic target', () => {
    const config = {
      ...baseConfig,
      authType: 'github-oidc',
      authProvider: 'databricks',
      authDatabricksHost: 'https://dbc-1234.cloud.databricks.com',
      authOidcAudience: 'databricks-account-id',
      anthropicApiTarget: 'dbc-1234.cloud.databricks.com',
    } as WrapperConfig;

    const result = buildAnthropicCredentialEnv({ config, proxyIp });

    expect(result.ANTHROPIC_BASE_URL).toBe(`http://${proxyIp}:10001`);
    expect(result.ANTHROPIC_AUTH_TOKEN).toMatch(/^sk-ant-/);
    expect(result.CLAUDE_CODE_API_KEY_HELPER).toBe('/usr/local/bin/get-claude-key.sh');
  });

  it('does not route Databricks OIDC when the Anthropic target is left at its default', () => {
    const config = {
      ...baseConfig,
      authType: 'github-oidc',
      authProvider: 'databricks',
      authDatabricksHost: 'https://dbc-1234.cloud.databricks.com',
      authOidcAudience: 'databricks-account-id',
    } as WrapperConfig;
    expect(buildAnthropicCredentialEnv({ config, proxyIp })).toEqual({});
  });

  it('returns env additions when anthropicApiKey is set', () => {
    const config = { ...baseConfig, anthropicApiKey: 'sk-ant-real-key' } as WrapperConfig;
    const result = buildAnthropicCredentialEnv({ config, proxyIp });
    expect(result.ANTHROPIC_BASE_URL).toBe(`http://${proxyIp}:10001`);
    // Placeholder must pass Claude Code's sk-ant- prefix validation
    expect(result.ANTHROPIC_AUTH_TOKEN).toMatch(/^sk-ant-/);
    expect(result.CLAUDE_CODE_API_KEY_HELPER).toBe('/usr/local/bin/get-claude-key.sh');
  });

  it('returns env additions when auth type is github-oidc with anthropic provider', () => {
    mockGetLowerCaseProcessEnvValue.mockImplementation((key: string) => {
      if (key === 'AWF_AUTH_TYPE') return 'github-oidc';
      if (key === 'AWF_AUTH_PROVIDER') return 'anthropic';
      return '';
    });
    const result = buildAnthropicCredentialEnv({ config: baseConfig, proxyIp });
    expect(result.ANTHROPIC_BASE_URL).toContain(proxyIp);
    expect(result.ANTHROPIC_AUTH_TOKEN).toBeDefined();
  });

  it('returns empty object when auth type is github-oidc but provider is not anthropic', () => {
    mockGetLowerCaseProcessEnvValue.mockImplementation((key: string) => {
      if (key === 'AWF_AUTH_TYPE') return 'github-oidc';
      if (key === 'AWF_AUTH_PROVIDER') return 'openai';
      return '';
    });
    const result = buildAnthropicCredentialEnv({ config: baseConfig, proxyIp });
    expect(result).toEqual({});
  });

  it('ANTHROPIC_AUTH_TOKEN placeholder has sk-ant- prefix for Claude Code key-format validation', () => {
    const config = { ...baseConfig, anthropicApiKey: 'sk-ant-test' } as WrapperConfig;
    const result = buildAnthropicCredentialEnv({ config, proxyIp });
    expect(result.ANTHROPIC_AUTH_TOKEN).toMatch(/^sk-ant-/);
  });

  it('real anthropicApiKey is NOT present in agent env (credential isolation)', () => {
    const realKey = 'sk-ant-real-secret-key';
    const config = { ...baseConfig, anthropicApiKey: realKey } as WrapperConfig;
    const result = buildAnthropicCredentialEnv({ config, proxyIp });
    expect(Object.values(result)).not.toContain(realKey);
  });

  it('ANTHROPIC_API_KEY is NOT set in returned env (excluded for credential isolation)', () => {
    const config = { ...baseConfig, anthropicApiKey: 'sk-ant-test' } as WrapperConfig;
    const result = buildAnthropicCredentialEnv({ config, proxyIp });
    expect(result.ANTHROPIC_API_KEY).toBeUndefined();
  });

  it('routes to Anthropic port 10001 specifically', () => {
    const config = { ...baseConfig, anthropicApiKey: 'sk-ant-test' } as WrapperConfig;
    const result = buildAnthropicCredentialEnv({ config, proxyIp });
    expect(result.ANTHROPIC_BASE_URL).toMatch(/:10001$/);
  });
});
