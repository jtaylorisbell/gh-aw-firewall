'use strict';

jest.mock('./github-oidc', () => ({
  mintGitHubOidcToken: jest.fn(),
  httpPost: jest.fn(),
}));

const { mintGitHubOidcToken, httpPost } = require('./github-oidc');
const {
  DatabricksOidcTokenProvider,
  resolveDatabricksTokenEndpoint,
  DEFAULT_TOKEN_LIFETIME_SECS,
  MAX_TOKEN_LIFETIME_SECS,
  MIN_REFRESH_DELAY_SECS,
} = require('./databricks-oidc-token-provider');

const CONFIG = {
  requestUrl: 'https://actions.example/oidc',
  requestToken: 'actions-token',
  host: 'https://dbc-1234.cloud.databricks.com',
  clientId: 'sp-application-id',
  oidcAudience: 'databricks-account-id',
  retryDelayMs: 1,
  maxInitRetries: 1,
};

function formBody(call) {
  return Object.fromEntries(new URLSearchParams(call[1]));
}

describe('resolveDatabricksTokenEndpoint', () => {
  it.each([
    ['https://dbc-1234.cloud.databricks.com', 'https://dbc-1234.cloud.databricks.com/oidc/v1/token'],
    ['dbc-1234.cloud.databricks.com', 'https://dbc-1234.cloud.databricks.com/oidc/v1/token'],
    ['https://dbc-1234.cloud.databricks.com/', 'https://dbc-1234.cloud.databricks.com/oidc/v1/token'],
    ['  https://adb-1.2.azuredatabricks.net/?o=1  ', 'https://adb-1.2.azuredatabricks.net/oidc/v1/token'],
    ['https://dbc-1234.cloud.databricks.com/serving-endpoints', 'https://dbc-1234.cloud.databricks.com/oidc/v1/token'],
  ])('resolves %p to %p', (host, expected) => {
    expect(resolveDatabricksTokenEndpoint(host)).toBe(expected);
  });

  it.each([
    ['http://dbc-1234.cloud.databricks.com'],
    ['https://user:pass@dbc-1234.cloud.databricks.com'],
    ['ftp://dbc-1234.cloud.databricks.com'],
    ['https://'],
  ])('rejects %p', (host) => {
    expect(() => resolveDatabricksTokenEndpoint(host)).toThrow('Invalid Databricks host');
  });

  it('requires a host', () => {
    expect(() => resolveDatabricksTokenEndpoint('  ')).toThrow('requires host');
  });
});

describe('DatabricksOidcTokenProvider', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mintGitHubOidcToken.mockResolvedValue('github-jwt');
    httpPost.mockResolvedValue({
      statusCode: 200,
      body: JSON.stringify({ access_token: 'dbx-oauth-token', token_type: 'Bearer', expires_in: 3600, scope: 'all-apis' }),
    });
  });

  it('mints a GitHub JWT for the configured audience and exchanges it at the workspace token endpoint', async () => {
    const provider = new DatabricksOidcTokenProvider(CONFIG);

    await provider.initialize();

    expect(mintGitHubOidcToken).toHaveBeenCalledWith({
      requestUrl: CONFIG.requestUrl,
      requestToken: CONFIG.requestToken,
      audience: 'databricks-account-id',
    });
    expect(httpPost).toHaveBeenCalledTimes(1);
    const call = httpPost.mock.calls[0];
    expect(call[0]).toBe('https://dbc-1234.cloud.databricks.com/oidc/v1/token');
    expect(formBody(call)).toEqual({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      subject_token: 'github-jwt',
      scope: 'all-apis',
      client_id: 'sp-application-id',
    });
    expect(call[2]).toEqual({
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
    });
    expect(provider.isReady()).toBe(true);
    expect(provider.getToken()).toBe('dbx-oauth-token');

    provider.shutdown();
  });

  it('omits client_id for account-wide federation policies', async () => {
    const provider = new DatabricksOidcTokenProvider({ ...CONFIG, clientId: '  ' });

    await provider.initialize();

    expect(formBody(httpPost.mock.calls[0])).not.toHaveProperty('client_id');
    provider.shutdown();
  });

  it('uses a configured scope', async () => {
    const provider = new DatabricksOidcTokenProvider({ ...CONFIG, scope: 'serving-endpoints' });

    await provider.initialize();

    expect(formBody(httpPost.mock.calls[0]).scope).toBe('serving-endpoints');
    provider.shutdown();
  });

  it('requires an OIDC audience', () => {
    expect(() => new DatabricksOidcTokenProvider({ ...CONFIG, oidcAudience: '' })).toThrow('requires oidcAudience');
  });

  it('rejects a non-https host at construction', () => {
    expect(() => new DatabricksOidcTokenProvider({ ...CONFIG, host: 'http://dbc-1234.cloud.databricks.com' }))
      .toThrow('Invalid Databricks host');
  });

  it('reports the OAuth error code and description without echoing the subject token', async () => {
    const provider = new DatabricksOidcTokenProvider(CONFIG);
    httpPost.mockResolvedValue({
      statusCode: 400,
      body: JSON.stringify({
        error: 'invalid_request',
        error_description: 'Token audience does not match policy for github-jwt',
      }),
    });

    const error = await provider._exchangeForDatabricksToken('github-jwt').catch(err => err);

    expect(error.message).toBe(
      'Databricks token exchange failed: HTTP 400 (invalid_request: Token audience does not match policy for [redacted])',
    );
    provider.shutdown();
  });

  it('does not include non-OAuth response bodies in errors', async () => {
    const provider = new DatabricksOidcTokenProvider(CONFIG);
    httpPost.mockResolvedValue({ statusCode: 502, body: '<html>upstream body</html>' });

    await expect(provider._exchangeForDatabricksToken('github-jwt'))
      .rejects.toThrow(/^Databricks token exchange failed: HTTP 502$/);
    provider.shutdown();
  });

  it('rejects responses without an access token', async () => {
    const provider = new DatabricksOidcTokenProvider(CONFIG);
    httpPost.mockResolvedValue({ statusCode: 200, body: JSON.stringify({ token_type: 'Bearer' }) });

    await expect(provider._exchangeForDatabricksToken('github-jwt'))
      .rejects.toThrow('missing "access_token"');
    provider.shutdown();
  });

  it('maps the transport timeout to a Databricks-specific error', async () => {
    const provider = new DatabricksOidcTokenProvider(CONFIG);
    httpPost.mockRejectedValue(new Error('Token exchange timeout'));

    await expect(provider._exchangeForDatabricksToken('github-jwt'))
      .rejects.toThrow('Databricks token exchange timeout');
    provider.shutdown();
  });

  it.each([
    [undefined, DEFAULT_TOKEN_LIFETIME_SECS],
    [0, DEFAULT_TOKEN_LIFETIME_SECS],
    ['not-a-number', DEFAULT_TOKEN_LIFETIME_SECS],
    ['600', 600],
    [86_400, MAX_TOKEN_LIFETIME_SECS],
  ])('normalizes expires_in=%p to %p seconds', async (expiresIn, expected) => {
    const provider = new DatabricksOidcTokenProvider(CONFIG);
    httpPost.mockResolvedValue({
      statusCode: 200,
      body: JSON.stringify({ access_token: 'dbx-oauth-token', expires_in: expiresIn }),
    });

    await expect(provider._exchangeForDatabricksToken('github-jwt'))
      .resolves.toEqual({ access_token: 'dbx-oauth-token', expires_in: expected });
    provider.shutdown();
  });

  describe('refresh scheduling', () => {
    it('refreshes short-lived tokens at 75% of their lifetime instead of immediately', () => {
      const provider = new DatabricksOidcTokenProvider(CONFIG);
      // The base class keeps a 5-minute margin, which is 0 for a 5-minute token.
      expect(provider._getRefreshDelaySecs(300)).toBe(225);
      expect(provider._getRefreshDelaySecs(3600)).toBe(2700);
      provider.shutdown();
    });

    it('never schedules a proactive refresh sooner than the floor', () => {
      const provider = new DatabricksOidcTokenProvider(CONFIG);
      expect(provider._getRefreshDelaySecs(1)).toBe(MIN_REFRESH_DELAY_SECS);
      provider.shutdown();
    });

    it('schedules the next refresh from the exchanged lifetime', async () => {
      jest.useFakeTimers();
      try {
        httpPost.mockResolvedValue({
          statusCode: 200,
          body: JSON.stringify({ access_token: 'dbx-oauth-token', expires_in: 300 }),
        });
        const provider = new DatabricksOidcTokenProvider(CONFIG);
        await provider.initialize();
        expect(httpPost).toHaveBeenCalledTimes(1);

        await jest.advanceTimersByTimeAsync(224_000);
        expect(httpPost).toHaveBeenCalledTimes(1);

        await jest.advanceTimersByTimeAsync(1_000);
        expect(httpPost).toHaveBeenCalledTimes(2);
        expect(mintGitHubOidcToken).toHaveBeenCalledTimes(2);

        provider.shutdown();
      } finally {
        jest.useRealTimers();
      }
    });
  });

  it('does not log identifiers in init context', async () => {
    const provider = new DatabricksOidcTokenProvider(CONFIG);
    await provider.initialize();

    const contexts = JSON.stringify([provider._getInitSuccessLogContext(), provider._getInitFailureLogContext()]);
    expect(contexts).not.toContain('sp-application-id');
    expect(contexts).not.toContain('dbc-1234');
    expect(contexts).not.toContain('databricks-account-id');
    provider.shutdown();
  });
});
