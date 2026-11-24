'use strict';

/**
 * OIDC Token Provider for Databricks workload identity federation.
 *
 * Mints a GitHub Actions OIDC token and exchanges it at the workspace OAuth
 * token endpoint (RFC 8693 token exchange) for a Databricks OAuth access token,
 * which the sidecar then injects as `Authorization: Bearer <token>`.
 *
 * Token flow:
 *   1. Request a GitHub OIDC JWT whose audience matches the Databricks
 *      federation policy (Databricks recommends the account ID)
 *   2. POST it to https://<workspace-host>/oidc/v1/token with
 *      grant_type=urn:ietf:params:oauth:grant-type:token-exchange and
 *      scope=all-apis, plus client_id for service principal federation policies
 *   3. Cache the token and refresh at 75% of its lifetime
 *
 * Databricks issues the access token with the same expiry as the subject JWT
 * and returns no refresh token, so every refresh mints a fresh GitHub JWT.
 *
 * @see https://docs.databricks.com/aws/en/dev-tools/auth/oauth-federation-exchange
 */

const { mintGitHubOidcToken, httpPost } = require('./github-oidc');
const { BaseOidcTokenProvider, REFRESH_FACTOR } = require('./oidc-token-provider-base');

const DATABRICKS_TOKEN_PATH = '/oidc/v1/token';
const DEFAULT_DATABRICKS_SCOPE = 'all-apis';
/**
 * Lifetime assumed when the exchange response omits `expires_in`. Databricks
 * tokens never outlive the GitHub JWT they were exchanged from, so assume a
 * short lifetime rather than serving an expired token.
 */
const DEFAULT_TOKEN_LIFETIME_SECS = 300;
const MAX_TOKEN_LIFETIME_SECS = 3600;
/** Floor on the proactive refresh delay, so a tiny `expires_in` cannot cause a hot refresh loop. */
const MIN_REFRESH_DELAY_SECS = 10;
const MAX_ERROR_DETAIL_LENGTH = 200;

const INVALID_HOST_MESSAGE =
  'Invalid Databricks host: expected an https:// workspace URL such as https://<workspace>.cloud.databricks.com';

/**
 * Resolve the workspace OAuth token endpoint from a Databricks host.
 *
 * Accepts the same forms as DATABRICKS_HOST (bare hostname or https URL). Any
 * path, query or fragment is dropped, so a pasted workspace URL such as
 * `https://adb-123.4.azuredatabricks.net/?o=123` still resolves to its origin.
 *
 * @param {string|undefined} host
 * @returns {string}
 */
function resolveDatabricksTokenEndpoint(host) {
  const value = typeof host === 'string' ? host.trim() : '';
  if (!value) {
    throw new Error('DatabricksOidcTokenProvider requires host');
  }
  let url;
  try {
    url = new URL(/^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(value) ? value : `https://${value}`);
  } catch {
    throw new Error(INVALID_HOST_MESSAGE);
  }
  // The GitHub JWT is a bearer credential: never send it in cleartext or to a
  // URL carrying userinfo.
  if (url.protocol !== 'https:' || !url.hostname || url.username || url.password) {
    throw new Error(INVALID_HOST_MESSAGE);
  }
  return `${url.origin}${DATABRICKS_TOKEN_PATH}`;
}

/**
 * Normalize `expires_in` from the exchange response to a usable lifetime.
 * @param {unknown} value
 * @returns {number}
 */
function normalizeLifetime(value) {
  const seconds = Number(value);
  if (!Number.isFinite(seconds) || seconds <= 0) return DEFAULT_TOKEN_LIFETIME_SECS;
  return Math.min(Math.floor(seconds), MAX_TOKEN_LIFETIME_SECS);
}

/**
 * Extract the OAuth error code/description from a failed exchange for logs.
 * The raw body is never echoed; the subject JWT is redacted defensively.
 *
 * @param {string} body
 * @param {string} subjectToken
 * @returns {string}
 */
function describeOAuthError(body, subjectToken) {
  let data;
  try {
    data = JSON.parse(body);
  } catch {
    return '';
  }
  if (!data || typeof data.error !== 'string' || !data.error) return '';
  const description = typeof data.error_description === 'string' ? data.error_description : '';
  const detail = description ? `${data.error}: ${description}` : data.error;
  const redacted = subjectToken ? detail.split(subjectToken).join('[redacted]') : detail;
  return ` (${redacted.slice(0, MAX_ERROR_DETAIL_LENGTH)})`;
}

/**
 * @typedef {Object} DatabricksOidcTokenProviderConfig
 * @property {string} requestUrl - ACTIONS_ID_TOKEN_REQUEST_URL
 * @property {string} requestToken - ACTIONS_ID_TOKEN_REQUEST_TOKEN
 * @property {string} host - Databricks workspace host or URL
 * @property {string} oidcAudience - Audience allowed by the Databricks federation policy
 * @property {string} [clientId] - Service principal application ID (omit for account-wide federation policies)
 * @property {string} [scope] - OAuth scope (default: all-apis)
 * @property {number} [retryDelayMs] - Retry delay after failed refresh (default: 30000)
 * @property {number} [maxInitRetries] - Maximum retries for initial token acquisition (default: 3)
 */

class DatabricksOidcTokenProvider extends BaseOidcTokenProvider {
  /**
   * @param {DatabricksOidcTokenProviderConfig} config
   */
  constructor(config) {
    super('databricks_oidc', config);
    const oidcAudience = (config.oidcAudience || '').trim();
    if (!oidcAudience) {
      throw new Error('DatabricksOidcTokenProvider requires oidcAudience (the audience in your Databricks federation policy)');
    }

    this._requestUrl = config.requestUrl;
    this._requestToken = config.requestToken;
    this._tokenEndpoint = resolveDatabricksTokenEndpoint(config.host);
    this._clientId = (config.clientId || '').trim() || undefined;
    this._scope = (config.scope || '').trim() || DEFAULT_DATABRICKS_SCOPE;
    this._oidcAudience = oidcAudience;
    this._cachedToken = null;
    this._httpPost = httpPost;
  }

  /**
   * Exchange a GitHub OIDC JWT for a Databricks OAuth access token.
   * @param {string} oidcJwt
   * @returns {Promise<{access_token: string, expires_in: number}>}
   */
  async _exchangeForDatabricksToken(oidcJwt) {
    const params = {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      subject_token: oidcJwt,
      scope: this._scope,
    };
    // Required for service principal federation policies; Databricks rejects it
    // for account-wide federation policies.
    if (this._clientId) params.client_id = this._clientId;

    let response;
    try {
      response = await this._httpPost(this._tokenEndpoint, new URLSearchParams(params).toString(), {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      });
    } catch (err) {
      if (err?.message === 'Token exchange timeout') {
        throw new Error('Databricks token exchange timeout');
      }
      throw err;
    }

    if (response.statusCode !== 200) {
      throw new Error(
        `Databricks token exchange failed: HTTP ${response.statusCode}${describeOAuthError(response.body, oidcJwt)}`,
      );
    }

    let data;
    try {
      data = JSON.parse(response.body);
    } catch {
      throw new Error('Databricks token response is not valid JSON');
    }
    if (typeof data?.access_token !== 'string' || !data.access_token) {
      throw new Error('Databricks token response missing "access_token" field');
    }
    return { access_token: data.access_token, expires_in: normalizeLifetime(data.expires_in) };
  }

  async _refreshToken() {
    const oidcJwt = await mintGitHubOidcToken({
      requestUrl: this._requestUrl,
      requestToken: this._requestToken,
      audience: this._oidcAudience,
    });
    const { access_token, expires_in } = await this._exchangeForDatabricksToken(oidcJwt);
    this._storeAndScheduleRefresh(access_token, expires_in);
  }

  /**
   * Databricks tokens expire with the subject JWT, which can be minutes away,
   * so refresh at a fixed fraction of the lifetime instead of keeping the base
   * class's 5-minute margin (which would refresh continuously).
   *
   * @param {number} expiresIn
   * @returns {number}
   */
  _getRefreshDelaySecs(expiresIn) {
    return Math.max(MIN_REFRESH_DELAY_SECS, expiresIn * REFRESH_FACTOR);
  }

  async _doRefresh() {
    await this._refreshToken();
  }

  _getCachedValue() {
    return this._cachedToken;
  }

  _setCachedValue(value) {
    this._cachedToken = value;
  }

  _getInitSuccessLogContext() {
    return {
      scope: this._scope,
      client_id_configured: !!this._clientId,
      expires_in_secs: this._expiresAt - Math.floor(Date.now() / 1000),
    };
  }

  _getInitFailureLogContext() {
    return {
      scope: this._scope,
      client_id_configured: !!this._clientId,
    };
  }
}

module.exports = {
  DatabricksOidcTokenProvider,
  resolveDatabricksTokenEndpoint,
  DATABRICKS_TOKEN_PATH,
  DEFAULT_DATABRICKS_SCOPE,
  DEFAULT_TOKEN_LIFETIME_SECS,
  MAX_TOKEN_LIFETIME_SECS,
  MIN_REFRESH_DELAY_SECS,
};
