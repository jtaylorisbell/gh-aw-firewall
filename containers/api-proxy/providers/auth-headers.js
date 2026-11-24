'use strict';
const { markCredentialHeaders, getHeaderCredentials } = require('../credential-protection');

/**
 * Shared auth-header construction helpers for provider adapters.
 *
 * Centralises the security-critical credential-injection patterns that appear
 * across multiple adapters so that changing an auth prefix, header name, or
 * integration-metadata key only requires a single edit.
 */

/**
 * Build an `Authorization` header using the given scheme prefix (e.g. `Bearer`,
 * `token`), optionally merged with extra headers.
 *
 * This is the single place that assembles an `Authorization` header value, so
 * every adapter that needs a non-default prefix (e.g. Copilot's Enterprise
 * `token <value>` scheme) composes it from here instead of concatenating the
 * prefix and token itself.
 *
 * @param {string} prefix - The auth scheme prefix (e.g. `Bearer`, `token`)
 * @param {string} token
 * @param {Record<string, string>} [extraHeaders]
 * @returns {Record<string, string>}
 */
function tokenAuthHeaders(prefix, token, extraHeaders) {
  return schemeAuthHeaders('Authorization', prefix, token, extraHeaders);
}

/**
 * Build `<headerName>: <scheme> <token>`, optionally merged with extra headers.
 *
 * @param {string} headerName
 * @param {string} scheme - The auth scheme prefix (e.g. `Bearer`)
 * @param {string} token
 * @param {Record<string, string>} [extraHeaders]
 * @returns {Record<string, string>}
 */
function schemeAuthHeaders(headerName, scheme, token, extraHeaders) {
  return markCredentialHeaders({ ...extraHeaders, [headerName]: scheme + ' ' + token }, [token]);
}

/**
 * Remove a leading `<scheme> ` from a credential, case-insensitively.
 *
 * Lets operators adopt an explicit auth scheme without first rewriting secrets
 * that already embed it (e.g. a secret stored as `Bearer <token>`), instead of
 * sending `Bearer Bearer <token>`.
 *
 * @param {string} scheme
 * @param {string} token
 * @returns {string}
 */
function stripAuthScheme(scheme, token) {
  if (typeof token !== 'string') return token;
  const prefix = scheme.toLowerCase() + ' ';
  return token.toLowerCase().startsWith(prefix) ? token.slice(prefix.length).trimStart() : token;
}

/**
 * Build a `Bearer` Authorization header, optionally merged with extra headers.
 *
 * @param {string} token
 * @param {Record<string, string>} [extraHeaders]
 * @returns {Record<string, string>}
 */
function bearerAuthHeaders(token, extraHeaders) {
  return tokenAuthHeaders('Bearer', token, extraHeaders);
}

/**
 * Build an auth header using a configurable HTTP header name (e.g. `x-api-key`,
 * `api-key`, `x-goog-api-key`), optionally merged with extra headers.
 *
 * @param {string} headerName - The HTTP header name to use
 * @param {string} token - The credential value
 * @param {Record<string, string>} [extraHeaders]
 * @returns {Record<string, string>}
 */
function providerKeyHeaders(headerName, token, extraHeaders) {
  return markCredentialHeaders({ ...extraHeaders, [headerName]: token }, [token]);
}

/**
 * Build a reusable auth-header builder function that encapsulates the
 * "custom header name vs. Authorization prefix" branching shared by the
 * OpenAI and Copilot adapters.
 *
 * When `headerName` is set (e.g. Azure OpenAI BYOK's `api-key`, or a caller
 * override such as `AWF_OPENAI_AUTH_HEADER`), the returned function builds a
 * `providerKeyHeaders`-style header. Otherwise it falls back to
 * `tokenAuthHeaders` using `prefix` (defaulting to `Bearer`), so callers such
 * as Copilot can select the `token` or `Bearer` scheme when creating the
 * reusable builder.
 *
 * `scheme` is an operator-configured auth scheme (`AWF_{PROVIDER}_AUTH_SCHEME`).
 * When set, the value becomes `<scheme> <token>`: in `headerName` if given,
 * otherwise in `Authorization` (it takes precedence over `prefix`). A credential
 * that already starts with the scheme is not prefixed twice.
 *
 * @param {{ headerName?: string, prefix?: string, scheme?: string }} [options]
 * @returns {(token: string, extraHeaders?: Record<string, string>) => Record<string, string>}
 */
function buildAuthHeaderFn({ headerName, prefix = 'Bearer', scheme } = {}) {
  if (scheme) {
    return (token, extraHeaders) => schemeAuthHeaders(
      headerName || 'Authorization',
      scheme,
      stripAuthScheme(scheme, token),
      extraHeaders,
    );
  }
  return (token, extraHeaders) => (headerName
    ? providerKeyHeaders(headerName, token, extraHeaders)
    : tokenAuthHeaders(prefix, token, extraHeaders));
}

/**
 * Add a `Copilot-Integration-Id` entry to an existing header object.
 *
 * @param {Record<string, string>} headers - Base headers to extend
 * @param {string} integrationId
 * @returns {Record<string, string>}
 */
function withCopilotIntegration(headers, integrationId) {
  return markCredentialHeaders({ ...headers, 'Copilot-Integration-Id': integrationId }, getHeaderCredentials(headers));
}

module.exports = {
  tokenAuthHeaders,
  schemeAuthHeaders,
  stripAuthScheme,
  bearerAuthHeaders,
  providerKeyHeaders,
  withCopilotIntegration,
  buildAuthHeaderFn,
};
