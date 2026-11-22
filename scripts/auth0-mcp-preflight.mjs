#!/usr/bin/env node
/**
 * Read-only OAuth/MCP connectivity preflight.
 *
 * Usage: node scripts/auth0-mcp-preflight.mjs https://staging.example.com/mcp
 * This checks public metadata and verifies the MCP endpoint denies anonymous
 * requests; it does not ask for an access token, log in or send write requests.
 */
const rawUrl = process.argv[2];

function fail(message) {
  throw new Error(message);
}
function httpsUrl(value, description) {
  let url;
  try { url = new URL(value); } catch { fail(`${description} is not a URL`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    fail(`${description} must be a clean HTTPS URL`);
  }
  return url;
}
function expect(condition, message) {
  if (!condition) fail(message);
}

async function fetchSafe(url, opts = {}) {
  const response = await fetch(url, {
    ...opts,
    redirect: 'error',
    signal: AbortSignal.timeout(8_000),
    headers: {
      accept: 'application/json',
      ...(opts.headers ?? {}),
    },
  });
  return response;
}

async function jsonResponse(response, description) {
  let value;
  try { value = await response.json(); }
  catch { fail(`${description}: response is not valid JSON`); }
  expect(value && typeof value === 'object' && !Array.isArray(value),
    `${description}: expected a JSON object`);
  return value;
}

try {
  if (!rawUrl || process.argv.length !== 3) {
    fail('Usage: node scripts/auth0-mcp-preflight.mjs https://STAGING_HOST/mcp');
  }
  const endpoint = httpsUrl(rawUrl, 'MCP endpoint');
  expect(endpoint.pathname === '/mcp', 'MCP endpoint must end with /mcp');
  const resourceMetadataUrl = new URL('/.well-known/oauth-protected-resource', endpoint);
  const resourceResponse = await fetchSafe(resourceMetadataUrl);
  expect(resourceResponse.status === 200,
    `Protected resource metadata returned HTTP ${resourceResponse.status}, expected 200`);
  const resourceMetadata = await jsonResponse(resourceResponse, 'Resource metadata');
  expect(resourceMetadata.resource === endpoint.toString(),
    'Resource metadata URL does not match the requested MCP endpoint');

  const issuer = resourceMetadata.authorization_servers?.[0];
  expect(typeof issuer === 'string', 'Resource metadata is missing an authorization server');
  const issuerUrl = httpsUrl(issuer, 'Authorization server issuer');
  // Only fetch well-known configuration after HTTPS issuer validation.
  const oidcUrl = new URL('.well-known/openid-configuration', issuerUrl);
  const oidcResponse = await fetchSafe(oidcUrl);
  expect(oidcResponse.status === 200,
    `Auth0 OpenID discovery returned HTTP ${oidcResponse.status}, expected 200`);
  const oidc = await jsonResponse(oidcResponse, 'OpenID metadata');
  expect(oidc.issuer === issuerUrl.toString(),
    'Issuer does not match authorization server metadata');
  expect(typeof oidc.jwks_uri === 'string', 'Auth0 metadata is missing JWKS URI');
  const jwksUrl = httpsUrl(oidc.jwks_uri, 'JWKS URI');
  expect(jwksUrl.origin === issuerUrl.origin, 'JWKS endpoint is on a different origin');

  const response = await fetchSafe(endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'strom-staging-preflight', version: '1.0.0' },
      },
    }),
  });
  expect(response.status === 401,
    `Anonymous MCP initialize returned HTTP ${response.status}, expected 401`);

  const challenge = response.headers.get('www-authenticate') ?? '';
  expect(/^Bearer\b/i.test(challenge), '401 response has no Bearer challenge');
  expect(challenge.includes('resource_metadata='), 'Bearer challenge is missing resource_metadata URL');

  console.log('PASS: OAuth protected resource metadata is valid');
  console.log('PASS: Auth0 issuer metadata and JWKS URL are available');
  console.log('PASS: anonymous MCP initialize is rejected with 401 + Bearer challenge');
  console.log('NOTE: real Auth0 login, token audience, user allowlist and tenant isolation are NOT tested');
} catch (err) {
  console.error(`FAIL: ${err instanceof Error ? err.message : 'Unknown preflight error'}`);
  process.exitCode = 1;
}
