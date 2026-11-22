/**
 * Auth0 bearer-token validation for remote MCP.
 *
 * HTTP mode is deliberately fail-closed. This is a resource server, not an
 * OAuth authorization server: Auth0 issues tokens; we verify them here.
 * No trust is placed in client-supplied identity or reverse-proxy headers.
 */
import { createPublicKey, verify as verifySignature } from 'node:crypto';
import type { IncomingMessage } from 'node:http';

export interface AuthConfig {
  issuer: string;
  audience: string;
  resource: string;
  requiredScope: string;
  allowedEmail: string;
}

export interface AuthIdentity {
  subject: string;
  principal: string;
}

type JsonObject = Record<string, unknown>;
type PublicJwk = JsonObject & { kty: string; kid: string };

const CLOCK_SKEW_SECONDS = 30;
const CACHE_MS = 5 * 60 * 1000;
const MAX_TOKEN_LENGTH = 16_384;
export const VERIFIED_EMAIL_CLAIM = 'https://stromstudio.pt/verified_email';

export class AuthFailure extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AuthFailure';
  }
}

function required(value: string | undefined, name: string): string {
  if (!value?.trim()) throw new Error(`HTTP MCP requires ${name}`);
  return value.trim();
}

export function loadAuthConfig(env: NodeJS.ProcessEnv = process.env): AuthConfig {
  const rawIssuer = required(env['AUTH0_ISSUER'], 'AUTH0_ISSUER');
  const issuerUrl = new URL(rawIssuer);
  if (
    issuerUrl.protocol !== 'https:' || issuerUrl.username || issuerUrl.password ||
    issuerUrl.search || issuerUrl.hash || issuerUrl.pathname !== '/'
  ) {
    throw new Error('AUTH0_ISSUER must be an HTTPS origin with a trailing slash');
  }
  const issuer = issuerUrl.toString();

  const audience = required(env['AUTH0_AUDIENCE'], 'AUTH0_AUDIENCE');
  const rawResource = required(env['MCP_PUBLIC_URL'], 'MCP_PUBLIC_URL');
  const resourceUrl = new URL(rawResource);
  if (
    resourceUrl.protocol !== 'https:' || resourceUrl.username || resourceUrl.password ||
    resourceUrl.search || resourceUrl.hash || resourceUrl.pathname !== '/mcp'
  ) {
    throw new Error('MCP_PUBLIC_URL must be the public HTTPS URL ending in /mcp');
  }

  const requiredScope = required(env['MCP_REQUIRED_SCOPE'] ?? 'scan:website', 'MCP_REQUIRED_SCOPE');
  if (!/^[A-Za-z0-9:._-]+$/.test(requiredScope)) throw new Error('Invalid MCP_REQUIRED_SCOPE');
  const allowedEmail = required(env['MCP_ALLOWED_EMAIL'], 'MCP_ALLOWED_EMAIL').toLowerCase();
  if (!/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(allowedEmail)) {
    throw new Error('MCP_ALLOWED_EMAIL must be an email address');
  }
  return { issuer, audience, resource: resourceUrl.toString(), requiredScope, allowedEmail };
}

function objectFromPart(part: string): JsonObject {
  if (!/^[A-Za-z0-9_-]+$/.test(part) || part.length > MAX_TOKEN_LENGTH) {
    throw new AuthFailure(401, 'invalid_token', 'Invalid token encoding');
  }
  try {
    const value: unknown = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    if (value && typeof value === 'object' && !Array.isArray(value)) return value as JsonObject;
  } catch {
    // Reject malformed token below.
  }
  throw new AuthFailure(401, 'invalid_token', 'Invalid token JSON');
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

export function protectedResourceMetadata(config: AuthConfig): JsonObject {
  return {
    resource: config.resource,
    authorization_servers: [config.issuer],
    scopes_supported: [config.requiredScope],
    bearer_methods_supported: ['header'],
  };
}

export function bearerChallenge(config: AuthConfig, error?: string): string {
  const metadata = new URL('/.well-known/oauth-protected-resource', config.resource).toString();
  return `Bearer resource_metadata="${metadata}"${error ? `, error="${error}"` : ''}`;
}

export class Auth0TokenVerifier {
  private cachedKeys = new Map<string, PublicJwk>();
  private cacheExpiresAt = 0;

  constructor(
    private readonly config: AuthConfig,
    private readonly fetchJwks: typeof fetch = fetch,
  ) {}

  private async refreshKeys(): Promise<void> {
    const endpoint = new URL('.well-known/jwks.json', this.config.issuer);
    let response: Response;
    try {
      response = await this.fetchJwks(endpoint.toString(), {
        redirect: 'error',
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error('JWKS unavailable');
    } catch {
      throw new AuthFailure(503, 'temporarily_unavailable', 'Auth0 signing keys unavailable');
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new AuthFailure(503, 'temporarily_unavailable', 'Invalid Auth0 JWKS response');
    }
    if (!body || typeof body !== 'object' || !('keys' in body) || !Array.isArray(body.keys)) {
      throw new AuthFailure(503, 'temporarily_unavailable', 'Invalid Auth0 JWKS');
    }
    const keys = new Map<string, PublicJwk>();
    for (const candidate of body.keys) {
      if (!candidate || typeof candidate !== 'object') continue;
      const key = candidate as JsonObject;
      if (
        key['kty'] === 'RSA' && typeof key['kid'] === 'string' &&
        (!key['use'] || key['use'] === 'sig') &&
        (!key['alg'] || key['alg'] === 'RS256') &&
        typeof key['n'] === 'string' && typeof key['e'] === 'string'
      ) keys.set(key['kid'], key as PublicJwk);
    }
    if (!keys.size) throw new AuthFailure(503, 'temporarily_unavailable', 'No usable Auth0 signing keys');
    this.cachedKeys = keys;
    this.cacheExpiresAt = Date.now() + CACHE_MS;
  }

  async verifyRequest(req: IncomingMessage): Promise<AuthIdentity> {
    const authorization = req.headers['authorization'];
    const match = typeof authorization === 'string' ? /^Bearer ([A-Za-z0-9._~-]+)$/.exec(authorization) : null;
    const token = match?.[1];
    if (!token || token.length > MAX_TOKEN_LENGTH) {
      throw new AuthFailure(401, 'invalid_token', 'Bearer token required');
    }
    const parts = token.split('.');
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    if (
      parts.length !== 3 || !encodedHeader || !encodedPayload || !encodedSignature ||
      !/^[A-Za-z0-9_-]+$/.test(encodedSignature)
    ) {
      throw new AuthFailure(401, 'invalid_token', 'Invalid access token');
    }
    const header = objectFromPart(encodedHeader);
    const payload = objectFromPart(encodedPayload);
    if (header['alg'] !== 'RS256' || typeof header['kid'] !== 'string' || 'crit' in header) {
      throw new AuthFailure(401, 'invalid_token', 'Unsupported token header');
    }
    const now = Math.floor(Date.now() / 1000);
    if (
      payload['iss'] !== this.config.issuer ||
      !(payload['aud'] === this.config.audience ||
        (isStringArray(payload['aud']) && payload['aud'].includes(this.config.audience))) ||
      typeof payload['sub'] !== 'string' || !payload['sub'] ||
      typeof payload['exp'] !== 'number' || payload['exp'] <= now - CLOCK_SKEW_SECONDS ||
      (typeof payload['nbf'] === 'number' && payload['nbf'] > now + CLOCK_SKEW_SECONDS) ||
      (typeof payload['iat'] === 'number' && payload['iat'] > now + CLOCK_SKEW_SECONDS)
    ) {
      throw new AuthFailure(401, 'invalid_token', 'Invalid token claims');
    }
    const scopes = typeof payload['scope'] === 'string' ? payload['scope'].split(/\s+/) : [];
    if (!scopes.includes(this.config.requiredScope)) {
      throw new AuthFailure(403, 'insufficient_scope', 'Missing required scope');
    }

    if (Date.now() >= this.cacheExpiresAt || !this.cachedKeys.has(header['kid'])) {
      await this.refreshKeys();
    }
    const jwk = this.cachedKeys.get(header['kid']);
    if (!jwk) throw new AuthFailure(401, 'invalid_token', 'Unknown token signing key');
    let signatureValid = false;
    try {
      const publicKey = createPublicKey({ key: jwk as import('node:crypto').JsonWebKey, format: 'jwk' });
      signatureValid = verifySignature(
        'RSA-SHA256',
        Buffer.from(`${encodedHeader}.${encodedPayload}`),
        publicKey,
        Buffer.from(encodedSignature, 'base64url'),
      );
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) throw new AuthFailure(401, 'invalid_token', 'Invalid token signature');

    // Staging-only allowlist. This claim is issued exclusively after Auth0
    // confirms email_verified=true via a Post-Login Action. Never trust a
    // caller-supplied email header or an unverified token email claim.
    const verifiedEmail = payload[VERIFIED_EMAIL_CLAIM];
    if (typeof verifiedEmail !== 'string' || verifiedEmail.toLowerCase() !== this.config.allowedEmail) {
      throw new AuthFailure(403, 'access_denied', 'Account not permitted for this MCP');
    }

    return { subject: payload['sub'], principal: `${this.config.issuer}:${payload['sub']}` };
  }
}
