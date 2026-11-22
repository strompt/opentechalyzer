import { generateKeyPairSync, sign } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { describe, expect, it, vi } from 'vitest';
import {
  Auth0TokenVerifier, AuthFailure, bearerChallenge, loadAuthConfig, protectedResourceMetadata, VERIFIED_EMAIL_CLAIM,
  type AuthConfig,
} from '../src/auth.js';

const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const config: AuthConfig = {
  issuer: 'https://example.eu.auth0.com/',
  audience: 'https://mcp.example.com/mcp',
  resource: 'https://mcp.example.com/mcp',
  requiredScope: 'scan:website',
  allowedEmail: 'strom.studio.pt@gmail.com',
};

function token(claims: Record<string, unknown> = {}, privateKey = keys.privateKey): string {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'test-key' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: config.issuer,
    aud: config.audience,
    sub: 'auth0|customer-a',
    scope: 'scan:website',
    [VERIFIED_EMAIL_CLAIM]: 'strom.studio.pt@gmail.com',
    exp: now + 3600,
    iat: now,
    ...claims,
  })).toString('base64url');
  const body = `${header}.${payload}`;
  const signature = sign('RSA-SHA256', Buffer.from(body), privateKey).toString('base64url');
  return `${body}.${signature}`;
}

function request(value?: string): IncomingMessage {
  return { headers: value ? { authorization: `Bearer ${value}` } : {} } as IncomingMessage;
}

function verifier(): Auth0TokenVerifier {
  const publicKey = keys.publicKey.export({ format: 'jwk' });
  const responseBody = JSON.stringify({ keys: [{ ...publicKey, kid: 'test-key', use: 'sig', alg: 'RS256' }] });
  const mockFetch = vi.fn(async () => new Response(responseBody, { status: 200 }));
  return new Auth0TokenVerifier(config, mockFetch as unknown as typeof fetch);
}

describe('Auth0 HTTP MCP security', () => {
  it('fails closed when Auth0 issuer, API audience or public URL is missing', () => {
    expect(() => loadAuthConfig({})).toThrow('AUTH0_ISSUER');
    expect(() => loadAuthConfig({ AUTH0_ISSUER: config.issuer })).toThrow('AUTH0_AUDIENCE');
    expect(() => loadAuthConfig({ AUTH0_ISSUER: config.issuer, AUTH0_AUDIENCE: config.audience })).toThrow('MCP_PUBLIC_URL');
  });

  it('rejects insecure issuer and public resource URLs', () => {
    expect(() => loadAuthConfig({
      AUTH0_ISSUER: 'http://example.eu.auth0.com/',
      AUTH0_AUDIENCE: config.audience,
      MCP_PUBLIC_URL: config.resource,
    })).toThrow('AUTH0_ISSUER');
    expect(() => loadAuthConfig({
      AUTH0_ISSUER: config.issuer,
      AUTH0_AUDIENCE: config.audience,
      MCP_PUBLIC_URL: 'http://mcp.example.com/mcp',
    })).toThrow('MCP_PUBLIC_URL');
  });

  it('requires a configured allowlisted email for staging', () => {
    expect(() => loadAuthConfig({
      AUTH0_ISSUER: config.issuer,
      AUTH0_AUDIENCE: config.audience,
      MCP_PUBLIC_URL: config.resource,
    })).toThrow('MCP_ALLOWED_EMAIL');
    expect(loadAuthConfig({
      AUTH0_ISSUER: config.issuer,
      AUTH0_AUDIENCE: config.audience,
      MCP_PUBLIC_URL: config.resource,
      MCP_ALLOWED_EMAIL: 'Strom.Studio.Pt@Gmail.com',
    }).allowedEmail).toBe('strom.studio.pt@gmail.com');
  });

  it('rejects tokens without a verified email claim or with another account', async () => {
    for (const value of [
      { [VERIFIED_EMAIL_CLAIM]: undefined },
      { [VERIFIED_EMAIL_CLAIM]: 'other@example.com' },
      { email: config.allowedEmail, email_verified: true, [VERIFIED_EMAIL_CLAIM]: undefined },
    ]) {
      await expect(verifier().verifyRequest(request(token(value))))
        .rejects.toMatchObject({ status: 403, code: 'access_denied' });
    }
  });

  it('accepts the explicitly allowlisted email regardless of email casing', async () => {
    const id = await verifier().verifyRequest(
      request(token({ [VERIFIED_EMAIL_CLAIM]: 'STROM.STUDIO.PT@GMAIL.COM' })),
    );
    expect(id.subject).toBe('auth0|customer-a');
  });

  it('publishes OAuth protected resource discovery and challenges', () => {
    expect(protectedResourceMetadata(config)).toMatchObject({
      resource: config.resource,
      authorization_servers: [config.issuer],
      scopes_supported: ['scan:website'],
    });
    expect(bearerChallenge(config, 'invalid_token')).toContain('resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"');
  });

  it('rejects anonymous requests before touching the MCP tools', async () => {
    await expect(verifier().verifyRequest(request())).rejects.toMatchObject({
      status: 401, code: 'invalid_token',
    } satisfies Partial<AuthFailure>);
  });

  it('accepts a correctly signed Auth0 access token with the expected scope', async () => {
    const id = await verifier().verifyRequest(request(token()));
    expect(id.subject).toBe('auth0|customer-a');
    expect(id.principal).toContain('customer-a');
  });

  it('rejects tokens signed by an unrelated key', async () => {
    await expect(verifier().verifyRequest(request(token({}, otherKeys.privateKey))))
      .rejects.toMatchObject({ status: 401, code: 'invalid_token' });
  });

  it('rejects wrong issuer, wrong audience, expired and missing-subject tokens', async () => {
    for (const claims of [
      { iss: 'https://malicious.example/' },
      { aud: 'https://another-api.example/' },
      { exp: Math.floor(Date.now() / 1000) - 3600 },
      { sub: '' },
    ]) {
      await expect(verifier().verifyRequest(request(token(claims))))
        .rejects.toMatchObject({ status: 401, code: 'invalid_token' });
    }
  });

  it('rejects missing scopes with 403', async () => {
    await expect(verifier().verifyRequest(request(token({ scope: 'other:scope' }))))
      .rejects.toMatchObject({ status: 403, code: 'insufficient_scope' });
  });

  it('rejects an unsigned-forged insufficient-scope token as invalid, not insufficient scope', async () => {
    await expect(verifier().verifyRequest(request(
      token({ scope: 'unauthorized:scope' }, otherKeys.privateKey),
    ))).rejects.toMatchObject({ status: 401, code: 'invalid_token' });
  });

  it('rejects a token with a malformed signature or encoding', async () => {
    await expect(verifier().verifyRequest(request('not-a-jwt')))
      .rejects.toMatchObject({ status: 401, code: 'invalid_token' });
  });

  it('rejects failed JWKS fetches instead of disabling authentication', async () => {
    const down = vi.fn(async () => { throw new Error('offline'); });
    const guard = new Auth0TokenVerifier(config, down as unknown as typeof fetch);
    await expect(guard.verifyRequest(request(token())))
      .rejects.toMatchObject({ status: 503, code: 'temporarily_unavailable' });
  });
});
