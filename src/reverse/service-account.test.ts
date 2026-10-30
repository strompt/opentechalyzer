import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync, verify } from 'node:crypto';
import { accessTokenFromServiceAccountJson } from './service-account.js';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('service account OAuth token exchange', () => {
  it('signs a valid JWT and caches the short-lived token in memory', async () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const config = JSON.stringify({
      type: 'service_account',
      client_email: 'test@example.iam.gserviceaccount.com',
      private_key: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    });
    let calls = 0;
    vi.stubGlobal('fetch', async (_url: string, opts: { body: URLSearchParams }) => {
      calls++;
      const signed = opts.body.get('assertion') ?? '';
      const parts = signed.split('.');
      expect(parts).toHaveLength(3);
      expect(verify(
        'RSA-SHA256',
        Buffer.from(parts.slice(0, 2).join('.')),
        pair.publicKey,
        Buffer.from(parts[2] ?? '', 'base64url'),
      )).toBe(true);
      return { ok: true, json: async () => ({ access_token: 'unit-test-token', expires_in: 3600 }) };
    });
    expect(await accessTokenFromServiceAccountJson(config)).toBe('unit-test-token');
    expect(await accessTokenFromServiceAccountJson(config)).toBe('unit-test-token');
    expect(calls).toBe(1);
  });

  it('does not call the network with invalid credentials', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(accessTokenFromServiceAccountJson('{}')).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
