import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('./service-account.js', () => ({
  accessTokenFromServiceAccountJson: vi.fn(async () => 'test-oauth-token'),
}));

import { resolveAccessToken, reverseLookup } from './bigquery.js';
import { accessTokenFromServiceAccountJson } from './service-account.js';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('BigQuery service-account integration', () => {
  it('reuses an existing Coolify credentials setting', async () => {
    vi.stubEnv('GCP_SERVICE_ACCOUNT_JSON', '{"type":"service_account"}');
    vi.stubEnv('GOOGLE_ACCESS_TOKEN', '');
    vi.stubEnv('GCP_ACCESS_TOKEN', '');
    expect(await resolveAccessToken()).toBe('test-oauth-token');
    expect(accessTokenFromServiceAccountJson).toHaveBeenCalledWith('{"type":"service_account"}');
  });

  it('does not exchange credentials when an explicit token is provided', async () => {
    vi.stubEnv('GCP_SERVICE_ACCOUNT_JSON', '{"type":"service_account"}');
    expect(await resolveAccessToken('explicit-test-token')).toBe('explicit-test-token');
    expect(accessTokenFromServiceAccountJson).not.toHaveBeenCalled();
  });

  it('only estimates the scan and does not execute a billable query', async () => {
    vi.stubEnv('GCP_SERVICE_ACCOUNT_JSON', '{"type":"service_account"}');
    vi.stubEnv('GOOGLE_ACCESS_TOKEN', '');
    vi.stubEnv('GCP_ACCESS_TOKEN', '');
    const requests: Array<{ url: string; body: { dryRun: boolean } }> = [];
    vi.stubGlobal('fetch', async (url: string, opts: { body: string }) => {
      const body = JSON.parse(opts.body) as { dryRun: boolean };
      requests.push({ url, body });
      return { ok: true, json: async () => ({ totalBytesProcessed: '1024' }) };
    });
    const result = await reverseLookup({ tech: ['Shopify'], projectId: 'test-project', rank: 10000, dryRun: true });
    expect(result.notRun).toContain('Dry run only');
    expect(requests).toHaveLength(1);
    expect(requests[0]?.body.dryRun).toBe(true);
    expect(requests[0]?.url).toContain('/projects/test-project/queries');
  });
});
