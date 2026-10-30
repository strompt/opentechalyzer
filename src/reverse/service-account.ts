/**
 * Exchange Google service-account JSON for a short-lived BigQuery OAuth access token.
 * The credential is read only from GCP_SERVICE_ACCOUNT_JSON at runtime.
 * It must never be committed to GitHub or included in tool results.
 */
import { createHash, sign } from 'node:crypto';

const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const BIGQUERY_SCOPE = 'https://www.googleapis.com/auth/bigquery';

interface ServiceAccount {
  type: string;
  client_email: string;
  private_key: string;
}

let cached: { fingerprint: string; token: string; expiresAt: number } | undefined;
let pending: Promise<string> | undefined;

function encode(payload: object): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

async function requestToken(json: string, fingerprint: string): Promise<string> {
  let credential: Partial<ServiceAccount>;
  try {
    credential = JSON.parse(json) as Partial<ServiceAccount>;
  } catch {
    throw new Error('GCP_SERVICE_ACCOUNT_JSON does not contain valid JSON.');
  }
  if (credential.type !== 'service_account' ||
      typeof credential.client_email !== 'string' ||
      !credential.client_email.endsWith('.gserviceaccount.com') ||
      typeof credential.private_key !== 'string' ||
      !credential.private_key.includes('BEGIN PRIVATE KEY')) {
    throw new Error('GCP_SERVICE_ACCOUNT_JSON must contain valid service-account credentials.');
  }

  const now = Math.floor(Date.now() / 1000);
  const header = encode({ alg: 'RS256', typ: 'JWT' });
  const claims = encode({
    iss: credential.client_email,
    scope: BIGQUERY_SCOPE,
    aud: TOKEN_ENDPOINT,
    iat: now,
    exp: now + 3600,
  });
  const unsigned = header + '.' + claims;
  const signature = sign('RSA-SHA256', Buffer.from(unsigned), credential.private_key).toString('base64url');
  const response = await fetch(TOKEN_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: unsigned + '.' + signature,
    }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) {
    // Do not include credential contents or token endpoint response in errors.
    throw new Error('Google service-account token exchange failed (HTTP ' + response.status + ').');
  }
  const data = (await response.json()) as { access_token?: string; expires_in?: number };
  if (!data.access_token) throw new Error('Google OAuth response has no access_token.');
  const lifetime = Math.max(60, Math.min(3600, data.expires_in ?? 3600));
  cached = { fingerprint, token: data.access_token, expiresAt: Date.now() + lifetime * 1000 };
  return data.access_token;
}

/** Return a cached OAuth token or exchange a freshly signed service-account JWT. */
export async function accessTokenFromServiceAccountJson(json: string): Promise<string> {
  const fingerprint = createHash('sha256').update(json).digest('hex');
  if (cached?.fingerprint === fingerprint && cached.expiresAt > Date.now() + 120_000) {
    return cached.token;
  }
  if (pending) return pending;
  pending = requestToken(json, fingerprint);
  try {
    return await pending;
  } finally {
    pending = undefined;
  }
}
