/**
 * Local business lead discovery from OpenStreetMap via public Overpass.
 * This is discovery of tagged physical establishments, not an exhaustive
 * directory of online shops or a Google Places replacement.
 */
export interface LocalLead {
  name: string;
  website: string;
  shop: string;
  address?: string;
  osmUrl: string;
}
// The legacy kumi.systems endpoint may be slow; use the maintained endpoint first.
// Public Overpass services are best-effort and can time out under load.
const ENDPOINTS = [
  'https://overpass.private.coffee/api/interpreter',
  'https://overpass-api.de/api/interpreter',
] as const;
const MAX_RESPONSE_BYTES = 5_000_000;
const CITY_RE = /^[\p{L}\p{M}\d .,'’()/-]{2,80}$/u;

function publicWebsite(value: string): string | null {
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : 'https://' + value);
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) return null;
    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!host.includes('.') || host === 'localhost' || host.endsWith('.local') ||
        host.endsWith('.internal') || host.endsWith('.test') || host.endsWith('.localhost') ||
        /^(?:10|127|0|169\.254|192\.168)\./.test(host) ||
        /^172\.(?:1[6-9]|2\d|3[01])\./.test(host) ||
        /^\d+\.\d+\.\d+\.\d+$/.test(host) ||
        host.includes(':')) return null;
    return url.origin + (url.pathname === '/' ? '' : url.pathname);
  } catch {
    return null;
  }
}

export async function discoverLocalBusinesses(city: string, opts: {
  shopType?: string;
  limit?: number;
} = {}): Promise<{ leads: LocalLead[]; warning: string; source: string }> {
  if (!CITY_RE.test(city)) throw new Error('Invalid city name (2-80 characters).');
  const limit = Math.max(1, Math.min(100, Math.floor(opts.limit ?? 25)));
  const shopType = opts.shopType?.trim().toLowerCase() ?? '';
  if (shopType && !/^[a-z_]{2,40}$/.test(shopType)) {
    throw new Error('shopType must be an OpenStreetMap shop tag, e.g. clothes, shoes, jewelry.');
  }
  const escapedCity = city.replace(/[\\"]/g, '\\$&');
  const shopFilter = shopType ? `["shop"="${shopType}"]` : '["shop"]';
  const query = `[out:json][timeout:25];area["name"="${escapedCity}"]["boundary"="administrative"]->.a;(nwr${shopFilter}["website"](area.a);nwr${shopFilter}["contact:website"](area.a););out tags center ${Math.min(limit * 5, 500)};`;
  let data: { elements?: Array<{ id: number; type: string; tags?: Record<string,string> }> } | undefined;
  const failures: string[] = [];
  for (const endpoint of ENDPOINTS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 28_000);
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'Opentechalyzer-STR0M/0.1 local-lead-research' },
        body: new URLSearchParams({ data: query }),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.text();
      if (payload.length > MAX_RESPONSE_BYTES) throw new Error('Response too large');
      const parsed = JSON.parse(payload) as { elements?: Array<{ id: number; type: string; tags?: Record<string,string> }> };
      if (!Array.isArray(parsed.elements)) throw new Error('Invalid Overpass response');
      data = parsed;
      break;
    } catch (error) {
      failures.push(`${new URL(endpoint).hostname}: ${controller.signal.aborted ? 'timeout (28s)' : (error as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }
  if (!data) throw new Error(`Overpass request failed on all providers: ${failures.join('; ')}`);
    const seen = new Set<string>();
    const leads: LocalLead[] = [];
    for (const obj of data.elements ?? []) {
      const tags = obj.tags ?? {};
      const website = publicWebsite(tags['website'] ?? tags['contact:website'] ?? '');
      if (!website || !tags['name']) continue;
      const key = new URL(website).hostname;
      if (seen.has(key)) continue;
      seen.add(key);
      const address = [tags['addr:street'],tags['addr:housenumber'],tags['addr:city']].filter(Boolean).join(' ');
      leads.push({ name: tags['name'], website, shop: tags['shop'] ?? 'other',
        ...(address ? { address } : {}), osmUrl: `https://www.openstreetmap.org/${obj.type}/${obj.id}` });
      if (leads.length >= limit) break;
    }
    return { leads, source: 'OpenStreetMap / Overpass API',
      warning: 'Only shops mapped in OSM with public website tags; not necessarily ecommerce. Municipality boundaries may include surrounding areas. Absence does not mean no business exists. Verify webshop functionality and contact details before outreach.' };
}
