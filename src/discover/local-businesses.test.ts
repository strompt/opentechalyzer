import { afterEach, describe, expect, it, vi } from 'vitest';
import { discoverLocalBusinesses } from './local-businesses.js';

afterEach(() => vi.unstubAllGlobals());

describe('local business discovery', () => {
  it('discovers and deduplicates public shop websites with a source reference', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      text: async () => JSON.stringify({ elements: [
        { type: 'node', id: 1, tags: { name: 'Loja Um', shop: 'clothes', website: 'https://loja.pt' } },
        { type: 'node', id: 2, tags: { name: 'Loja Um 2', shop: 'clothes', website: 'https://loja.pt/ofertas' } },
        { type: 'way', id: 3, tags: { name: 'Loja Dois', shop: 'shoes', 'contact:website': 'https://dois.pt' } },
        { type: 'node', id: 4, tags: { name: 'Rede interna', shop: 'shoes', website: 'http://127.0.0.1' } },
      ] }),
    });
    vi.stubGlobal('fetch', fetchMock);
    const result = await discoverLocalBusinesses('Viana do Castelo', { limit: 10 });
    expect(result.leads).toHaveLength(2);
    expect(result.leads[0]?.website).toBe('https://loja.pt');
    expect(result.leads[1]?.osmUrl).toBe('https://www.openstreetmap.org/way/3');
    const body = fetchMock.mock.calls[0]?.[1]?.body as URLSearchParams;
    expect(body.get('data')).toContain('Viana do Castelo');
  });

  it('rejects unsafe input before any external request', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(discoverLocalBusinesses('Viana\";out;')).rejects.toThrow();
    await expect(discoverLocalBusinesses('Viana do Castelo', { shopType: 'clothes\"]' })).rejects.toThrow();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
