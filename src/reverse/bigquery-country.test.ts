import { describe, expect, it } from 'vitest';
import { buildReverseQuery, normalizeCountryCodes } from './bigquery.js';

describe('country and popularity filters', () => {
  it('filters Portuguese ccTLDs and avoids most-popular-first sorting', () => {
    const { sql } = buildReverseQuery({ tech: ['Shopify'], countries: ['pt'], rank: 1000000, minRank: 100000, selection: 'diverse', seed: 3, limit: 100 });
    expect(sql).toContain("ENDS_WITH(LOWER(NET.HOST(page)), '.pt')");
    expect(sql).toContain('`rank` >= 100000');
    expect(sql).toContain('`rank` <= 1000000');
    expect(sql).toContain('ORDER BY FARM_FINGERPRINT');
    expect(sql).toContain('LIMIT 100');
  });
  it('supports multiple countries and GB to UK domain mapping', () => {
    const { sql } = buildReverseQuery({ tech: ['Shopify'], countries: ['PT', 'ES', 'GB'] });
    expect(sql).toContain("'.pt'");
    expect(sql).toContain("'.es'");
    expect(sql).toContain("'.uk'");
  });
  it('preserves original popular-first behavior with no country filters', () => {
    const { sql } = buildReverseQuery({ tech: ['Shopify'] });
    expect(sql).toContain('ORDER BY `rank` NULLS LAST');
    expect(sql).not.toContain('NET.HOST(page)');
  });
  it('rejects invalid country codes and popularity ranges', () => {
    expect(() => normalizeCountryCodes(['Portugal'])).toThrow();
    expect(() => buildReverseQuery({ tech: ['Shopify'], minRank: 1000000, rank: 100000 })).toThrow();
  });
});
