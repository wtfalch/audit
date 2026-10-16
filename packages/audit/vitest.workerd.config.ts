import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

// No nodejs_compat flag: a Worker that does not turn it on must still sign.
export default defineConfig({
  plugins: [
    cloudflareTest({ miniflare: { compatibilityDate: '2025-09-01', compatibilityFlags: [] } }),
  ],
  test: { include: ['test-workerd/*.workerd.test.ts'] },
});
