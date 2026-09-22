import { defineConfig } from 'vitest/config';

// With TEST_DATABASE_URL set the files share one real database, so they run
// one at a time; on PGlite every file has a database of its own.
export default defineConfig({
  test: {
    include: ['src/**/*.test.{ts,tsx}'],
    fileParallelism: !process.env.TEST_DATABASE_URL,
    testTimeout: 30_000,
    // The design package's ESM imports are extensionless, which a bundler
    // resolves and bare Node does not; let Vite process it.
    server: { deps: { inline: ['@wtfalch/design'] } },
  },
});
