import { defineConfig } from 'vitest/config';

// Claude Bridge tests spawn the MCP server with a fake provider. No database,
// no global setup, no model stack.
export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['tests/unit/ops/claude-bridge/**/*.test.mjs'],
    fileParallelism: false,
    pool: 'forks',
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
