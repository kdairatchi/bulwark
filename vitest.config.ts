import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

const isCI = !!process.env.CI
const isWindows = process.platform === 'win32'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.test.ts'],
    // Verbose locally, but in CI it streams ~370KB / 2200 lines through the
    // runner's stdout pipe. Windows runs have been dying mid-stream with a bare
    // "exit code 1" and no summary, so keep CI output small and also write the
    // results to a file — a file survives whatever is eating stdout.
    reporters: isCI
      ? ['dot', ['junit', { outputFile: 'test-results/junit.xml' }]]
      : ['verbose'],
    // Windows CI has flaked with thread-pool workers dying mid-run (empty junit).
    // Forks isolate better on that runner; keep threads elsewhere for speed.
    pool: isCI && isWindows ? 'forks' : 'threads',
    ...(isCI && isWindows ? { fileParallelism: false } : {}),
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src/renderer/src'),
      '@shared': resolve(__dirname, 'src/shared'),
    },
  },
})
