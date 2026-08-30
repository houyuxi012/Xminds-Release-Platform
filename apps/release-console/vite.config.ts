import react from '@vitejs/plugin-react';
import { playwright } from '@vitest/browser-playwright';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

const MAX_PRODUCTION_CHUNK_SIZE = 500_000;
const DEVELOPMENT_API_TARGET =
  process.env.XMINDS_RELEASE_CONSOLE_API_PROXY_TARGET?.trim() || 'http://127.0.0.1:8080';

function enforceProductionChunkSize(): Plugin {
  return {
    name: 'xminds-enforce-production-chunk-size',
    apply: 'build',
    generateBundle(_options, bundle) {
      const oversizedChunks = Object.values(bundle)
        .filter((output) => output.type === 'chunk')
        .map((chunk) => ({ fileName: chunk.fileName, size: Buffer.byteLength(chunk.code) }))
        .filter((chunk) => chunk.size > MAX_PRODUCTION_CHUNK_SIZE)
        .sort((left, right) => right.size - left.size);

      if (oversizedChunks.length > 0) {
        const details = oversizedChunks
          .map((chunk) => `${chunk.fileName}: ${(chunk.size / 1000).toFixed(2)} kB`)
          .join(', ');
        this.error(
          `Production chunks must not exceed ${MAX_PRODUCTION_CHUNK_SIZE / 1000} kB: ${details}`,
        );
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), enforceProductionChunkSize()],
  build: {
    rolldownOptions: {
      output: {
        strictExecutionOrder: true,
        codeSplitting: {
          includeDependenciesRecursively: true,
          maxSize: 450_000,
          groups: [
            {
              name: 'vendor',
              test: /node_modules[\\/]/,
              priority: 10,
              includeDependenciesRecursively: true,
              maxSize: 450_000,
            },
          ],
        },
      },
    },
  },
  server: {
    port: 4173,
    strictPort: true,
    proxy: {
      '/api': {
        target: DEVELOPMENT_API_TARGET,
      },
    },
  },
  preview: {
    port: 4173,
    strictPort: true,
  },
  test: {
    setupFiles: './src/test/setup.ts',
    css: true,
    fileParallelism: false,
    exclude: ['tests/e2e/**', '**/node_modules/**', '**/dist/**'],
    browser: {
      enabled: true,
      headless: true,
      screenshotFailures: false,
      provider: playwright(),
      instances: [{ browser: 'chromium' }],
      viewport: { width: 1440, height: 900 },
    },
  },
});
