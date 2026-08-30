import react from '@vitejs/plugin-react';
import { playwright } from '@vitest/browser-playwright';
import type { Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

const MAX_PRODUCTION_CHUNK_SIZE = 500_000;

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
        codeSplitting: {
          groups: [
            {
              name: 'react-vendor',
              test: /node_modules[\\/](?:react|react-dom|react-router|react-router-dom)[\\/]/,
              priority: 60,
              includeDependenciesRecursively: false,
            },
            {
              name: 'rc-components',
              test: /node_modules[\\/](?:antd[\\/]node_modules[\\/])?@rc-component[\\/]/,
              priority: 50,
              includeDependenciesRecursively: false,
            },
            {
              name: 'ant-design-icons',
              test: /node_modules[\\/]@ant-design[\\/](?:icons|icons-svg)[\\/]/,
              priority: 40,
              includeDependenciesRecursively: false,
            },
            {
              name: 'ant-design-pro',
              test: /node_modules[\\/]@ant-design[\\/]pro-components[\\/]/,
              priority: 30,
              includeDependenciesRecursively: false,
            },
            {
              name: 'antd-data-entry',
              test: /node_modules[\\/]antd[\\/](?:es|lib)[\\/](?:input|date-picker|form|color-picker|upload|select|radio|checkbox|switch|cascader|slider|input-number|tree-select|rate|time-picker)[\\/]/,
              priority: 20,
              includeDependenciesRecursively: false,
            },
            {
              name: 'antd-data-display',
              test: /node_modules[\\/]antd[\\/](?:es|lib)[\\/](?:table|steps|typography|result|tabs|menu|modal|notification|image|pagination|progress|badge|dropdown|message|tag|skeleton|drawer|descriptions|timeline|tooltip|alert|collapse|avatar|statistic|popover|popconfirm|empty)[\\/]/,
              priority: 20,
              includeDependenciesRecursively: false,
            },
            {
              name: 'antd-core',
              test: /node_modules[\\/]antd[\\/](?!node_modules[\\/])/,
              priority: 10,
              includeDependenciesRecursively: false,
            },
            {
              name: 'ant-design-runtime',
              test: /node_modules[\\/]@ant-design[\\/]/,
              priority: 10,
              includeDependenciesRecursively: false,
            },
            {
              name: 'vendor',
              test: /node_modules[\\/]/,
            },
          ],
        },
      },
    },
  },
  server: {
    port: 4173,
    strictPort: true,
  },
  preview: {
    port: 4173,
    strictPort: true,
  },
  test: {
    setupFiles: './src/test/setup.ts',
    css: true,
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
