import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    'index': 'src/index.ts',
    'core/index': 'src/core/index.ts',
    'middleware/index': 'src/middleware/index.ts',
    'api/index': 'src/api/index.ts',
    'dashboard/index': 'src/dashboard/index.ts',
  },
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  external: ['react', 'react-dom', 'next', 'node-appwrite'],
  splitting: true,
  treeshake: true,
})
