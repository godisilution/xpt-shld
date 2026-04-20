import type { NextConfig } from 'next'
import path from 'path'

const parentSrc = path.resolve(__dirname, '..', 'src')

const nextConfig: NextConfig = {
  transpilePackages: ['xpecto-shield'],
  serverExternalPackages: ['node-appwrite'],
  webpack: (config) => {
    config.resolve = config.resolve || {}
    config.resolve.alias = {
      ...config.resolve.alias,
      'xpecto-shield/core': path.join(parentSrc, 'core', 'index.ts'),
      'xpecto-shield/middleware': path.join(parentSrc, 'middleware', 'index.ts'),
      'xpecto-shield/api': path.join(parentSrc, 'api', 'index.ts'),
      'xpecto-shield/dashboard': path.join(parentSrc, 'dashboard', 'index.ts'),
      'xpecto-shield': path.join(parentSrc, 'index.ts'),
    }
    return config
  },
}

export default nextConfig
