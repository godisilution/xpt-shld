import type { NextConfig } from 'next'

const nextConfig: NextConfig = {
  transpilePackages: ['xpecto-shield'],
  serverExternalPackages: ['node-appwrite'],
}

export default nextConfig
