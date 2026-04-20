import { createAppwriteClient } from 'xpecto-shield/api'
import type { AppwriteConfig } from 'xpecto-shield'

let clientInstance: ReturnType<typeof createAppwriteClient> | null = null

export function getAppwriteClient() {
  if (clientInstance) return clientInstance

  const config: AppwriteConfig = {
    endpoint: process.env.APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1',
    projectId: process.env.APPWRITE_PROJECT_ID || '',
    apiKey: process.env.APPWRITE_API_KEY || '',
    databaseId: process.env.APPWRITE_DATABASE_ID || 'xpecto_shield',
  }

  clientInstance = createAppwriteClient(config)
  return clientInstance
}
