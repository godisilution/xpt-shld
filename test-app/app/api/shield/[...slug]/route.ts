import { createShieldAPI } from 'xpecto-shield/api'
import type { AppwriteConfig } from 'xpecto-shield'

const appwriteConfig: AppwriteConfig = {
  endpoint: process.env.APPWRITE_ENDPOINT || 'https://cloud.appwrite.io/v1',
  projectId: process.env.APPWRITE_PROJECT_ID || '',
  apiKey: process.env.APPWRITE_API_KEY || '',
  databaseId: process.env.APPWRITE_DATABASE_ID || 'xpecto_shield',
}

const api = createShieldAPI({
  appwrite: appwriteConfig,
  authCheck: async () => true,
})

export const GET = api.handleGET
export const POST = api.handlePOST
export const DELETE = api.handleDELETE
