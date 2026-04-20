import { c as AppwriteConfig, k as ShieldAppwriteClient, A as AIConfig, g as IncidentLog, h as IncidentStats, D as DateRange, a as AIReport, S as ShieldAPIConfig } from '../types-wAOtwm6s.js';

/**
 * Create an Appwrite client wrapper for Xpecto Shield.
 *
 * @param config - Appwrite connection configuration
 * @returns A fully typed ShieldAppwriteClient
 */
declare function createAppwriteClient(config: AppwriteConfig): ShieldAppwriteClient;

/**
 * Create an AI analytics pipeline.
 *
 * @param config - AI/LLM provider configuration
 * @returns Object with analysis methods
 */
declare function createAIAnalytics(config: AIConfig): {
    /**
     * Generate a comprehensive security analysis report from incident data.
     *
     * @param incidents - Array of incident logs to analyze
     * @param stats - Aggregated incident statistics
     * @param dateRange - The analysis time period
     * @returns An AIReport ready for storage
     */
    generateReport(incidents: IncidentLog[], stats: IncidentStats, dateRange: DateRange): Promise<AIReport>;
    /**
     * Generate a quick threat assessment for a single incident.
     */
    assessThreat(incident: IncidentLog): Promise<{
        severity: "low" | "medium" | "high" | "critical";
        analysis: string;
        recommendation: string;
    }>;
};

/**
 * Create API route handlers for the Shield admin dashboard.
 *
 * @param config - API configuration with Appwrite credentials and auth check
 * @returns Object with all route handlers
 *
 * @example
 * ```typescript
 * // app/api/shield/[...slug]/route.ts
 * import { createShieldAPI } from 'xpecto-shield/api'
 *
 * const api = createShieldAPI({
 *   appwrite: { endpoint: '...', projectId: '...', apiKey: '...' },
 *   authCheck: async (req) => { ... },
 * })
 *
 * export const GET = api.handleGET
 * export const POST = api.handlePOST
 * export const DELETE = api.handleDELETE
 * ```
 */
declare function createShieldAPI(config: ShieldAPIConfig): {
    /**
     * GET /api/shield/:resource
     * Resources: stats, incidents, blocked-ips, reports, settings
     */
    handleGET(request: Request): Promise<Response>;
    /**
     * POST /api/shield/:resource
     * Resources: block-ip, unblock-ip, generate-report, settings, setup
     */
    handlePOST(request: Request): Promise<Response>;
    /**
     * DELETE /api/shield/:resource/:id
     */
    handleDELETE(request: Request): Promise<Response>;
};

export { createAIAnalytics, createAppwriteClient, createShieldAPI };
