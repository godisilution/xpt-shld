// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — AI Analytics Pipeline
// ═══════════════════════════════════════════════════════════════
//
// Provider-agnostic AI integration using the OpenAI-compatible
// chat completions API. Works with any provider that supports
// the standard endpoint format.
// ═══════════════════════════════════════════════════════════════

import type {
  AIConfig,
  AIReport,
  IncidentLog,
  IncidentStats,
  ThreatCategory,
  ShieldAppwriteClient,
  DateRange,
} from '../core/types'
import { CATEGORY_LABELS } from '../core/types'

// ─── Types ─────────────────────────────────────────────────────

interface ChatMessage {
  role: 'system' | 'user' | 'assistant'
  content: string
}

interface ChatCompletionResponse {
  choices: Array<{
    message: {
      content: string
    }
  }>
  model: string
  usage?: {
    prompt_tokens: number
    completion_tokens: number
    total_tokens: number
  }
}

// ─── AI Analytics Client ───────────────────────────────────────

/**
 * Create an AI analytics pipeline.
 *
 * @param config - AI/LLM provider configuration
 * @returns Object with analysis methods
 */
export function createAIAnalytics(config: AIConfig) {
  const { baseUrl, apiKey, model } = config

  /**
   * Call the OpenAI-compatible chat completions API.
   */
  async function chatCompletion(
    messages: ChatMessage[],
    options?: { temperature?: number; maxTokens?: number }
  ): Promise<string> {
    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages,
        temperature: options?.temperature ?? 0.3,
        max_tokens: options?.maxTokens ?? 4096,
        response_format: { type: 'json_object' },
      }),
    })

    if (!response.ok) {
      const error = await response.text()
      throw new Error(`[xpecto-shield] AI API error (${response.status}): ${error}`)
    }

    const data = (await response.json()) as ChatCompletionResponse
    return data.choices[0]?.message?.content || ''
  }

  return {
    /**
     * Generate a comprehensive security analysis report from incident data.
     *
     * @param incidents - Array of incident logs to analyze
     * @param stats - Aggregated incident statistics
     * @param dateRange - The analysis time period
     * @returns An AIReport ready for storage
     */
    async generateReport(
      incidents: IncidentLog[],
      stats: IncidentStats,
      dateRange: DateRange
    ): Promise<AIReport> {
      // Prepare incident summary for the AI
      const incidentSummary = prepareIncidentSummary(incidents, stats)

      const systemPrompt = `You are a senior cybersecurity analyst AI for "Xpecto Shield", an Intrusion Detection & Prevention System (IDPS). Your role is to analyze web attack incidents and produce structured, actionable security reports.

You must respond in valid JSON format with the following structure:
{
  "executiveSummary": "A 2-3 paragraph executive summary of the security status",
  "patternAnalysis": {
    "dominantAttackTypes": ["list of most common attack types"],
    "attackPatterns": ["identified patterns in the attacks"],
    "sophisticationLevel": "low|medium|high",
    "notes": "any additional pattern observations"
  },
  "trendAnalysis": {
    "volumeTrend": "increasing|stable|decreasing",
    "peakHours": ["hours with most attacks"],
    "emergingThreats": ["any new or unusual attack patterns"],
    "notes": "trend observations"
  },
  "riskAssessment": {
    "overallRisk": "low|medium|high|critical",
    "categoryRisks": {"sqli": "level", "xss": "level", ...},
    "vulnerabilities": ["potential vulnerabilities suggested by the attacks"],
    "notes": "risk observations"
  },
  "recommendations": {
    "immediate": ["urgent actions to take"],
    "shortTerm": ["actions for the next 1-2 weeks"],
    "longTerm": ["strategic security improvements"],
    "notes": "additional recommendations"
  },
  "threatLevel": "low|medium|high|critical"
}`

      const userPrompt = `Analyze the following web security incident data and generate a comprehensive report:

## Analysis Period
From: ${dateRange.start}
To: ${dateRange.end}

## Incident Statistics
${incidentSummary}

Provide your analysis in the specified JSON format.`

      try {
        const aiResponse = await chatCompletion(
          [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt },
          ],
          { temperature: 0.3, maxTokens: 4096 }
        )

        // Parse the AI response
        const parsed = JSON.parse(aiResponse)

        const report: AIReport = {
          createdAt: new Date().toISOString(),
          dateRangeStart: dateRange.start,
          dateRangeEnd: dateRange.end,
          incidentCount: incidents.length,
          executiveSummary: parsed.executiveSummary || 'No summary available.',
          patternAnalysis: JSON.stringify(parsed.patternAnalysis || {}),
          trendAnalysis: JSON.stringify(parsed.trendAnalysis || {}),
          riskAssessment: JSON.stringify(parsed.riskAssessment || {}),
          recommendations: JSON.stringify(parsed.recommendations || {}),
          threatLevel: parsed.threatLevel || 'medium',
          modelUsed: model,
        }

        return report
      } catch (error) {
        console.error('[xpecto-shield] AI report generation failed:', error)

        // Return a fallback report
        return {
          createdAt: new Date().toISOString(),
          dateRangeStart: dateRange.start,
          dateRangeEnd: dateRange.end,
          incidentCount: incidents.length,
          executiveSummary: `AI analysis unavailable. ${incidents.length} incidents detected during this period. Manual review recommended.`,
          patternAnalysis: JSON.stringify({ error: 'AI analysis failed' }),
          trendAnalysis: JSON.stringify({ error: 'AI analysis failed' }),
          riskAssessment: JSON.stringify({ error: 'AI analysis failed' }),
          recommendations: JSON.stringify({ immediate: ['Review incidents manually'] }),
          threatLevel: incidents.length > 100 ? 'high' : incidents.length > 10 ? 'medium' : 'low',
          modelUsed: model,
        }
      }
    },

    /**
     * Generate a quick threat assessment for a single incident.
     */
    async assessThreat(incident: IncidentLog): Promise<{
      severity: 'low' | 'medium' | 'high' | 'critical'
      analysis: string
      recommendation: string
    }> {
      const prompt = `Briefly assess this web attack in 2-3 sentences:
- Category: ${CATEGORY_LABELS[incident.attackCategory]}
- Payload: ${incident.matchedPayload.substring(0, 200)}
- Path: ${incident.requestPath}
- Confidence: ${(incident.confidence * 100).toFixed(0)}%

Respond in JSON: { "severity": "low|medium|high|critical", "analysis": "...", "recommendation": "..." }`

      try {
        const response = await chatCompletion(
          [{ role: 'user', content: prompt }],
          { temperature: 0.2, maxTokens: 500 }
        )

        return JSON.parse(response)
      } catch {
        return {
          severity: incident.confidence > 0.9 ? 'high' : 'medium',
          analysis: `${CATEGORY_LABELS[incident.attackCategory]} attack detected with ${(incident.confidence * 100).toFixed(0)}% confidence.`,
          recommendation: 'Review the incident details and verify the block action.',
        }
      }
    },
  }
}

// ─── Helpers ───────────────────────────────────────────────────

function prepareIncidentSummary(
  incidents: IncidentLog[],
  stats: IncidentStats
): string {
  const lines: string[] = []

  lines.push(`Total Incidents: ${stats.totalIncidents}`)
  lines.push(`Blocked IPs: ${stats.totalBlockedIPs}`)
  lines.push(`Active Threats (last hour): ${stats.activeThreats}`)
  lines.push(`Average Confidence: ${(stats.averageConfidence * 100).toFixed(1)}%`)
  lines.push('')

  lines.push('### Attack Category Breakdown')
  for (const [cat, count] of Object.entries(stats.categoryBreakdown)) {
    if (count > 0) {
      const label = CATEGORY_LABELS[cat as ThreatCategory]
      const pct = ((count / stats.totalIncidents) * 100).toFixed(1)
      lines.push(`- ${label}: ${count} (${pct}%)`)
    }
  }
  lines.push('')

  lines.push('### Top Attacker IPs')
  for (const attacker of stats.topAttackerIPs.slice(0, 5)) {
    lines.push(`- ${attacker.ip}: ${attacker.count} attacks (last: ${CATEGORY_LABELS[attacker.lastCategory]})`)
  }
  lines.push('')

  // Sample payloads (up to 10)
  lines.push('### Sample Detected Payloads')
  const samplePayloads = incidents.slice(0, 10)
  for (const inc of samplePayloads) {
    lines.push(`- [${inc.attackCategory}] ${inc.matchedPayload.substring(0, 100)} (conf: ${(inc.confidence * 100).toFixed(0)}%)`)
  }

  return lines.join('\n')
}
