import { CATEGORY_LABELS } from './chunk-PTK2JL2Y.js';
import { Client, Databases, Query, ID } from 'node-appwrite';

var COLLECTIONS = {
  INCIDENTS: "shield_incidents",
  BLOCKED_IPS: "shield_blocked_ips",
  AI_REPORTS: "shield_ai_reports",
  SETTINGS: "shield_settings"
};
function createAppwriteClient(config) {
  const {
    endpoint,
    projectId,
    apiKey,
    databaseId = "xpecto_shield"
  } = config;
  const client = new Client().setEndpoint(endpoint).setProject(projectId).setKey(apiKey);
  const databases = new Databases(client);
  function buildPaginationQueries(options) {
    const queries = [];
    const limit = options.limit || 25;
    const page = options.page || 1;
    const offset = (page - 1) * limit;
    queries.push(Query.limit(limit));
    queries.push(Query.offset(offset));
    if (options.sortBy) {
      queries.push(
        options.sortOrder === "asc" ? Query.orderAsc(options.sortBy) : Query.orderDesc(options.sortBy)
      );
    } else {
      queries.push(Query.orderDesc("$createdAt"));
    }
    return queries;
  }
  function buildIncidentFilterQueries(filters) {
    const queries = [];
    if (filters.category) {
      queries.push(Query.equal("attackCategory", filters.category));
    }
    if (filters.sourceIP) {
      queries.push(Query.equal("sourceIP", filters.sourceIP));
    }
    if (filters.action) {
      queries.push(Query.equal("action", filters.action));
    }
    if (filters.dateFrom) {
      queries.push(Query.greaterThanEqual("timestamp", filters.dateFrom));
    }
    if (filters.dateTo) {
      queries.push(Query.lessThanEqual("timestamp", filters.dateTo));
    }
    if (filters.minConfidence !== void 0) {
      queries.push(Query.greaterThanEqual("confidence", filters.minConfidence));
    }
    return queries;
  }
  const shieldClient = {
    // ════════════════ Incidents ════════════════════════════
    async logIncident(incident) {
      try {
        await databases.createDocument(
          databaseId,
          COLLECTIONS.INCIDENTS,
          ID.unique(),
          {
            timestamp: incident.timestamp,
            sourceIP: incident.sourceIP,
            requestPath: incident.requestPath,
            requestMethod: incident.requestMethod,
            attackCategory: incident.attackCategory,
            matchedPayload: incident.matchedPayload.substring(0, 500),
            confidence: incident.confidence,
            rawInput: incident.rawInput.substring(0, 1e3),
            action: incident.action,
            userAgent: incident.userAgent.substring(0, 500),
            geoLocation: incident.geoLocation || null
          }
        );
      } catch (error) {
        console.error("[xpecto-shield] Failed to log incident:", error);
        throw error;
      }
    },
    async getIncidents(options) {
      const queries = [
        ...buildPaginationQueries(options),
        ...options.filters ? buildIncidentFilterQueries(options.filters) : []
      ];
      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.INCIDENTS,
        queries
      );
      const limit = options.limit || 25;
      const page = options.page || 1;
      return {
        data: response.documents.map((doc) => ({
          id: doc.$id,
          timestamp: doc.timestamp,
          sourceIP: doc.sourceIP,
          requestPath: doc.requestPath,
          requestMethod: doc.requestMethod,
          attackCategory: doc.attackCategory,
          matchedPayload: doc.matchedPayload,
          confidence: doc.confidence,
          rawInput: doc.rawInput,
          action: doc.action,
          userAgent: doc.userAgent,
          geoLocation: doc.geoLocation
        })),
        total: response.total,
        page,
        limit,
        hasMore: page * limit < response.total
      };
    },
    async getIncidentStats(dateRange) {
      const queries = [Query.limit(5e3)];
      if (dateRange) {
        queries.push(Query.greaterThanEqual("timestamp", dateRange.start));
        queries.push(Query.lessThanEqual("timestamp", dateRange.end));
      }
      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.INCIDENTS,
        queries
      );
      const categoryBreakdown = {
        sqli: 0,
        xss: 0,
        lfi: 0,
        ssrf: 0,
        "path-traversal": 0
      };
      const ipCounts = {};
      const hourCounts = {};
      let totalConfidence = 0;
      for (const doc of response.documents) {
        const cat = doc.attackCategory;
        categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + 1;
        const ip = doc.sourceIP;
        if (!ipCounts[ip]) ipCounts[ip] = { count: 0, lastCategory: cat };
        ipCounts[ip].count++;
        ipCounts[ip].lastCategory = cat;
        const hour = doc.timestamp.substring(0, 13);
        hourCounts[hour] = (hourCounts[hour] || 0) + 1;
        totalConfidence += doc.confidence;
      }
      let totalBlockedIPs = 0;
      try {
        const blocked = await databases.listDocuments(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          [Query.equal("isActive", true), Query.limit(1)]
        );
        totalBlockedIPs = blocked.total;
      } catch {
      }
      const topAttackerIPs = Object.entries(ipCounts).sort((a, b) => b[1].count - a[1].count).slice(0, 10).map(([ip, data]) => ({
        ip,
        count: data.count,
        lastCategory: data.lastCategory
      }));
      const hourlyTimeline = Object.entries(hourCounts).sort((a, b) => a[0].localeCompare(b[0])).slice(-24).map(([hour, count]) => ({ hour, count }));
      return {
        totalIncidents: response.total,
        totalBlockedIPs,
        activeThreats: response.documents.filter(
          (doc) => {
            const ts = new Date(doc.timestamp).getTime();
            return Date.now() - ts < 36e5;
          }
        ).length,
        categoryBreakdown,
        hourlyTimeline,
        topAttackerIPs,
        averageConfidence: response.total > 0 ? totalConfidence / response.total : 0
      };
    },
    // ════════════════ Blocked IPs ══════════════════════════
    async isIPBlocked(ip) {
      try {
        const response = await databases.listDocuments(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          [
            Query.equal("ipAddress", ip),
            Query.equal("isActive", true),
            Query.limit(1)
          ]
        );
        if (response.documents.length === 0) return false;
        const doc = response.documents[0];
        const expiresAt = doc.expiresAt;
        if (expiresAt && new Date(expiresAt).getTime() < Date.now()) {
          await databases.updateDocument(
            databaseId,
            COLLECTIONS.BLOCKED_IPS,
            doc.$id,
            { isActive: false }
          );
          return false;
        }
        return true;
      } catch {
        return false;
      }
    },
    async getIPRecord(ip) {
      try {
        const response = await databases.listDocuments(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          [Query.equal("ipAddress", ip), Query.limit(1)]
        );
        if (response.documents.length === 0) return null;
        const doc = response.documents[0];
        return {
          id: doc.$id,
          ipAddress: doc.ipAddress,
          reason: doc.reason,
          strikeCount: doc.strikeCount,
          blockedAt: doc.blockedAt,
          expiresAt: doc.expiresAt,
          lastAttackCategory: doc.lastAttackCategory,
          isActive: doc.isActive
        };
      } catch {
        return null;
      }
    },
    async incrementStrike(ip, category) {
      const existing = await shieldClient.getIPRecord(ip);
      if (existing) {
        const newCount = existing.strikeCount + 1;
        await databases.updateDocument(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          existing.id,
          {
            strikeCount: newCount,
            lastAttackCategory: category
          }
        );
        return newCount;
      }
      await databases.createDocument(
        databaseId,
        COLLECTIONS.BLOCKED_IPS,
        ID.unique(),
        {
          ipAddress: ip,
          reason: "auto",
          strikeCount: 1,
          blockedAt: (/* @__PURE__ */ new Date()).toISOString(),
          expiresAt: null,
          lastAttackCategory: category,
          isActive: false
        }
      );
      return 1;
    },
    async blockIP(ip, reason, duration) {
      const expiresAt = duration ? new Date(Date.now() + duration * 1e3).toISOString() : null;
      const existing = await shieldClient.getIPRecord(ip);
      if (existing) {
        await databases.updateDocument(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          existing.id,
          {
            reason,
            blockedAt: (/* @__PURE__ */ new Date()).toISOString(),
            expiresAt,
            isActive: true
          }
        );
      } else {
        await databases.createDocument(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          ID.unique(),
          {
            ipAddress: ip,
            reason,
            strikeCount: 0,
            blockedAt: (/* @__PURE__ */ new Date()).toISOString(),
            expiresAt,
            lastAttackCategory: "sqli",
            isActive: true
          }
        );
      }
    },
    async unblockIP(ip) {
      const existing = await shieldClient.getIPRecord(ip);
      if (existing) {
        await databases.updateDocument(
          databaseId,
          COLLECTIONS.BLOCKED_IPS,
          existing.id,
          { isActive: false }
        );
      }
    },
    async getBlockedIPs(options) {
      const queries = [
        ...buildPaginationQueries(options),
        Query.equal("isActive", true)
      ];
      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.BLOCKED_IPS,
        queries
      );
      const limit = options.limit || 25;
      const page = options.page || 1;
      return {
        data: response.documents.map((doc) => ({
          id: doc.$id,
          ipAddress: doc.ipAddress,
          reason: doc.reason,
          strikeCount: doc.strikeCount,
          blockedAt: doc.blockedAt,
          expiresAt: doc.expiresAt,
          lastAttackCategory: doc.lastAttackCategory,
          isActive: doc.isActive
        })),
        total: response.total,
        page,
        limit,
        hasMore: page * limit < response.total
      };
    },
    // ════════════════ AI Reports ═══════════════════════════
    async saveReport(report) {
      const doc = await databases.createDocument(
        databaseId,
        COLLECTIONS.AI_REPORTS,
        ID.unique(),
        {
          createdAt: report.createdAt,
          dateRangeStart: report.dateRangeStart,
          dateRangeEnd: report.dateRangeEnd,
          incidentCount: report.incidentCount,
          executiveSummary: report.executiveSummary,
          patternAnalysis: report.patternAnalysis,
          trendAnalysis: report.trendAnalysis,
          riskAssessment: report.riskAssessment,
          recommendations: report.recommendations,
          threatLevel: report.threatLevel,
          modelUsed: report.modelUsed
        }
      );
      return doc.$id;
    },
    async getReport(id) {
      const doc = await databases.getDocument(
        databaseId,
        COLLECTIONS.AI_REPORTS,
        id
      );
      return {
        id: doc.$id,
        createdAt: doc.createdAt,
        dateRangeStart: doc.dateRangeStart,
        dateRangeEnd: doc.dateRangeEnd,
        incidentCount: doc.incidentCount,
        executiveSummary: doc.executiveSummary,
        patternAnalysis: doc.patternAnalysis,
        trendAnalysis: doc.trendAnalysis,
        riskAssessment: doc.riskAssessment,
        recommendations: doc.recommendations,
        threatLevel: doc.threatLevel,
        modelUsed: doc.modelUsed
      };
    },
    async getReports(options) {
      const queries = buildPaginationQueries(options);
      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.AI_REPORTS,
        queries
      );
      const limit = options.limit || 25;
      const page = options.page || 1;
      return {
        data: response.documents.map((doc) => ({
          id: doc.$id,
          createdAt: doc.createdAt,
          dateRangeStart: doc.dateRangeStart,
          dateRangeEnd: doc.dateRangeEnd,
          incidentCount: doc.incidentCount,
          executiveSummary: doc.executiveSummary,
          patternAnalysis: doc.patternAnalysis,
          trendAnalysis: doc.trendAnalysis,
          riskAssessment: doc.riskAssessment,
          recommendations: doc.recommendations,
          threatLevel: doc.threatLevel,
          modelUsed: doc.modelUsed
        })),
        total: response.total,
        page,
        limit,
        hasMore: page * limit < response.total
      };
    },
    // ════════════════ Settings ═════════════════════════════
    async getSetting(key) {
      try {
        const doc = await databases.getDocument(
          databaseId,
          COLLECTIONS.SETTINGS,
          key
        );
        return doc.value;
      } catch {
        return null;
      }
    },
    async setSetting(key, value) {
      try {
        await databases.getDocument(databaseId, COLLECTIONS.SETTINGS, key);
        await databases.updateDocument(
          databaseId,
          COLLECTIONS.SETTINGS,
          key,
          { value }
        );
      } catch {
        await databases.createDocument(
          databaseId,
          COLLECTIONS.SETTINGS,
          key,
          { key, value }
        );
      }
    },
    async getAllSettings() {
      const response = await databases.listDocuments(
        databaseId,
        COLLECTIONS.SETTINGS,
        [Query.limit(100)]
      );
      const settings = {};
      for (const doc of response.documents) {
        settings[doc.key] = doc.value;
      }
      return settings;
    },
    // ════════════════ Setup ════════════════════════════════
    async ensureCollections() {
      console.log("[xpecto-shield] Ensuring Appwrite collections exist...");
      try {
        try {
          await databases.create(databaseId, "Xpecto Shield");
        } catch {
        }
        const collections = [
          {
            id: COLLECTIONS.INCIDENTS,
            name: "Shield Incidents",
            attributes: [
              { key: "timestamp", type: "string", size: 30, required: true },
              { key: "sourceIP", type: "string", size: 50, required: true },
              { key: "requestPath", type: "string", size: 500, required: true },
              { key: "requestMethod", type: "string", size: 10, required: true },
              { key: "attackCategory", type: "string", size: 20, required: true },
              { key: "matchedPayload", type: "string", size: 500, required: true },
              { key: "confidence", type: "float", required: true },
              { key: "rawInput", type: "string", size: 1e3, required: true },
              { key: "action", type: "string", size: 10, required: true },
              { key: "userAgent", type: "string", size: 500, required: true },
              { key: "geoLocation", type: "string", size: 100, required: false }
            ],
            indexes: [
              { key: "idx_timestamp", type: "key", attributes: ["timestamp"], orders: ["DESC"] },
              { key: "idx_sourceIP", type: "key", attributes: ["sourceIP"] },
              { key: "idx_category", type: "key", attributes: ["attackCategory"] }
            ]
          },
          {
            id: COLLECTIONS.BLOCKED_IPS,
            name: "Shield Blocked IPs",
            attributes: [
              { key: "ipAddress", type: "string", size: 50, required: true },
              { key: "reason", type: "string", size: 10, required: true },
              { key: "strikeCount", type: "integer", required: true },
              { key: "blockedAt", type: "string", size: 30, required: true },
              { key: "expiresAt", type: "string", size: 30, required: false },
              { key: "lastAttackCategory", type: "string", size: 20, required: true },
              { key: "isActive", type: "boolean", required: true }
            ],
            indexes: [
              { key: "idx_ipAddress", type: "key", attributes: ["ipAddress"] },
              { key: "idx_isActive", type: "key", attributes: ["isActive"] }
            ]
          },
          {
            id: COLLECTIONS.AI_REPORTS,
            name: "Shield AI Reports",
            attributes: [
              { key: "createdAt", type: "string", size: 30, required: true },
              { key: "dateRangeStart", type: "string", size: 30, required: true },
              { key: "dateRangeEnd", type: "string", size: 30, required: true },
              { key: "incidentCount", type: "integer", required: true },
              { key: "executiveSummary", type: "string", size: 5e3, required: true },
              { key: "patternAnalysis", type: "string", size: 1e4, required: true },
              { key: "trendAnalysis", type: "string", size: 1e4, required: true },
              { key: "riskAssessment", type: "string", size: 5e3, required: true },
              { key: "recommendations", type: "string", size: 5e3, required: true },
              { key: "threatLevel", type: "string", size: 10, required: true },
              { key: "modelUsed", type: "string", size: 100, required: true }
            ]
          },
          {
            id: COLLECTIONS.SETTINGS,
            name: "Shield Settings",
            attributes: [
              { key: "key", type: "string", size: 100, required: true },
              { key: "value", type: "string", size: 5e3, required: true }
            ]
          }
        ];
        for (const col of collections) {
          try {
            await databases.createCollection(databaseId, col.id, col.name);
            console.log(`[xpecto-shield] Created collection: ${col.name}`);
          } catch {
          }
          for (const attr of col.attributes) {
            try {
              if (attr.type === "string") {
                await databases.createStringAttribute(
                  databaseId,
                  col.id,
                  attr.key,
                  attr.size,
                  attr.required
                );
              } else if (attr.type === "integer") {
                await databases.createIntegerAttribute(
                  databaseId,
                  col.id,
                  attr.key,
                  attr.required
                );
              } else if (attr.type === "float") {
                await databases.createFloatAttribute(
                  databaseId,
                  col.id,
                  attr.key,
                  attr.required
                );
              } else if (attr.type === "boolean") {
                await databases.createBooleanAttribute(
                  databaseId,
                  col.id,
                  attr.key,
                  attr.required
                );
              }
            } catch {
            }
          }
          if ("indexes" in col && col.indexes) {
            for (const idx of col.indexes) {
              try {
                await databases.createIndex(
                  databaseId,
                  col.id,
                  idx.key,
                  idx.type,
                  idx.attributes,
                  idx.orders
                );
              } catch {
              }
            }
          }
        }
        console.log("[xpecto-shield] \u2713 All collections verified/created");
      } catch (error) {
        console.error("[xpecto-shield] Collection setup error:", error);
        throw error;
      }
    }
  };
  return shieldClient;
}

// src/api/ai-analytics.ts
function createAIAnalytics(config) {
  const { baseUrl, apiKey, model } = config;
  async function chatCompletion(messages, options) {
    const response = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model,
        messages,
        temperature: options?.temperature ?? 0.3,
        max_tokens: options?.maxTokens ?? 4096,
        response_format: { type: "json_object" }
      })
    });
    if (!response.ok) {
      const error = await response.text();
      throw new Error(`[xpecto-shield] AI API error (${response.status}): ${error}`);
    }
    const data = await response.json();
    return data.choices[0]?.message?.content || "";
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
    async generateReport(incidents, stats, dateRange) {
      const incidentSummary = prepareIncidentSummary(incidents, stats);
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
}`;
      const userPrompt = `Analyze the following web security incident data and generate a comprehensive report:

## Analysis Period
From: ${dateRange.start}
To: ${dateRange.end}

## Incident Statistics
${incidentSummary}

Provide your analysis in the specified JSON format.`;
      try {
        const aiResponse = await chatCompletion(
          [
            { role: "system", content: systemPrompt },
            { role: "user", content: userPrompt }
          ],
          { temperature: 0.3, maxTokens: 4096 }
        );
        const parsed = JSON.parse(aiResponse);
        const report = {
          createdAt: (/* @__PURE__ */ new Date()).toISOString(),
          dateRangeStart: dateRange.start,
          dateRangeEnd: dateRange.end,
          incidentCount: incidents.length,
          executiveSummary: parsed.executiveSummary || "No summary available.",
          patternAnalysis: JSON.stringify(parsed.patternAnalysis || {}),
          trendAnalysis: JSON.stringify(parsed.trendAnalysis || {}),
          riskAssessment: JSON.stringify(parsed.riskAssessment || {}),
          recommendations: JSON.stringify(parsed.recommendations || {}),
          threatLevel: parsed.threatLevel || "medium",
          modelUsed: model
        };
        return report;
      } catch (error) {
        console.error("[xpecto-shield] AI report generation failed:", error);
        return {
          createdAt: (/* @__PURE__ */ new Date()).toISOString(),
          dateRangeStart: dateRange.start,
          dateRangeEnd: dateRange.end,
          incidentCount: incidents.length,
          executiveSummary: `AI analysis unavailable. ${incidents.length} incidents detected during this period. Manual review recommended.`,
          patternAnalysis: JSON.stringify({ error: "AI analysis failed" }),
          trendAnalysis: JSON.stringify({ error: "AI analysis failed" }),
          riskAssessment: JSON.stringify({ error: "AI analysis failed" }),
          recommendations: JSON.stringify({ immediate: ["Review incidents manually"] }),
          threatLevel: incidents.length > 100 ? "high" : incidents.length > 10 ? "medium" : "low",
          modelUsed: model
        };
      }
    },
    /**
     * Generate a quick threat assessment for a single incident.
     */
    async assessThreat(incident) {
      const prompt = `Briefly assess this web attack in 2-3 sentences:
- Category: ${CATEGORY_LABELS[incident.attackCategory]}
- Payload: ${incident.matchedPayload.substring(0, 200)}
- Path: ${incident.requestPath}
- Confidence: ${(incident.confidence * 100).toFixed(0)}%

Respond in JSON: { "severity": "low|medium|high|critical", "analysis": "...", "recommendation": "..." }`;
      try {
        const response = await chatCompletion(
          [{ role: "user", content: prompt }],
          { temperature: 0.2, maxTokens: 500 }
        );
        return JSON.parse(response);
      } catch {
        return {
          severity: incident.confidence > 0.9 ? "high" : "medium",
          analysis: `${CATEGORY_LABELS[incident.attackCategory]} attack detected with ${(incident.confidence * 100).toFixed(0)}% confidence.`,
          recommendation: "Review the incident details and verify the block action."
        };
      }
    }
  };
}
function prepareIncidentSummary(incidents, stats) {
  const lines = [];
  lines.push(`Total Incidents: ${stats.totalIncidents}`);
  lines.push(`Blocked IPs: ${stats.totalBlockedIPs}`);
  lines.push(`Active Threats (last hour): ${stats.activeThreats}`);
  lines.push(`Average Confidence: ${(stats.averageConfidence * 100).toFixed(1)}%`);
  lines.push("");
  lines.push("### Attack Category Breakdown");
  for (const [cat, count] of Object.entries(stats.categoryBreakdown)) {
    if (count > 0) {
      const label = CATEGORY_LABELS[cat];
      const pct = (count / stats.totalIncidents * 100).toFixed(1);
      lines.push(`- ${label}: ${count} (${pct}%)`);
    }
  }
  lines.push("");
  lines.push("### Top Attacker IPs");
  for (const attacker of stats.topAttackerIPs.slice(0, 5)) {
    lines.push(`- ${attacker.ip}: ${attacker.count} attacks (last: ${CATEGORY_LABELS[attacker.lastCategory]})`);
  }
  lines.push("");
  lines.push("### Sample Detected Payloads");
  const samplePayloads = incidents.slice(0, 10);
  for (const inc of samplePayloads) {
    lines.push(`- [${inc.attackCategory}] ${inc.matchedPayload.substring(0, 100)} (conf: ${(inc.confidence * 100).toFixed(0)}%)`);
  }
  return lines.join("\n");
}

// src/api/dashboard-api.ts
function createShieldAPI(config) {
  const appwriteClient = createAppwriteClient(config.appwrite);
  const aiAnalytics = config.ai ? createAIAnalytics(config.ai) : null;
  async function requireAuth(request) {
    const isAuthed = await config.authCheck(request);
    if (!isAuthed) {
      return new Response(
        JSON.stringify({ error: "UNAUTHORIZED", message: "Admin access required." }),
        { status: 401, headers: { "Content-Type": "application/json" } }
      );
    }
    return null;
  }
  function getSlug(request) {
    const url = new URL(request.url);
    const match = url.pathname.match(/\/api\/shield\/(.*)/);
    if (!match) return [];
    return match[1].split("/").filter(Boolean);
  }
  return {
    /**
     * GET /api/shield/:resource
     * Resources: stats, incidents, blocked-ips, reports, settings
     */
    async handleGET(request) {
      const authError = await requireAuth(request);
      if (authError) return authError;
      const slug = getSlug(request);
      const url = new URL(request.url);
      const resource = slug[0];
      try {
        switch (resource) {
          case "stats": {
            const from = url.searchParams.get("from") || void 0;
            const to = url.searchParams.get("to") || void 0;
            const dateRange = from && to ? { start: from, end: to } : void 0;
            const stats = await appwriteClient.getIncidentStats(dateRange);
            return jsonResponse(stats);
          }
          case "incidents": {
            const page = parseInt(url.searchParams.get("page") || "1");
            const limit = parseInt(url.searchParams.get("limit") || "25");
            const category = url.searchParams.get("category");
            const sourceIP = url.searchParams.get("ip") || void 0;
            const dateFrom = url.searchParams.get("from") || void 0;
            const dateTo = url.searchParams.get("to") || void 0;
            const result = await appwriteClient.getIncidents({
              page,
              limit,
              sortBy: "timestamp",
              sortOrder: "desc",
              filters: {
                category: category || void 0,
                sourceIP,
                dateFrom,
                dateTo
              }
            });
            return jsonResponse(result);
          }
          case "blocked-ips": {
            const page = parseInt(url.searchParams.get("page") || "1");
            const limit = parseInt(url.searchParams.get("limit") || "25");
            const result = await appwriteClient.getBlockedIPs({ page, limit });
            return jsonResponse(result);
          }
          case "reports": {
            if (slug[1]) {
              const report = await appwriteClient.getReport(slug[1]);
              return jsonResponse(report);
            }
            const page = parseInt(url.searchParams.get("page") || "1");
            const limit = parseInt(url.searchParams.get("limit") || "10");
            const result = await appwriteClient.getReports({ page, limit });
            return jsonResponse(result);
          }
          case "settings": {
            const settings = await appwriteClient.getAllSettings();
            return jsonResponse(settings);
          }
          default:
            return jsonResponse({ error: "NOT_FOUND", message: `Unknown resource: ${resource}` }, 404);
        }
      } catch (error) {
        console.error(`[xpecto-shield] API GET error (${resource}):`, error);
        return jsonResponse({ error: "INTERNAL_ERROR", message: "An internal error occurred." }, 500);
      }
    },
    /**
     * POST /api/shield/:resource
     * Resources: block-ip, unblock-ip, generate-report, settings, setup
     */
    async handlePOST(request) {
      const authError = await requireAuth(request);
      if (authError) return authError;
      const slug = getSlug(request);
      const resource = slug[0];
      try {
        switch (resource) {
          case "block-ip": {
            const body = await request.json();
            const { ip, duration } = body;
            if (!ip) {
              return jsonResponse({ error: "INVALID_INPUT", message: "IP address required." }, 400);
            }
            await appwriteClient.blockIP(ip, "manual", duration);
            return jsonResponse({ success: true, message: `Blocked IP: ${ip}` });
          }
          case "unblock-ip": {
            const body = await request.json();
            const { ip } = body;
            if (!ip) {
              return jsonResponse({ error: "INVALID_INPUT", message: "IP address required." }, 400);
            }
            await appwriteClient.unblockIP(ip);
            return jsonResponse({ success: true, message: `Unblocked IP: ${ip}` });
          }
          case "generate-report": {
            if (!aiAnalytics) {
              return jsonResponse(
                { error: "AI_NOT_CONFIGURED", message: "AI analytics is not configured." },
                400
              );
            }
            const body = await request.json();
            const { from, to } = body;
            if (!from || !to) {
              return jsonResponse({ error: "INVALID_INPUT", message: "Date range required." }, 400);
            }
            const dateRange = { start: from, end: to };
            const stats = await appwriteClient.getIncidentStats(dateRange);
            const incidents = await appwriteClient.getIncidents({
              page: 1,
              limit: 500,
              filters: { dateFrom: from, dateTo: to }
            });
            const report = await aiAnalytics.generateReport(
              incidents.data,
              stats,
              dateRange
            );
            const reportId = await appwriteClient.saveReport(report);
            return jsonResponse({ success: true, reportId, report });
          }
          case "settings": {
            const body = await request.json();
            const settings = body;
            for (const [key, value] of Object.entries(settings)) {
              await appwriteClient.setSetting(key, value);
            }
            return jsonResponse({ success: true, message: "Settings updated." });
          }
          case "setup": {
            await appwriteClient.ensureCollections();
            return jsonResponse({ success: true, message: "Collections created/verified." });
          }
          default:
            return jsonResponse({ error: "NOT_FOUND", message: `Unknown action: ${resource}` }, 404);
        }
      } catch (error) {
        console.error(`[xpecto-shield] API POST error (${resource}):`, error);
        return jsonResponse({ error: "INTERNAL_ERROR", message: "An internal error occurred." }, 500);
      }
    },
    /**
     * DELETE /api/shield/:resource/:id
     */
    async handleDELETE(request) {
      const authError = await requireAuth(request);
      if (authError) return authError;
      const slug = getSlug(request);
      const resource = slug[0];
      try {
        switch (resource) {
          case "unblock-ip": {
            const ip = slug[1];
            if (!ip) {
              return jsonResponse({ error: "INVALID_INPUT", message: "IP address required." }, 400);
            }
            await appwriteClient.unblockIP(decodeURIComponent(ip));
            return jsonResponse({ success: true, message: `Unblocked IP: ${ip}` });
          }
          default:
            return jsonResponse({ error: "NOT_FOUND", message: `Unknown resource: ${resource}` }, 404);
        }
      } catch (error) {
        console.error(`[xpecto-shield] API DELETE error (${resource}):`, error);
        return jsonResponse({ error: "INTERNAL_ERROR", message: "An internal error occurred." }, 500);
      }
    }
  };
}
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

export { createAIAnalytics, createAppwriteClient, createShieldAPI };
//# sourceMappingURL=chunk-EGNL2GFQ.js.map
//# sourceMappingURL=chunk-EGNL2GFQ.js.map