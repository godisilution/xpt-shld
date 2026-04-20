import { createDetectionEngine, createDetectionEngineFromCompiled } from './chunk-5P3M5JP2.js';

// src/middleware/request-analyzer.ts
async function extractRequestInputs(request) {
  const inputs = {};
  const url = new URL(request.url);
  inputs["url.path"] = url.pathname;
  for (const [key, value] of url.searchParams.entries()) {
    inputs[`query.${key}`] = value;
  }
  const scannableHeaders = [
    "referer",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-real-ip",
    "user-agent",
    "origin"
  ];
  for (const header of scannableHeaders) {
    const value = request.headers.get(header);
    if (value) {
      inputs[`header.${header}`] = value;
    }
  }
  const cookieHeader = request.headers.get("cookie");
  if (cookieHeader) {
    const cookies = parseCookieString(cookieHeader);
    for (const [key, value] of Object.entries(cookies)) {
      inputs[`cookie.${key}`] = value;
    }
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    try {
      const contentType = request.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        const body = await request.clone().json();
        flattenObject(body, "body", inputs);
      } else if (contentType.includes("application/x-www-form-urlencoded")) {
        const text = await request.clone().text();
        const params = new URLSearchParams(text);
        for (const [key, value] of params.entries()) {
          inputs[`body.${key}`] = value;
        }
      } else if (contentType.includes("multipart/form-data")) {
        try {
          const formData = await request.clone().formData();
          for (const [key, value] of formData.entries()) {
            if (typeof value === "string") {
              inputs[`body.${key}`] = value;
            }
          }
        } catch {
        }
      } else if (contentType.includes("text/")) {
        const text = await request.clone().text();
        if (text.length > 0 && text.length <= 1e4) {
          inputs["body.raw"] = text;
        }
      }
    } catch {
    }
  }
  return inputs;
}
function extractClientIP(request) {
  const ipHeaders = [
    "x-real-ip",
    "x-forwarded-for",
    "cf-connecting-ip",
    // Cloudflare
    "true-client-ip"
    // Akamai
  ];
  for (const header of ipHeaders) {
    const value = request.headers.get(header);
    if (value) {
      const ip = value.split(",")[0].trim();
      if (ip) return ip;
    }
  }
  return "0.0.0.0";
}
function matchesPath(urlPath, patterns) {
  for (const pattern of patterns) {
    if (pattern === "/*") return true;
    if (pattern === urlPath) return true;
    if (pattern.endsWith("/*")) {
      const prefix = pattern.slice(0, -2);
      if (urlPath === prefix || urlPath.startsWith(prefix + "/")) {
        return true;
      }
    }
  }
  return false;
}
function parseCookieString(cookieStr) {
  const cookies = {};
  const pairs = cookieStr.split(";");
  for (const pair of pairs) {
    const eqIndex = pair.indexOf("=");
    if (eqIndex === -1) continue;
    const key = pair.substring(0, eqIndex).trim();
    const value = pair.substring(eqIndex + 1).trim();
    if (key) {
      cookies[key] = value;
    }
  }
  return cookies;
}
function flattenObject(obj, prefix, result, depth = 0) {
  if (depth > 5) return;
  if (obj === null || obj === void 0) return;
  if (typeof obj === "string") {
    result[prefix] = obj;
    return;
  }
  if (typeof obj === "number" || typeof obj === "boolean") {
    result[prefix] = String(obj);
    return;
  }
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length && i < 50; i++) {
      flattenObject(obj[i], `${prefix}[${i}]`, result, depth + 1);
    }
    return;
  }
  if (typeof obj === "object") {
    for (const [key, value] of Object.entries(obj)) {
      flattenObject(value, `${prefix}.${key}`, result, depth + 1);
    }
  }
}

// src/middleware/response-builder.ts
function buildBlockResponse(category, clientIP) {
  const html = generateBlockPage(category);
  return new Response(html, {
    status: 403,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Shield-Status": "blocked",
      "X-Shield-Category": category,
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY"
    }
  });
}
function buildBlockResponseJSON(category, clientIP) {
  return new Response(
    JSON.stringify({
      error: "REQUEST_BLOCKED",
      message: "Your request has been blocked by Xpecto Shield.",
      category,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }),
    {
      status: 403,
      headers: {
        "Content-Type": "application/json",
        "X-Shield-Status": "blocked",
        "X-Shield-Category": category,
        "Cache-Control": "no-store"
      }
    }
  );
}
function isJSONRequest(request) {
  const accept = request.headers.get("accept") || "";
  const contentType = request.headers.get("content-type") || "";
  return accept.includes("application/json") || contentType.includes("application/json") || request.url.includes("/api/");
}
var CATEGORY_NAMES = {
  sqli: "SQL Injection",
  xss: "Cross-Site Scripting",
  lfi: "Local File Inclusion",
  ssrf: "Server-Side Request Forgery",
  "path-traversal": "Path Traversal"
};
function generateBlockPage(category, clientIP) {
  const categoryName = CATEGORY_NAMES[category];
  const timestamp = (/* @__PURE__ */ new Date()).toISOString();
  const incidentId = generateIncidentId();
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Denied \u2014 Xpecto Shield</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@700;900&display=swap');

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0a0a0f;
      color: #e0e0e0;
      font-family: 'JetBrains Mono', monospace;
      overflow: hidden;
    }

    /* Animated grid background */
    body::before {
      content: '';
      position: fixed;
      inset: 0;
      background: 
        linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      animation: gridScroll 20s linear infinite;
    }

    @keyframes gridScroll {
      0% { transform: translate(0, 0); }
      100% { transform: translate(40px, 40px); }
    }

    .shield-block {
      position: relative;
      max-width: 520px;
      width: 90%;
      background: rgba(10, 10, 20, 0.95);
      border: 1px solid rgba(0, 255, 136, 0.3);
      clip-path: polygon(0 12px, 12px 0, 100% 0, 100% calc(100% - 12px), calc(100% - 12px) 100%, 0 100%);
      padding: 2.5rem;
      text-align: center;
    }

    /* Corner accents */
    .shield-block::before,
    .shield-block::after {
      content: '';
      position: absolute;
      width: 40px;
      height: 40px;
      border: 1px solid #00ff88;
    }
    .shield-block::before {
      top: -1px;
      left: -1px;
      border-right: none;
      border-bottom: none;
    }
    .shield-block::after {
      bottom: -1px;
      right: -1px;
      border-left: none;
      border-top: none;
    }

    .shield-icon {
      font-size: 3rem;
      margin-bottom: 1rem;
      animation: pulse 2s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }

    .shield-title {
      font-family: 'Orbitron', sans-serif;
      font-weight: 900;
      font-size: 1.5rem;
      color: #ff3366;
      text-transform: uppercase;
      letter-spacing: 3px;
      margin-bottom: 0.5rem;
      text-shadow: 0 0 20px rgba(255, 51, 102, 0.5);
    }

    .shield-subtitle {
      font-size: 0.8rem;
      color: rgba(255, 255, 255, 0.4);
      margin-bottom: 1.5rem;
    }

    .shield-category {
      display: inline-block;
      background: rgba(255, 51, 102, 0.15);
      border: 1px solid rgba(255, 51, 102, 0.4);
      color: #ff3366;
      padding: 0.4rem 1rem;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 2px;
      margin-bottom: 1.5rem;
      clip-path: polygon(0 4px, 4px 0, 100% 0, 100% calc(100% - 4px), calc(100% - 4px) 100%, 0 100%);
    }

    .shield-message {
      font-size: 0.85rem;
      line-height: 1.6;
      color: rgba(255, 255, 255, 0.6);
      margin-bottom: 1.5rem;
    }

    .shield-details {
      text-align: left;
      background: rgba(0, 255, 136, 0.03);
      border: 1px solid rgba(0, 255, 136, 0.1);
      padding: 1rem;
      font-size: 0.7rem;
      color: rgba(0, 255, 136, 0.7);
      margin-bottom: 1rem;
    }

    .shield-details div {
      padding: 0.2rem 0;
    }

    .shield-details .label {
      color: rgba(255, 255, 255, 0.3);
      display: inline-block;
      width: 100px;
    }

    .shield-footer {
      font-size: 0.65rem;
      color: rgba(255, 255, 255, 0.2);
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      padding-top: 1rem;
    }

    .neon-line {
      height: 2px;
      background: linear-gradient(90deg, transparent, #00ff88, transparent);
      margin: 1.5rem 0;
      animation: scanLine 3s ease-in-out infinite;
    }

    @keyframes scanLine {
      0%, 100% { opacity: 0.3; }
      50% { opacity: 1; }
    }
  </style>
</head>
<body>
  <div class="shield-block">
    <div class="shield-icon">\u{1F6E1}\uFE0F</div>
    <div class="shield-title">Access Denied</div>
    <div class="shield-subtitle">Xpecto Shield \u2014 Intrusion Detection & Prevention</div>
    
    <div class="shield-category">${categoryName}</div>
    
    <div class="shield-message">
      Your request has been flagged and blocked for containing
      a potentially malicious payload. This incident has been logged.
    </div>

    <div class="neon-line"></div>

    <div class="shield-details">
      <div><span class="label">Incident:</span> ${incidentId}</div>
      <div><span class="label">Timestamp:</span> ${timestamp}</div>
      <div><span class="label">Category:</span> ${categoryName}</div>
      <div><span class="label">Action:</span> BLOCKED</div>
    </div>

    <div class="shield-footer">
      If you believe this is a false positive, contact the site administrator
      with the incident ID above.
    </div>
  </div>
</body>
</html>`;
}
function generateIncidentId() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let id = "XS-";
  for (let i = 0; i < 8; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

// src/middleware/shield-middleware.ts
var strikeCache = /* @__PURE__ */ new Map();
var blockCache = /* @__PURE__ */ new Set();
function cleanStrikeCache(blockDuration) {
  const now = Date.now();
  for (const [ip, data] of strikeCache.entries()) {
    if (now - data.lastStrike > blockDuration * 1e3) {
      strikeCache.delete(ip);
    }
  }
  for (const ip of blockCache) {
    const strike = strikeCache.get(ip);
    if (!strike || now - strike.lastStrike > blockDuration * 1e3) {
      blockCache.delete(ip);
    }
  }
}
async function createShieldMiddleware(config, onIncident) {
  const {
    categories,
    confidenceThreshold = 0.7,
    maxStrikes = 3,
    blockDuration = 86400,
    whitelistIPs = ["127.0.0.1", "::1"],
    protectedPaths = ["/*"],
    excludePaths = []
  } = config;
  let engine;
  if (config.payloadDir) {
    engine = await createDetectionEngine({
      payloadDir: config.payloadDir,
      categories,
      confidenceThreshold
    });
  } else {
    engine = await createDetectionEngine({
      categories,
      confidenceThreshold
    });
  }
  setInterval(() => cleanStrikeCache(blockDuration), 6e4);
  const stats = engine.getStats();
  console.log(
    `[xpecto-shield] Middleware initialized \u2014 ${stats.totalPatterns} patterns | threshold: ${confidenceThreshold} | max strikes: ${maxStrikes}`
  );
  return async function shieldMiddleware(request) {
    const url = new URL(request.url);
    const clientIP = extractClientIP(request);
    if (excludePaths.length > 0 && matchesPath(url.pathname, excludePaths)) {
      return;
    }
    if (!matchesPath(url.pathname, protectedPaths)) {
      return;
    }
    if (whitelistIPs.includes(clientIP)) {
      return;
    }
    if (blockCache.has(clientIP)) {
      return isJSONRequest(request) ? buildBlockResponseJSON("sqli") : buildBlockResponse("sqli");
    }
    try {
      const inputs = await extractRequestInputs(request);
      const result = engine.analyzeMultiple(inputs);
      if (!result.detected) {
        return;
      }
      const topThreat = result.threats[0];
      const existingStrike = strikeCache.get(clientIP) || { count: 0, lastStrike: 0 };
      existingStrike.count++;
      existingStrike.lastStrike = Date.now();
      strikeCache.set(clientIP, existingStrike);
      const shouldBlock = existingStrike.count >= maxStrikes;
      if (shouldBlock) {
        blockCache.add(clientIP);
      }
      const incident = {
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        sourceIP: clientIP,
        requestPath: url.pathname,
        requestMethod: request.method,
        attackCategory: topThreat.category,
        matchedPayload: topThreat.matchedPayload,
        confidence: topThreat.confidence,
        rawInput: topThreat.rawInput,
        action: "blocked",
        userAgent: request.headers.get("user-agent") || "unknown"
      };
      if (onIncident) {
        onIncident(incident).catch((err) => {
          console.error("[xpecto-shield] Incident callback error:", err);
        });
      }
      console.warn(
        `[xpecto-shield] \u26A0 BLOCKED | IP: ${clientIP} | Category: ${topThreat.category} | Path: ${url.pathname} | Confidence: ${topThreat.confidence.toFixed(2)} | Strikes: ${existingStrike.count}/${maxStrikes} | Scan: ${result.scanTimeMs.toFixed(1)}ms`
      );
      return isJSONRequest(request) ? buildBlockResponseJSON(topThreat.category, clientIP) : buildBlockResponse(topThreat.category, clientIP);
    } catch (error) {
      console.error(
        "[xpecto-shield] Analysis error \u2014 passing request through:",
        error instanceof Error ? error.message : error
      );
      return;
    }
  };
}
async function createShieldMiddlewareFromCompiled(compiledData, config, onIncident) {
  const {
    categories,
    confidenceThreshold = 0.7,
    maxStrikes = 3,
    blockDuration = 86400,
    whitelistIPs = ["127.0.0.1", "::1"],
    protectedPaths = ["/*"],
    excludePaths = []
  } = config;
  const engine = await createDetectionEngineFromCompiled(compiledData, {
    categories,
    confidenceThreshold
  });
  setInterval(() => cleanStrikeCache(blockDuration), 6e4);
  const stats = engine.getStats();
  console.log(
    `[xpecto-shield] Middleware initialized (compiled) \u2014 ${stats.totalPatterns} patterns | threshold: ${confidenceThreshold}`
  );
  return async function shieldMiddleware(request) {
    const url = new URL(request.url);
    const clientIP = extractClientIP(request);
    if (excludePaths.length > 0 && matchesPath(url.pathname, excludePaths)) return;
    if (!matchesPath(url.pathname, protectedPaths)) return;
    if (whitelistIPs.includes(clientIP)) return;
    if (blockCache.has(clientIP)) {
      return isJSONRequest(request) ? buildBlockResponseJSON("sqli") : buildBlockResponse("sqli");
    }
    try {
      const inputs = await extractRequestInputs(request);
      const result = engine.analyzeMultiple(inputs);
      if (!result.detected) return;
      const topThreat = result.threats[0];
      const existing = strikeCache.get(clientIP) || { count: 0, lastStrike: 0 };
      existing.count++;
      existing.lastStrike = Date.now();
      strikeCache.set(clientIP, existing);
      if (existing.count >= maxStrikes) blockCache.add(clientIP);
      const incident = {
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        sourceIP: clientIP,
        requestPath: url.pathname,
        requestMethod: request.method,
        attackCategory: topThreat.category,
        matchedPayload: topThreat.matchedPayload,
        confidence: topThreat.confidence,
        rawInput: topThreat.rawInput,
        action: "blocked",
        userAgent: request.headers.get("user-agent") || "unknown"
      };
      if (onIncident) {
        onIncident(incident).catch((err) => {
          console.error("[xpecto-shield] Incident callback error:", err);
        });
      }
      console.warn(
        `[xpecto-shield] \u26A0 BLOCKED | IP: ${clientIP} | ${topThreat.category} | ${url.pathname} | ${topThreat.confidence.toFixed(2)} | ${result.scanTimeMs.toFixed(1)}ms`
      );
      return isJSONRequest(request) ? buildBlockResponseJSON(topThreat.category, clientIP) : buildBlockResponse(topThreat.category, clientIP);
    } catch (error) {
      console.error("[xpecto-shield] Analysis error:", error instanceof Error ? error.message : error);
      return;
    }
  };
}

export { buildBlockResponse, buildBlockResponseJSON, createShieldMiddleware, createShieldMiddlewareFromCompiled, extractClientIP, extractRequestInputs, isJSONRequest, matchesPath };
//# sourceMappingURL=chunk-3RGOH5YK.js.map
//# sourceMappingURL=chunk-3RGOH5YK.js.map