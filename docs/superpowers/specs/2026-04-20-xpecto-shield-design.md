# Xpecto Shield — Design Specification

> **Thesis**: "Sistem Deteksi dan Pencegahan Eksploitasi Web serta Mitigasi dengan IP Blocking dan Pelaporan Analitik Berbasis AI"
>
> **Author**: Ragel Listiyono (3123510644)
>
> **Date**: 2026-04-20

---

## 1. System Overview

Xpecto Shield is a Web-based Intrusion Detection and Prevention System (IDPS) that:

1. **Detects** malicious payloads in real-time using a hybrid Aho-Corasick + precision validation engine
2. **Prevents** exploitation by blocking requests and blacklisting attacker IPs
3. **Mitigates** through AI-driven analytics that analyze attack patterns, assess risk, and generate recommendations

The system is delivered as a **single npm package** (`xpecto-shield`) with modular TypeScript exports, designed to integrate into any Next.js application with minimal configuration (~20 lines of code in the host app).

---

## 2. Architecture Decisions

### 2.1 Packaging: Single Package with Modular Exports

**Decision**: Single npm package with TypeScript `exports` field for clean module separation.

**Rationale**: A monorepo with multiple packages adds unnecessary complexity for a thesis project. TypeScript path exports give the same clean API boundaries while keeping everything in one publishable unit.

```
import { createDetectionEngine } from 'xpecto-shield/core'
import { createShieldMiddleware } from 'xpecto-shield/middleware'
import { createShieldAPI } from 'xpecto-shield/api'
import { ShieldDashboard } from 'xpecto-shield/dashboard'
```

### 2.2 Detection Algorithm: Aho-Corasick Hybrid

**Decision**: Replace "Anchored Exact Line Matching" (from original SPPA) with a two-stage hybrid engine.

**Rationale**: Anchored Exact Line Matching has O(n × k) complexity per request, which is unacceptable at 5,000+ patterns. The hybrid approach achieves O(n + m + z) complexity — pattern-count independent — while maintaining high precision.

- **Stage 1 — Aho-Corasick**: Single-pass substring matching across all 5,000+ patterns. Built once at startup (~50-100ms), reused for all requests with <1ms scan time. Immune to ReDoS attacks.
- **Stage 2 — Precision Validation**: Confirms Stage 1 candidates with context-aware checking, confidence scoring (0.0-1.0), and whitelist verification. Reduces false positives.

### 2.3 Runtime: Next.js Middleware with Node.js Runtime

**Decision**: Use `runtime: 'nodejs'` in Next.js middleware configuration (stable since Next.js 15.5).

**Rationale**: The Edge Runtime restricts `fs`, native modules, and many npm packages. The Node.js runtime provides full access to the Aho-Corasick engine, payload file loading, and Appwrite SDK — all within the middleware layer.

### 2.4 AI Analytics: Provider-Agnostic (OpenAI-Compatible)

**Decision**: Accept any OpenAI-compatible API endpoint (base URL + API key + model name).

**Rationale**: Allows the user to switch between Gemini, OpenRouter, Groq, or any other provider without code changes. Structured JSON mode ensures consistent output format regardless of provider.

### 2.5 Admin Dashboard: Protected Route Within Host App

**Decision**: Dashboard lives at `/admin/shield/` within the host website, not as a separate deployment.

**Rationale**: Xpecto Shield protects a single website — its dashboard belongs within that site. Eliminates extra hosting costs, CORS complexity, and deployment pipelines. Similar pattern to WordPress security plugins (Wordfence, Sucuri).

### 2.6 Data Persistence: Appwrite BaaS

**Decision**: Use Appwrite collections for all persistent data (incidents, blocked IPs, AI reports, settings).

**Rationale**: The host website already uses Appwrite. No need for a separate database. Appwrite provides built-in authentication, audit logs, and rate limiting.

---

## 3. File Structure

```
xpecto-shield/                     (repo: ragel-pa)
├── src/
│   ├── core/                       # Detection Engine
│   │   ├── index.ts                # Public API: createDetectionEngine, types
│   │   ├── aho-corasick.ts         # Aho-Corasick automaton (build, search)
│   │   ├── detection-engine.ts     # Hybrid orchestrator (Stage 1 + Stage 2)
│   │   ├── payload-loader.ts       # Loads .txt files, categorizes patterns
│   │   ├── input-decoder.ts        # Multi-layer decoding (URL, HTML, Unicode, Base64)
│   │   └── types.ts                # DetectionResult, ThreatCategory, EngineConfig
│   │
│   ├── middleware/                  # Next.js Middleware Integration
│   │   ├── index.ts                # Public API: createShieldMiddleware
│   │   ├── shield-middleware.ts    # Middleware factory (config → NextMiddleware)
│   │   ├── request-analyzer.ts    # Extracts input from 5 attack surfaces
│   │   └── response-builder.ts    # Builds 403/200 responses with security headers
│   │
│   ├── api/                        # API Route Handlers
│   │   ├── index.ts                # Public API: createShieldAPI
│   │   ├── incident-logger.ts     # Writes incidents to Appwrite
│   │   ├── ip-manager.ts          # IP block/unblock/check/expire logic
│   │   ├── ai-analytics.ts        # LLM pipeline: preprocess → prompt → call → parse
│   │   ├── dashboard-api.ts       # REST handlers for dashboard data
│   │   └── appwrite-client.ts     # Appwrite SDK wrapper (collections, queries)
│   │
│   ├── dashboard/                  # Admin Dashboard (React Components)
│   │   ├── index.ts                # Public API: ShieldDashboard component
│   │   ├── ShieldDashboard.tsx    # Root component with internal routing
│   │   ├── pages/
│   │   │   ├── OverviewPage.tsx    # Stats, timeline chart, recent attacks
│   │   │   ├── IncidentsPage.tsx   # Attack log table with filters
│   │   │   ├── BlockedIPsPage.tsx  # IP management table
│   │   │   ├── AnalyticsPage.tsx   # AI reports (trigger + view)
│   │   │   └── SettingsPage.tsx    # Shield configuration panels
│   │   ├── components/
│   │   │   ├── Sidebar.tsx         # Terminal-style navigation
│   │   │   ├── StatCard.tsx        # Holographic metric card
│   │   │   ├── DataTable.tsx       # Terminal variant table with sorting/filtering
│   │   │   ├── Chart.tsx           # Neon-styled charts (timeline, distribution)
│   │   │   ├── FilterBar.tsx       # Terminal inputs with > prefix
│   │   │   ├── Badge.tsx           # Severity/category badges
│   │   │   ├── Modal.tsx           # Slide-out detail panel
│   │   │   └── ThreatGauge.tsx     # Neon meter for risk scores
│   │   └── styles/
│   │       └── shield.css          # Cyberpunk design tokens & component styles
│   │
│   └── index.ts                    # Root barrel: re-exports all public APIs
│
├── payloads/                       # Attack Signature Database
│   ├── sqli.txt                    # SQL Injection (~585 payloads)
│   ├── xss.txt                     # Cross-Site Scripting (~2,669 payloads)
│   ├── path-traversal.txt          # Directory Traversal (~847 payloads)
│   ├── ssrf.txt                    # Server-Side Request Forgery (~122 payloads)
│   └── lfi.txt                     # Local File Inclusion (~1,000 payloads)
│
├── docs/
│   ├── cyberpunk.md                # Design system reference
│   ├── allsqli.txt                 # Original payload reference
│   └── superpowers/specs/          # This spec and future specs
│
├── tests/                          # Test suite
│   ├── core/
│   │   ├── aho-corasick.test.ts    # Unit tests for automaton
│   │   ├── detection-engine.test.ts # Integration tests for hybrid engine
│   │   └── input-decoder.test.ts   # Decoding edge cases
│   ├── middleware/
│   │   └── shield-middleware.test.ts
│   ├── api/
│   │   ├── ip-manager.test.ts
│   │   └── ai-analytics.test.ts
│   └── e2e/
│       └── detection-flow.test.ts  # End-to-end: request → detect → block → log
│
├── package.json                    # exports field, dependencies, scripts
├── tsconfig.json                   # TypeScript configuration
├── vitest.config.ts                # Test runner configuration
└── README.md                       # Usage documentation
```

---

## 4. Core Detection Engine

### 4.1 Aho-Corasick Automaton (`src/core/aho-corasick.ts`)

Implements a Deterministic Finite Automaton (DFA) for multi-pattern string matching.

**API**:
```typescript
class AhoCorasickAutomaton {
  constructor()
  
  // Add a pattern with its category
  addPattern(pattern: string, category: ThreatCategory): void
  
  // Build the failure links (call once after all patterns added)
  build(): void
  
  // Search input text — returns all matches in a single pass
  search(input: string): AhoCorasickMatch[]
}

interface AhoCorasickMatch {
  pattern: string          // The matched pattern text
  category: ThreatCategory // 'sqli' | 'xss' | 'lfi' | 'ssrf' | 'path-traversal'
  position: number         // Start index in input
  length: number           // Length of matched pattern
}
```

**Implementation details**:
- Trie node structure with `goto` transitions, `failure` links, and `output` list
- Case-insensitive matching (all patterns and input lowercased before insertion/search)
- Built once at cold-start, reused via module-level singleton
- Pure TypeScript — no native dependencies, works in Node.js runtime

### 4.2 Hybrid Detection Engine (`src/core/detection-engine.ts`)

**API**:
```typescript
interface DetectionEngineConfig {
  payloadDir: string                        // Path to payloads/ directory
  categories: ThreatCategory[]              // Which categories to load
  caseSensitive?: boolean                   // Default: false
  confidenceThreshold?: number              // Default: 0.7
  whitelist?: string[]                      // Patterns to never flag
}

async function createDetectionEngine(config: DetectionEngineConfig): Promise<DetectionEngine>

interface DetectionEngine {
  analyze(input: string): DetectionResult
  analyzeMultiple(inputs: Record<string, string>): DetectionResult
  getStats(): EngineStats
}

interface DetectionResult {
  detected: boolean
  threats: ThreatMatch[]
  scanTimeMs: number
}

interface ThreatMatch {
  category: ThreatCategory
  matchedPayload: string
  confidence: number       // 0.0 - 1.0
  inputField: string       // Which input field contained the threat
  decodedInput: string     // The decoded input value
  rawInput: string         // The original raw input
}
```

**Hybrid flow**:
1. **Normalize input**: Multi-layer decoding (URL → HTML entity → Unicode → Base64 detection)
2. **Stage 1 — Aho-Corasick scan**: Single-pass against all loaded patterns. Returns candidate matches.
3. **Stage 2 — Precision validation**: For each candidate:
   - **Context scoring**: Does the match appear in a SQL/HTML/path context?
   - **Length ratio**: Ratio of pattern length to input length (very short patterns in long inputs get lower confidence)
   - **Whitelist check**: Skip if input matches a known safe pattern
   - **Confidence calculation**: Weighted combination → if above threshold, confirmed as threat

### 4.3 Input Decoder (`src/core/input-decoder.ts`)

Multi-layer decoding pipeline to defeat evasion techniques:

```
Raw Input
  → URL decode (%27 → ', %3C → <)
  → Double URL decode (%2527 → %27 → ')
  → HTML entity decode (&lt; → <, &#x27; → ')
  → Unicode normalize (fullwidth characters → ASCII)
  → Base64 detection (detect and decode base64 segments)
  → Null byte removal (%00 → removed)
  → Result: normalized string for scanning
```

### 4.4 Payload Loader (`src/core/payload-loader.ts`)

Reads `.txt` files from the `payloads/` directory. Each file:
- Named by category: `sqli.txt`, `xss.txt`, etc.
- One payload per line
- Lines starting with `#` or empty lines are skipped
- Category headers within files (e.g., `MySQL Blind (Time Based):`) are stripped

```typescript
async function loadPayloads(dir: string, categories: ThreatCategory[]): Promise<PayloadDatabase>

interface PayloadDatabase {
  patterns: Map<string, ThreatCategory>   // pattern → category
  totalCount: number
  categoryCounts: Record<ThreatCategory, number>
}
```

**Bundling strategy**: At package build time (`tsup`), the `.txt` payload files are pre-compiled into a static TypeScript module (`compiled-payloads.ts`) containing the patterns as a JSON-serializable object. This avoids `fs.readFileSync` at runtime, ensuring compatibility with serverless environments (Netlify, Vercel). The `payloadDir` config option is for development/testing; production uses the compiled module automatically.

---

## 5. Middleware Integration

### 5.1 Shield Middleware (`src/middleware/shield-middleware.ts`)

**API**:
```typescript
interface ShieldMiddlewareConfig {
  // Detection
  payloadDir: string
  categories?: ThreatCategory[]           // Default: all 5
  confidenceThreshold?: number            // Default: 0.7
  
  // IP Blocking
  maxStrikes?: number                     // Default: 3
  blockDuration?: number                  // Default: 86400 (24h in seconds)
  whitelistIPs?: string[]                 // Default: ['127.0.0.1']
  
  // Appwrite
  appwrite: {
    endpoint: string
    projectId: string
    apiKey: string
    databaseId?: string                   // Default: 'xpecto_shield'
  }
  
  // AI (optional)
  ai?: {
    baseUrl: string
    apiKey: string
    model: string
  }
  
  // Routing
  protectedPaths?: string[]              // Default: ['/*']
  excludePaths?: string[]                // Default: ['/_next/*', '/favicon.ico']
}

function createShieldMiddleware(config: ShieldMiddlewareConfig): {
  middleware: NextMiddleware
  engine: DetectionEngine
}
```

### 5.2 Request Analyzer (`src/middleware/request-analyzer.ts`)

Extracts input from 5 attack surfaces:

| Surface | Extraction Method |
|---|---|
| URL Path | `request.nextUrl.pathname` |
| Query Parameters | `request.nextUrl.searchParams` — each key-value pair |
| Request Body | `await request.json()` or `await request.text()` — parsed recursively |
| Headers | Selected headers: `cookie`, `referer`, `user-agent`, `x-forwarded-for` |
| Cookies | `request.cookies.getAll()` — each cookie value |

Returns a flat `Record<string, string>` mapping field names to values for the detection engine.

### 5.3 Middleware Flow

```
1. Check if request path is excluded → SKIP, call next()
2. Check if source IP is blocked in Appwrite → BLOCK immediately (403)
3. Extract all input fields from request
4. Run detection engine on all fields
5. If threat detected:
   a. Log incident to Appwrite (async, non-blocking)
   b. Increment IP strike counter
   c. If strikes >= maxStrikes → block IP in Appwrite
   d. Return 403 with security headers
6. If no threat → call next()
```

---

## 6. API Layer

### 6.1 Shield API (`src/api/dashboard-api.ts`)

Single catch-all handler factory for Next.js App Router:

```typescript
function createShieldAPI(config: ShieldAPIConfig): {
  handler: (req: NextRequest) => Promise<NextResponse>
}
```

**Endpoints**:

| Route | Method | Purpose | Auth Required |
|---|---|---|---|
| `GET /incidents` | GET | Paginated attack logs | Yes |
| `GET /incidents/stats` | GET | Dashboard KPI metrics | Yes |
| `POST /blocked-ips` | POST | Manual block/unblock | Yes |
| `GET /blocked-ips` | GET | List blocked IPs | Yes |
| `POST /analytics` | POST | Trigger AI analysis | Yes |
| `GET /analytics/:id` | GET | Fetch AI report | Yes |
| `GET /settings` | GET | Read shield config | Yes |
| `PUT /settings` | PUT | Update shield config | Yes |

All endpoints require `authCheck` to return `true` — the consumer provides their own auth verification function.

### 6.2 Incident Logger (`src/api/incident-logger.ts`)

```typescript
interface IncidentLog {
  timestamp: string           // ISO 8601
  sourceIP: string
  requestPath: string
  requestMethod: string
  attackCategory: ThreatCategory
  matchedPayload: string
  confidence: number
  rawInput: string
  action: 'blocked' | 'logged'
  userAgent: string
  geoLocation?: string
}

async function logIncident(appwrite: AppwriteClient, incident: IncidentLog): Promise<void>
```

Uses fire-and-forget pattern (non-blocking) in middleware to avoid adding latency.

### 6.3 IP Manager (`src/api/ip-manager.ts`)

```typescript
async function isIPBlocked(appwrite: AppwriteClient, ip: string): Promise<boolean>
async function incrementStrike(appwrite: AppwriteClient, ip: string, category: ThreatCategory): Promise<number>
async function blockIP(appwrite: AppwriteClient, ip: string, reason: string, duration?: number): Promise<void>
async function unblockIP(appwrite: AppwriteClient, ip: string): Promise<void>
async function getBlockedIPs(appwrite: AppwriteClient, options: PaginationOptions): Promise<PaginatedResult<BlockedIP>>
```

**IP blocking logic**:
- Each detected attack increments the strike counter for that IP
- When `strikeCount >= maxStrikes`, IP is automatically blocked
- Blocked IPs have an `expiresAt` timestamp (null = permanent)
- Expired blocks are cleaned up lazily (checked on next request from that IP)

### 6.4 AI Analytics (`src/api/ai-analytics.ts`)

```typescript
interface AnalyticsRequest {
  dateRangeStart: string
  dateRangeEnd: string
  categories?: ThreatCategory[]      // Filter by attack type
}

interface AnalyticsReport {
  executiveSummary: string
  patternAnalysis: PatternInsight[]
  trendAnalysis: TrendInsight[]
  riskAssessment: RiskScore
  recommendations: Recommendation[]
  threatLevel: 'low' | 'medium' | 'high' | 'critical'
}

async function triggerAnalysis(
  appwrite: AppwriteClient,
  aiConfig: AIConfig,
  request: AnalyticsRequest
): Promise<string>  // Returns report ID
```

**Pipeline**:
1. Query incidents from Appwrite within date range
2. Preprocess: aggregate by category, IP, time intervals; compute statistics
3. Build contextual prompt with system role ("cybersecurity analyst") and structured data
4. Call OpenAI-compatible endpoint with JSON mode enabled
5. Parse and validate response against expected schema
6. Store report in `ai_reports` collection
7. Return report ID for dashboard to fetch

**Prompt structure**:
```
System: You are a senior cybersecurity analyst specializing in web application security.
        Analyze the following attack data and provide a structured security report.

User: {
  "period": "2026-04-01 to 2026-04-20",
  "totalIncidents": 1247,
  "categoryBreakdown": { "sqli": 524, "xss": 387, ... },
  "topAttackerIPs": [...],
  "timeDistribution": [...],
  "samplePayloads": [...],
  "systemContext": "Next.js web application with Appwrite backend"
}

Respond in JSON format matching this schema: { ... }
```

---

## 7. Appwrite Data Schema

### Database: `xpecto_shield`

#### Collection: `incidents`

| Attribute | Type | Index | Description |
|---|---|---|---|
| timestamp | datetime | Yes | When the attack was detected |
| sourceIP | string(45) | Yes | Attacker's IP address |
| requestPath | string(2048) | No | Request URL path |
| requestMethod | string(10) | No | HTTP method |
| attackCategory | string(20) | Yes | sqli, xss, lfi, ssrf, path-traversal |
| matchedPayload | string(4096) | No | The exact payload that matched |
| confidence | float | No | Detection confidence (0.0-1.0) |
| rawInput | string(4096) | No | Original input before decoding |
| action | string(10) | Yes | blocked, logged |
| userAgent | string(512) | No | User-Agent header |
| geoLocation | string(100) | No | Country/region if available |

#### Collection: `blocked_ips`

| Attribute | Type | Index | Description |
|---|---|---|---|
| ipAddress | string(45) | Yes (unique) | The blocked IP |
| reason | string(20) | No | auto, manual |
| strikeCount | integer | No | Number of attacks detected |
| blockedAt | datetime | No | When the block started |
| expiresAt | datetime | Yes | When block expires (null = permanent) |
| lastAttackCategory | string(20) | No | Most recent attack type |
| isActive | boolean | Yes | Current block status |

#### Collection: `ai_reports`

| Attribute | Type | Index | Description |
|---|---|---|---|
| createdAt | datetime | Yes | When the report was generated |
| dateRangeStart | datetime | No | Analysis period start |
| dateRangeEnd | datetime | No | Analysis period end |
| incidentCount | integer | No | Number of incidents analyzed |
| executiveSummary | string(10000) | No | AI-generated summary |
| patternAnalysis | string(10000) | No | JSON string of pattern insights |
| trendAnalysis | string(10000) | No | JSON string of trend data |
| riskAssessment | string(10000) | No | JSON string of risk scores |
| recommendations | string(10000) | No | JSON string of recommendations |
| threatLevel | string(10) | Yes | low, medium, high, critical |
| modelUsed | string(100) | No | AI model identifier |

#### Collection: `shield_settings`

| Attribute | Type | Index | Description |
|---|---|---|---|
| key | string(100) | Yes (unique) | Setting name |
| value | string(10000) | No | JSON-stringified value |
| updatedAt | datetime | No | Last modification time |

---

## 8. Admin Dashboard

### 8.1 Design System

The dashboard uses the **Cyberpunk/Glitch Design System** defined in `docs/cyberpunk.md`.

**Key design tokens**:
- Background: `#0a0a0f` (deep void black)
- Primary accent: `#00ff88` (electric green)
- Secondary accent: `#ff00ff` (hot magenta)
- Tertiary accent: `#00d4ff` (cyan)
- Destructive: `#ff3366` (red-pink)
- Cards: `#12121a` (purple-black)
- Typography: Orbitron (headings), JetBrains Mono (body/code)

**Visual signatures**:
- Chamfered corners (clip-path, no border-radius)
- Neon glow borders (multi-layer box-shadow)
- Scanline overlay on the entire dashboard
- Terminal aesthetic (monospace, `>` prefix on inputs)
- Chromatic aberration on headline text
- Circuit grid background pattern

**Severity color coding**:
- LOW: `#00d4ff` (cyan)
- MEDIUM: `#00ff88` (green)
- HIGH: `#ff00ff` (magenta)
- CRITICAL: `#ff3366` (red-pink)

### 8.2 Component Architecture

The dashboard is exported as a single self-contained React component:

```typescript
interface ShieldDashboardProps {
  apiBase: string              // Base URL for API routes (e.g., '/api/xpecto-shield')
  theme?: 'cyberpunk'          // Currently only cyberpunk theme
  locale?: 'en' | 'id'        // Language support
}

function ShieldDashboard(props: ShieldDashboardProps): JSX.Element
```

**Internal routing**: Uses URL hash (`#overview`, `#incidents`, `#blocked-ips`, `#analytics`, `#settings`) to avoid conflicting with the host app's Next.js router.

### 8.3 Pages

#### Overview (`#overview`)
- 4 stat cards (holographic variant): Total Attacks, IPs Blocked, Active Threats, System Health
- Attack timeline chart (24h, neon green line on void background)
- Threat distribution pie/donut chart (color per category)
- Recent attacks table (terminal variant, last 10 entries)

#### Incidents (`#incidents`)
- KPI strip: Detection Rate, False Positive Rate, Avg Response Time
- Filter bar: Date range, category, severity, IP search — terminal inputs
- Paginated data table with sortable columns
- Click-to-expand detail panel (full request, decoded input, payload match)
- Export to CSV functionality

#### Blocked IPs (`#blocked-ips`)
- IP table: Address, reason, strike count, blocked time, expires, status
- Status badges: ACTIVE (pulsing green), EXPIRED (dim gray), PERMANENT (magenta)
- Action buttons: Unblock, Extend, Make Permanent
- Manual block form with glitch CTA button

#### Analytics (`#analytics`)
- Date range picker (terminal-style inputs)
- "ANALYZE WITH AI" button (glitch variant)
- Loading state: scanline animation with blinking cursor
- Report display: 4 holographic panels — Summary, Patterns, Risk, Recommendations
- Report history list (previous analyses)

#### Settings (`#settings`)
- Detection Settings: categories toggle, confidence threshold slider
- IP Blocking: max strikes, block duration, whitelist IPs
- AI Configuration: API base URL, API key (masked), model name
- Notifications: toggles for browser/telegram alerts
- Save button (glitch variant)

---

## 9. Integration Guide (Host Website)

The host website (Next.js on Netlify with Appwrite) needs **3 files changed**:

### 9.1 Install Package
```bash
npm install github:ragel/xpecto-shield
# or after npm publish:
npm install xpecto-shield
```

### 9.2 Middleware (`middleware.ts`)
```typescript
import { createShieldMiddleware } from 'xpecto-shield/middleware'

const shield = createShieldMiddleware({
  payloadDir: './node_modules/xpecto-shield/payloads',
  appwrite: {
    endpoint: process.env.APPWRITE_ENDPOINT!,
    projectId: process.env.APPWRITE_PROJECT_ID!,
    apiKey: process.env.APPWRITE_API_KEY!,
  },
  ai: {
    baseUrl: process.env.AI_BASE_URL!,
    apiKey: process.env.AI_API_KEY!,
    model: process.env.AI_MODEL!,
  },
  excludePaths: ['/admin/shield/*', '/_next/*', '/favicon.ico'],
})

export default shield.middleware
export const config = {
  runtime: 'nodejs',
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
```

### 9.3 API Route (`app/api/xpecto-shield/[...route]/route.ts`)
```typescript
import { createShieldAPI } from 'xpecto-shield/api'

const api = createShieldAPI({
  appwrite: {
    endpoint: process.env.APPWRITE_ENDPOINT!,
    projectId: process.env.APPWRITE_PROJECT_ID!,
    apiKey: process.env.APPWRITE_API_KEY!,
  },
  ai: {
    baseUrl: process.env.AI_BASE_URL!,
    apiKey: process.env.AI_API_KEY!,
    model: process.env.AI_MODEL!,
  },
  authCheck: async (req) => {
    // Custom auth verification
    return true // Replace with actual auth logic
  },
})

export const GET = api.handler
export const POST = api.handler
export const PUT = api.handler
```

### 9.4 Dashboard Page (`app/admin/shield/page.tsx`)
```typescript
import { ShieldDashboard } from 'xpecto-shield/dashboard'

export default function ShieldPage() {
  return <ShieldDashboard apiBase="/api/xpecto-shield" locale="id" />
}
```

### 9.5 Environment Variables (`.env.local`)
```env
APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1
APPWRITE_PROJECT_ID=your-project-id
APPWRITE_API_KEY=your-api-key
AI_BASE_URL=https://openrouter.ai/api/v1
AI_API_KEY=your-ai-api-key
AI_MODEL=google/gemini-2.0-flash
```

---

## 10. Technology Stack

| Component | Technology | Version |
|---|---|---|
| Language | TypeScript | 5.x |
| Runtime | Node.js | 20+ |
| Framework target | Next.js | 15.5+ |
| Backend service | Appwrite | Cloud |
| Hosting target | Netlify | - |
| Testing | Vitest | 3.x |
| AI SDK | OpenAI-compatible REST API | - |
| Build | tsup or unbuild | - |
| Charts | Lightweight (CSS/SVG-based) | Custom |
| Design | Cyberpunk/Glitch system | Custom |

### Dependencies (minimal)
```json
{
  "dependencies": {
    "node-appwrite": "^14.0.0"
  },
  "peerDependencies": {
    "next": ">=15.5.0",
    "react": ">=18.0.0",
    "react-dom": ">=18.0.0"
  },
  "devDependencies": {
    "typescript": "^5.0.0",
    "vitest": "^3.0.0",
    "tsup": "^8.0.0"
  }
}
```

---

## 11. Error Handling Strategy

- **Detection engine errors**: Log and allow request (fail-open for availability; fail-closed is configurable)
- **Appwrite connection errors**: Cache blocked IP list locally; log incidents to in-memory buffer and flush when connection recovers
- **AI API errors**: Return error status to dashboard; don't block any requests due to AI failure
- **Malformed payloads in `.txt` files**: Skip and log warning during build; don't crash the engine

---

## 12. Security Considerations

- **API key management**: All keys via environment variables, never hardcoded
- **Dashboard auth**: Delegated to host app via `authCheck` callback — not managed by Xpecto Shield itself
- **Rate limiting**: Appwrite provides built-in rate limiting; dashboard API can add application-level limits
- **Payload file integrity**: Payloads are read-only at build time; modifying them requires redeployment
- **ReDoS protection**: Aho-Corasick is immune to ReDoS by design (no backtracking)
- **Data sanitization**: Attack logs store raw payloads but dashboard renders them as escaped text (no XSS in the dashboard itself)

---

## 13. Testing Strategy

### Unit Tests
- Aho-Corasick automaton: pattern insertion, build, search, edge cases (empty input, overlapping patterns, unicode)
- Input decoder: URL encoding, double encoding, HTML entities, base64, null bytes
- Detection engine: known payloads → detected, safe inputs → not detected, confidence scoring
- IP manager: strike counting, expiry logic, whitelist

### Integration Tests
- Middleware: mock Next.js request → detect → block → log
- API handlers: CRUD operations on Appwrite collections
- AI pipeline: mock LLM response → parse → validate → store

### End-to-End Tests
- Full flow: HTTP request with SQLi payload → middleware detects → blocks → logs to Appwrite → visible in dashboard API
