import { THREAT_CATEGORIES } from './chunk-PTK2JL2Y.js';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

// src/core/aho-corasick.ts
var AhoCorasickAutomaton = class {
  root;
  patternCount = 0;
  isBuilt = false;
  constructor() {
    this.root = this.createNode(0);
  }
  /**
   * Add a pattern to the automaton.
   * Must be called BEFORE build().
   *
   * @param pattern - The pattern string to match against
   * @param category - The threat category this pattern belongs to
   */
  addPattern(pattern, category) {
    if (this.isBuilt) {
      throw new Error(
        "[xpecto-shield] Cannot add patterns after build(). Call reset() first."
      );
    }
    const normalizedPattern = pattern.toLowerCase();
    if (normalizedPattern.length === 0) return;
    let current = this.root;
    for (const char of normalizedPattern) {
      if (!current.children.has(char)) {
        current.children.set(char, this.createNode(current.depth + 1));
      }
      current = current.children.get(char);
    }
    current.output.push({ pattern: normalizedPattern, category });
    this.patternCount++;
  }
  /**
   * Build the failure links using BFS.
   * Must be called after all patterns are added and before search().
   */
  build() {
    const queue = [];
    for (const [, child] of this.root.children) {
      child.failure = this.root;
      queue.push(child);
    }
    while (queue.length > 0) {
      const current = queue.shift();
      for (const [char, child] of current.children) {
        queue.push(child);
        let failureNode = current.failure;
        while (failureNode !== null && !failureNode.children.has(char)) {
          failureNode = failureNode.failure;
        }
        child.failure = failureNode ? failureNode.children.get(char) : this.root;
        if (child.failure === child) {
          child.failure = this.root;
        }
        if (child.failure.output.length > 0) {
          child.output = [...child.output, ...child.failure.output];
        }
      }
    }
    this.isBuilt = true;
  }
  /**
   * Search the input text for all pattern matches in a single pass.
   *
   * @param input - The text to scan
   * @returns Array of all matches found, including overlapping matches
   */
  search(input) {
    if (!this.isBuilt) {
      throw new Error(
        "[xpecto-shield] Automaton not built. Call build() before search()."
      );
    }
    const normalizedInput = input.toLowerCase();
    const matches = [];
    let current = this.root;
    for (let i = 0; i < normalizedInput.length; i++) {
      const char = normalizedInput[i];
      while (current !== this.root && !current.children.has(char)) {
        current = current.failure;
      }
      if (current.children.has(char)) {
        current = current.children.get(char);
      }
      if (current.output.length > 0) {
        for (const { pattern, category } of current.output) {
          matches.push({
            pattern,
            category,
            position: i - pattern.length + 1,
            length: pattern.length
          });
        }
      }
    }
    return matches;
  }
  /**
   * Reset the automaton — clears all patterns and failure links.
   * Call this if you need to rebuild with different patterns.
   */
  reset() {
    this.root = this.createNode(0);
    this.patternCount = 0;
    this.isBuilt = false;
  }
  /**
   * Get the total number of patterns added to the automaton.
   */
  getPatternCount() {
    return this.patternCount;
  }
  /**
   * Check if the automaton has been built and is ready for searching.
   */
  getIsBuilt() {
    return this.isBuilt;
  }
  /** Create a new trie node */
  createNode(depth) {
    return {
      children: /* @__PURE__ */ new Map(),
      failure: null,
      output: [],
      depth
    };
  }
};

// src/core/input-decoder.ts
function decodeInput(raw) {
  if (!raw || raw.length === 0) return raw;
  let decoded = raw;
  decoded = decodeDoubleURLEncoding(decoded);
  decoded = decodeURLEncoding(decoded);
  decoded = decodeHTMLEntities(decoded);
  decoded = normalizeUnicode(decoded);
  decoded = removeNullBytes(decoded);
  decoded = detectAndDecodeBase64(decoded);
  return decoded;
}
function decodeURLEncoding(input) {
  try {
    return decodeURIComponent(input);
  } catch {
    return input.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }
}
function decodeDoubleURLEncoding(input) {
  return input.replace(/%25([0-9A-Fa-f]{2})/g, "%$1");
}
function decodeHTMLEntities(input) {
  const namedEntities = {
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&#39;": "'",
    "&nbsp;": " ",
    "&tab;": "	",
    "&newline;": "\n",
    "&sol;": "/",
    "&bsol;": "\\",
    "&lpar;": "(",
    "&rpar;": ")",
    "&lsqb;": "[",
    "&rsqb;": "]",
    "&lcub;": "{",
    "&rcub;": "}",
    "&semi;": ";",
    "&colon;": ":",
    "&comma;": ",",
    "&period;": ".",
    "&equals;": "=",
    "&plus;": "+",
    "&hyphen;": "-",
    "&ast;": "*",
    "&num;": "#",
    "&excl;": "!",
    "&quest;": "?",
    "&percnt;": "%",
    "&grave;": "`",
    "&tilde;": "~",
    "&Hat;": "^",
    "&vert;": "|",
    "&commat;": "@"
  };
  let result = input;
  for (const [entity, char] of Object.entries(namedEntities)) {
    result = result.replaceAll(entity, char);
  }
  result = result.replace(/&#[xX]([0-9A-Fa-f]+);?/g, (_, hex) => {
    const codePoint = parseInt(hex, 16);
    return codePoint > 0 && codePoint <= 1114111 ? String.fromCodePoint(codePoint) : "";
  });
  result = result.replace(/&#(\d+);?/g, (_, dec) => {
    const codePoint = parseInt(dec, 10);
    return codePoint > 0 && codePoint <= 1114111 ? String.fromCodePoint(codePoint) : "";
  });
  return result;
}
function normalizeUnicode(input) {
  let result = "";
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code >= 65281 && code <= 65374) {
      result += String.fromCharCode(code - 65248);
    } else if (code === 12288) {
      result += " ";
    } else {
      result += input[i];
    }
  }
  return result;
}
function removeNullBytes(input) {
  return input.replace(/%00/gi, "").replace(/\0/g, "").replace(/\\0/g, "").replace(/\\x00/gi, "");
}
function detectAndDecodeBase64(input) {
  const base64Regex = /[A-Za-z0-9+/]{16,}={0,2}/g;
  return input.replace(base64Regex, (match) => {
    try {
      const padded = match.length % 4 === 0 ? match : match + "=".repeat(4 - match.length % 4);
      const decoded = atob(padded);
      const isPrintable = /^[\x20-\x7E\t\n\r]+$/.test(decoded);
      if (isPrintable && decoded.length >= 4) {
        return decoded;
      }
      return match;
    } catch {
      return match;
    }
  });
}
var CATEGORY_FILES = {
  sqli: "sqli.txt",
  xss: "xss.txt",
  lfi: "lfi.txt",
  ssrf: "ssrf.txt",
  "path-traversal": "path-traversal.txt"
};
async function loadPayloadsFromDir(dir, categories = THREAT_CATEGORIES) {
  const patterns = /* @__PURE__ */ new Map();
  const categoryCounts = {
    sqli: 0,
    xss: 0,
    lfi: 0,
    ssrf: 0,
    "path-traversal": 0
  };
  for (const category of categories) {
    const filename = CATEGORY_FILES[category];
    const filepath = join(dir, filename);
    if (!existsSync(filepath)) {
      console.warn(
        `[xpecto-shield] Payload file not found: ${filepath} \u2014 skipping ${category}`
      );
      continue;
    }
    try {
      const content = readFileSync(filepath, "utf-8");
      const categoryPatterns = parsePayloadFile(content, category);
      for (const [pattern, cat] of categoryPatterns) {
        if (!patterns.has(pattern)) {
          patterns.set(pattern, cat);
          categoryCounts[cat]++;
        }
      }
    } catch (error) {
      console.error(
        `[xpecto-shield] Error loading ${filepath}:`,
        error instanceof Error ? error.message : error
      );
    }
  }
  return {
    patterns,
    totalCount: patterns.size,
    categoryCounts
  };
}
function parsePayloadFile(content, category) {
  const patterns = /* @__PURE__ */ new Map();
  const lines = content.split("\n");
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0) continue;
    if (line.startsWith("#")) continue;
    if (line.endsWith(":") && !line.includes(" ") === false && line.length < 100) {
      const hasLettersOnly = /^[A-Za-z0-9\s()_/-]+:$/.test(line);
      if (hasLettersOnly) continue;
    }
    const normalized = line.toLowerCase();
    if (normalized.length < 3) continue;
    patterns.set(normalized, category);
  }
  return patterns;
}
function loadPayloadsFromCompiled(compiledData) {
  const patterns = /* @__PURE__ */ new Map();
  const categoryCounts = {
    sqli: 0,
    xss: 0,
    lfi: 0,
    ssrf: 0,
    "path-traversal": 0
  };
  for (const [pattern, category] of Object.entries(compiledData)) {
    patterns.set(pattern, category);
    categoryCounts[category]++;
  }
  return {
    patterns,
    totalCount: patterns.size,
    categoryCounts
  };
}

// src/core/detection-engine.ts
var SQL_CONTEXT_KEYWORDS = [
  "select",
  "insert",
  "update",
  "delete",
  "drop",
  "union",
  "from",
  "where",
  "table",
  "database",
  "exec",
  "execute",
  "having",
  "group",
  "order",
  "alter",
  "create",
  "truncate",
  "information_schema",
  "sysobjects",
  "syscolumns"
];
var XSS_CONTEXT_KEYWORDS = [
  "script",
  "javascript",
  "onerror",
  "onload",
  "onclick",
  "onfocus",
  "onmouseover",
  "eval",
  "alert",
  "document",
  "window",
  "cookie",
  "innerhtml",
  "outerhtml",
  "srcdoc",
  "svg",
  "img",
  "iframe",
  "body",
  "input",
  "form"
];
var PATH_CONTEXT_KEYWORDS = [
  "..",
  "/",
  "\\",
  "etc",
  "passwd",
  "shadow",
  "proc",
  "self",
  "environ",
  "boot.ini",
  "win.ini",
  "web.config"
];
var CONTEXT_KEYWORDS = {
  sqli: SQL_CONTEXT_KEYWORDS,
  xss: XSS_CONTEXT_KEYWORDS,
  "path-traversal": PATH_CONTEXT_KEYWORDS,
  lfi: PATH_CONTEXT_KEYWORDS
};
async function createDetectionEngine(config = {}) {
  const {
    payloadDir,
    categories = THREAT_CATEGORIES,
    confidenceThreshold = 0.7,
    whitelist = []
  } = config;
  const buildStart = performance.now();
  let payloadDb;
  if (payloadDir) {
    payloadDb = await loadPayloadsFromDir(payloadDir, categories);
  } else {
    payloadDb = {
      patterns: /* @__PURE__ */ new Map(),
      totalCount: 0,
      categoryCounts: {
        sqli: 0,
        xss: 0,
        lfi: 0,
        ssrf: 0,
        "path-traversal": 0
      }
    };
  }
  const automaton = new AhoCorasickAutomaton();
  for (const [pattern, category] of payloadDb.patterns) {
    automaton.addPattern(pattern, category);
  }
  automaton.build();
  const buildTimeMs = performance.now() - buildStart;
  console.log(
    `[xpecto-shield] Detection engine built in ${buildTimeMs.toFixed(1)}ms \u2014 ${payloadDb.totalCount} patterns loaded across ${categories.length} categories`
  );
  const normalizedWhitelist = whitelist.map((w) => w.toLowerCase());
  const engine = {
    analyze(input, fieldName = "input") {
      const scanStart = performance.now();
      const decoded = decodeInput(input);
      const candidates = automaton.search(decoded);
      if (candidates.length === 0) {
        return {
          detected: false,
          threats: [],
          scanTimeMs: performance.now() - scanStart
        };
      }
      const validatedThreats = validateCandidates(
        candidates,
        decoded,
        input,
        fieldName,
        confidenceThreshold,
        normalizedWhitelist
      );
      return {
        detected: validatedThreats.length > 0,
        threats: validatedThreats,
        scanTimeMs: performance.now() - scanStart
      };
    },
    analyzeMultiple(inputs) {
      const scanStart = performance.now();
      const allThreats = [];
      for (const [fieldName, value] of Object.entries(inputs)) {
        if (!value || typeof value !== "string") continue;
        const result = engine.analyze(value, fieldName);
        allThreats.push(...result.threats);
      }
      return {
        detected: allThreats.length > 0,
        threats: allThreats,
        scanTimeMs: performance.now() - scanStart
      };
    },
    getStats() {
      return {
        totalPatterns: payloadDb.totalCount,
        categoryCounts: { ...payloadDb.categoryCounts },
        buildTimeMs,
        isReady: true
      };
    }
  };
  return engine;
}
function validateCandidates(candidates, decodedInput, rawInput, fieldName, threshold, whitelist) {
  const threats = [];
  const seenPatterns = /* @__PURE__ */ new Set();
  for (const safePattern of whitelist) {
    if (decodedInput.includes(safePattern)) {
      return [];
    }
  }
  for (const candidate of candidates) {
    if (seenPatterns.has(candidate.pattern)) continue;
    seenPatterns.add(candidate.pattern);
    const confidence = calculateConfidence(candidate, decodedInput);
    if (confidence >= threshold) {
      threats.push({
        category: candidate.category,
        matchedPayload: candidate.pattern,
        confidence,
        inputField: fieldName,
        decodedInput: decodedInput.substring(0, 500),
        // Cap for storage
        rawInput: rawInput.substring(0, 500)
      });
    }
  }
  threats.sort((a, b) => b.confidence - a.confidence);
  return threats;
}
function calculateConfidence(match, decodedInput) {
  let score = 0.6;
  const lengthRatio = match.length / decodedInput.length;
  const lengthBonus = Math.min(lengthRatio * 0.4, 0.2);
  score += lengthBonus;
  const contextKeywords = CONTEXT_KEYWORDS[match.category];
  if (contextKeywords) {
    const inputLower = decodedInput.toLowerCase();
    let contextHits = 0;
    for (const keyword of contextKeywords) {
      if (inputLower.includes(keyword) && keyword !== match.pattern) {
        contextHits++;
      }
    }
    const contextBonus = Math.min(contextHits * 0.05, 0.2);
    score += contextBonus;
  }
  return Math.min(score, 1);
}
async function createDetectionEngineFromCompiled(compiledData, config = {}) {
  const payloadDb = loadPayloadsFromCompiled(compiledData);
  const {
    confidenceThreshold = 0.7,
    whitelist = []
  } = config;
  const buildStart = performance.now();
  const automaton = new AhoCorasickAutomaton();
  for (const [pattern, category] of payloadDb.patterns) {
    automaton.addPattern(pattern, category);
  }
  automaton.build();
  const buildTimeMs = performance.now() - buildStart;
  const normalizedWhitelist = whitelist.map((w) => w.toLowerCase());
  const engine = {
    analyze(input, fieldName = "input") {
      const scanStart = performance.now();
      const decoded = decodeInput(input);
      const candidates = automaton.search(decoded);
      if (candidates.length === 0) {
        return { detected: false, threats: [], scanTimeMs: performance.now() - scanStart };
      }
      const validatedThreats = validateCandidates(
        candidates,
        decoded,
        input,
        fieldName,
        confidenceThreshold,
        normalizedWhitelist
      );
      return {
        detected: validatedThreats.length > 0,
        threats: validatedThreats,
        scanTimeMs: performance.now() - scanStart
      };
    },
    analyzeMultiple(inputs) {
      const scanStart = performance.now();
      const allThreats = [];
      for (const [fieldName, value] of Object.entries(inputs)) {
        if (!value || typeof value !== "string") continue;
        const result = engine.analyze(value, fieldName);
        allThreats.push(...result.threats);
      }
      return {
        detected: allThreats.length > 0,
        threats: allThreats,
        scanTimeMs: performance.now() - scanStart
      };
    },
    getStats() {
      return {
        totalPatterns: payloadDb.totalCount,
        categoryCounts: { ...payloadDb.categoryCounts },
        buildTimeMs,
        isReady: true
      };
    }
  };
  return engine;
}

export { AhoCorasickAutomaton, createDetectionEngine, createDetectionEngineFromCompiled, decodeInput, loadPayloadsFromCompiled, loadPayloadsFromDir, parsePayloadFile };
//# sourceMappingURL=chunk-5P3M5JP2.js.map
//# sourceMappingURL=chunk-5P3M5JP2.js.map