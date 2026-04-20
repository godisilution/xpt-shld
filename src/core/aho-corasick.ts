// ═══════════════════════════════════════════════════════════════
// Xpecto Shield — Aho-Corasick Multi-Pattern String Matching
// ═══════════════════════════════════════════════════════════════
//
// Implementation of the Aho-Corasick algorithm for simultaneous
// multi-pattern string matching in O(n + m + z) time complexity.
//
// - n = length of input text
// - m = total length of all patterns (build time only)
// - z = number of matches found
//
// The automaton is built once at startup and reused for all
// subsequent scan requests with sub-millisecond performance.
// ═══════════════════════════════════════════════════════════════

import type { ThreatCategory, AhoCorasickMatch } from './types'

/** Internal trie node structure */
interface TrieNode {
  /** Character transitions (goto function) */
  children: Map<string, TrieNode>
  /** Failure link — longest proper suffix that is also a prefix of some pattern */
  failure: TrieNode | null
  /** Output patterns at this node (including via suffix links) */
  output: Array<{ pattern: string; category: ThreatCategory }>
  /** Depth in the trie (equals prefix length) */
  depth: number
}

/**
 * Aho-Corasick Automaton for high-performance multi-pattern string matching.
 *
 * Usage:
 * ```typescript
 * const ac = new AhoCorasickAutomaton()
 * ac.addPattern("SELECT", "sqli")
 * ac.addPattern("<script>", "xss")
 * ac.build()
 * const matches = ac.search("try SELECT * FROM <script>alert(1)</script>")
 * ```
 */
export class AhoCorasickAutomaton {
  private root: TrieNode
  private patternCount: number = 0
  private isBuilt: boolean = false

  constructor() {
    this.root = this.createNode(0)
  }

  /**
   * Add a pattern to the automaton.
   * Must be called BEFORE build().
   *
   * @param pattern - The pattern string to match against
   * @param category - The threat category this pattern belongs to
   */
  addPattern(pattern: string, category: ThreatCategory): void {
    if (this.isBuilt) {
      throw new Error(
        '[xpecto-shield] Cannot add patterns after build(). Call reset() first.'
      )
    }

    const normalizedPattern = pattern.toLowerCase()

    if (normalizedPattern.length === 0) return

    let current = this.root

    for (const char of normalizedPattern) {
      if (!current.children.has(char)) {
        current.children.set(char, this.createNode(current.depth + 1))
      }
      current = current.children.get(char)!
    }

    // Add to output list at the terminal node
    current.output.push({ pattern: normalizedPattern, category })
    this.patternCount++
  }

  /**
   * Build the failure links using BFS.
   * Must be called after all patterns are added and before search().
   */
  build(): void {
    const queue: TrieNode[] = []

    // Initialize failure links for depth-1 nodes (direct children of root)
    for (const [, child] of this.root.children) {
      child.failure = this.root
      queue.push(child)
    }

    // BFS to construct failure links for deeper nodes
    while (queue.length > 0) {
      const current = queue.shift()!

      for (const [char, child] of current.children) {
        queue.push(child)

        // Walk up failure chain to find the longest proper suffix
        // that is also a prefix of some pattern
        let failureNode = current.failure

        while (failureNode !== null && !failureNode.children.has(char)) {
          failureNode = failureNode.failure
        }

        child.failure = failureNode
          ? failureNode.children.get(char)!
          : this.root

        // Avoid self-loop
        if (child.failure === child) {
          child.failure = this.root
        }

        // Merge output from failure chain (dictionary suffix links)
        if (child.failure.output.length > 0) {
          child.output = [...child.output, ...child.failure.output]
        }
      }
    }

    this.isBuilt = true
  }

  /**
   * Search the input text for all pattern matches in a single pass.
   *
   * @param input - The text to scan
   * @returns Array of all matches found, including overlapping matches
   */
  search(input: string): AhoCorasickMatch[] {
    if (!this.isBuilt) {
      throw new Error(
        '[xpecto-shield] Automaton not built. Call build() before search().'
      )
    }

    const normalizedInput = input.toLowerCase()
    const matches: AhoCorasickMatch[] = []
    let current = this.root

    for (let i = 0; i < normalizedInput.length; i++) {
      const char = normalizedInput[i]

      // Follow failure links until we find a matching transition or reach root
      while (current !== this.root && !current.children.has(char)) {
        current = current.failure!
      }

      if (current.children.has(char)) {
        current = current.children.get(char)!
      }

      // Collect all outputs at this state (including from suffix links)
      if (current.output.length > 0) {
        for (const { pattern, category } of current.output) {
          matches.push({
            pattern,
            category,
            position: i - pattern.length + 1,
            length: pattern.length,
          })
        }
      }
    }

    return matches
  }

  /**
   * Reset the automaton — clears all patterns and failure links.
   * Call this if you need to rebuild with different patterns.
   */
  reset(): void {
    this.root = this.createNode(0)
    this.patternCount = 0
    this.isBuilt = false
  }

  /**
   * Get the total number of patterns added to the automaton.
   */
  getPatternCount(): number {
    return this.patternCount
  }

  /**
   * Check if the automaton has been built and is ready for searching.
   */
  getIsBuilt(): boolean {
    return this.isBuilt
  }

  /** Create a new trie node */
  private createNode(depth: number): TrieNode {
    return {
      children: new Map(),
      failure: null,
      output: [],
      depth,
    }
  }
}
