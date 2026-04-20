import type { ThreatCategory, AhoCorasickMatch } from './types'

interface TrieNode {
  children: Map<string, TrieNode>
  failure: TrieNode | null
  output: Array<{ pattern: string; category: ThreatCategory }>
  depth: number
}

export class AhoCorasickAutomaton {
  private root: TrieNode
  private patternCount: number = 0
  private isBuilt: boolean = false

  constructor() {
    this.root = this.createNode(0)
  }

  addPattern(pattern: string, category: ThreatCategory): void {
    if (this.isBuilt) {
      throw new Error('[xpecto-shield] Cannot add patterns after build().')
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

    current.output.push({ pattern: normalizedPattern, category })
    this.patternCount++
  }

  build(): void {
    const queue: TrieNode[] = []

    for (const [, child] of this.root.children) {
      child.failure = this.root
      queue.push(child)
    }

    while (queue.length > 0) {
      const current = queue.shift()!

      for (const [char, child] of current.children) {
        queue.push(child)

        let failureNode = current.failure
        while (failureNode !== null && !failureNode.children.has(char)) {
          failureNode = failureNode.failure
        }

        child.failure = failureNode
          ? failureNode.children.get(char)!
          : this.root

        if (child.failure === child) {
          child.failure = this.root
        }

        if (child.failure.output.length > 0) {
          child.output = [...child.output, ...child.failure.output]
        }
      }
    }

    this.isBuilt = true
  }

  search(input: string): AhoCorasickMatch[] {
    if (!this.isBuilt) {
      throw new Error('[xpecto-shield] Automaton not built. Call build() first.')
    }

    const normalizedInput = input.toLowerCase()
    const matches: AhoCorasickMatch[] = []
    let current = this.root

    for (let i = 0; i < normalizedInput.length; i++) {
      const char = normalizedInput[i]

      while (current !== this.root && !current.children.has(char)) {
        current = current.failure!
      }

      if (current.children.has(char)) {
        current = current.children.get(char)!
      }

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

  reset(): void {
    this.root = this.createNode(0)
    this.patternCount = 0
    this.isBuilt = false
  }

  getPatternCount(): number {
    return this.patternCount
  }

  getIsBuilt(): boolean {
    return this.isBuilt
  }

  private createNode(depth: number): TrieNode {
    return {
      children: new Map(),
      failure: null,
      output: [],
      depth,
    }
  }
}
