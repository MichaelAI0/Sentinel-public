/**
 * Context Window Manager
 *
 * Manages LLM context window limits by tracking token usage,
 * prioritizing content, and implementing smart truncation.
 *
 * @module utils/context-manager
 */

// Note: Result, err, ok, ValidationError available from @sentinel/shared when needed

// ============================================
// CONSTANTS
// ============================================

/** Approximate tokens per character (conservative estimate) */
const CHARS_PER_TOKEN = 4;

/** Default context window size (tokens) */
export const DEFAULT_CONTEXT_SIZE = 8192;

/** Reserved tokens for output generation */
export const RESERVED_OUTPUT_TOKENS = 2048;

/** Content type priorities (higher = more important) */
export const CONTENT_PRIORITIES = {
  SYSTEM: 100, // System prompts
  CRITICAL: 90, // Critical analysis data
  HIGH: 70, // Important findings
  MEDIUM: 50, // Supporting evidence
  LOW: 30, // Background context
  OPTIONAL: 10, // Nice to have
} as const;

// ============================================
// TYPES & INTERFACES
// ============================================

/**
 * Priority level for content
 */
export type ContentPriority = keyof typeof CONTENT_PRIORITIES;

/**
 * Content block with metadata
 */
export type ContentBlock = {
  id: string;
  content: string;
  priority: ContentPriority;
  category: string;
  estimatedTokens: number;
  truncatable: boolean;
  minTokens?: number; // Minimum tokens if truncated
};

/**
 * Context window allocation result
 */
export type ContextAllocation = {
  blocks: ContentBlock[];
  totalTokens: number;
  usedTokens: number;
  remainingTokens: number;
  truncatedBlocks: string[];
  droppedBlocks: string[];
  utilizationPercent: number;
};

/**
 * Token budget configuration
 */
export type TokenBudget = {
  total: number;
  reserved: number;
  available: number;
  categories: Map<string, number>;
};

/**
 * Truncation strategy
 */
export type TruncationStrategy = 'end' | 'middle' | 'smart';

// ============================================
// TOKEN ESTIMATION
// ============================================

/**
 * Estimate token count from text
 * Uses character-based estimation with safety margin
 */
export function estimateTokens(text: string): number {
  if (!text) return 0;
  return Math.ceil(text.length / CHARS_PER_TOKEN);
}

/**
 * Estimate tokens for structured data (JSON)
 */
export function estimateJsonTokens(data: unknown): number {
  const json = JSON.stringify(data, null, 2);
  // JSON is more verbose, add 20% overhead
  return Math.ceil(estimateTokens(json) * 1.2);
}

/**
 * Calculate max characters for a token budget
 */
export function tokensToChars(tokens: number): number {
  return tokens * CHARS_PER_TOKEN;
}

// ============================================
// CONTENT BLOCK BUILDER
// ============================================

/**
 * Builder for creating content blocks
 */
export class ContentBlockBuilder {
  private blocks: ContentBlock[] = [];
  private idCounter = 0;

  /**
   * Add a content block
   */
  add(
    content: string,
    options: {
      priority?: ContentPriority;
      category?: string;
      truncatable?: boolean;
      minTokens?: number;
    } = {},
  ): this {
    const id = `block_${++this.idCounter}`;
    const estimatedTokens = estimateTokens(content);

    this.blocks.push({
      id,
      content,
      priority: options.priority ?? 'MEDIUM',
      category: options.category ?? 'general',
      estimatedTokens,
      truncatable: options.truncatable ?? true,
      minTokens: options.minTokens,
    });

    return this;
  }

  /**
   * Add system prompt (highest priority, non-truncatable)
   */
  addSystem(content: string): this {
    return this.add(content, {
      priority: 'SYSTEM',
      category: 'system',
      truncatable: false,
    });
  }

  /**
   * Add critical analysis data
   */
  addCritical(content: string, category = 'critical'): this {
    return this.add(content, {
      priority: 'CRITICAL',
      category,
      truncatable: false,
    });
  }

  /**
   * Add analysis findings (truncatable with minimum)
   */
  addFindings(content: string, minTokens = 100): this {
    return this.add(content, {
      priority: 'HIGH',
      category: 'findings',
      truncatable: true,
      minTokens,
    });
  }

  /**
   * Add supporting context (freely truncatable)
   */
  addContext(content: string): this {
    return this.add(content, {
      priority: 'LOW',
      category: 'context',
      truncatable: true,
    });
  }

  /**
   * Get all blocks sorted by priority
   */
  build(): ContentBlock[] {
    return [...this.blocks].sort(
      (a, b) => CONTENT_PRIORITIES[b.priority] - CONTENT_PRIORITIES[a.priority],
    );
  }

  /**
   * Get total estimated tokens
   */
  getTotalTokens(): number {
    return this.blocks.reduce((sum, b) => sum + b.estimatedTokens, 0);
  }

  /**
   * Clear all blocks
   */
  clear(): this {
    this.blocks = [];
    this.idCounter = 0;
    return this;
  }
}

// ============================================
// CONTEXT WINDOW MANAGER
// ============================================

/**
 * Manages LLM context window allocation
 *
 * @example
 * ```typescript
 * const manager = new ContextWindowManager(8192);
 *
 * const builder = new ContentBlockBuilder();
 * builder
 *   .addSystem('You are a malware analyst...')
 *   .addCritical(JSON.stringify(triageResults))
 *   .addFindings(suspiciousStrings)
 *   .addContext(disassemblyOutput);
 *
 * const allocation = manager.allocate(builder.build());
 * const prompt = manager.buildPrompt(allocation);
 * ```
 */
export class ContextWindowManager {
  private readonly maxTokens: number;
  private readonly reservedTokens: number;
  private readonly availableTokens: number;

  constructor(
    maxTokens: number = DEFAULT_CONTEXT_SIZE,
    reservedForOutput: number = RESERVED_OUTPUT_TOKENS,
  ) {
    this.maxTokens = maxTokens;
    this.reservedTokens = reservedForOutput;
    this.availableTokens = maxTokens - reservedForOutput;
  }

  /**
   * Allocate tokens to content blocks
   * Uses priority-based allocation with truncation as needed
   */
  allocate(blocks: ContentBlock[], strategy: TruncationStrategy = 'smart'): ContextAllocation {
    // Sort by priority (highest first)
    const sorted = [...blocks].sort(
      (a, b) => CONTENT_PRIORITIES[b.priority] - CONTENT_PRIORITIES[a.priority],
    );

    const allocated: ContentBlock[] = [];
    const truncated: string[] = [];
    const dropped: string[] = [];
    let usedTokens = 0;

    for (const block of sorted) {
      const remaining = this.availableTokens - usedTokens;

      if (remaining <= 0) {
        // No space left, drop remaining blocks
        dropped.push(block.id);
        continue;
      }

      if (block.estimatedTokens <= remaining) {
        // Block fits entirely
        allocated.push(block);
        usedTokens += block.estimatedTokens;
      } else if (block.truncatable && remaining > (block.minTokens ?? 50)) {
        // Truncate block to fit
        const truncatedContent = this.truncateContent(block.content, remaining, strategy);
        allocated.push({
          ...block,
          content: truncatedContent,
          estimatedTokens: remaining,
        });
        usedTokens += remaining;
        truncated.push(block.id);
      } else {
        // Can't fit, drop it
        dropped.push(block.id);
      }
    }

    return {
      blocks: allocated,
      totalTokens: this.maxTokens,
      usedTokens,
      remainingTokens: this.availableTokens - usedTokens,
      truncatedBlocks: truncated,
      droppedBlocks: dropped,
      utilizationPercent: (usedTokens / this.availableTokens) * 100,
    };
  }

  /**
   * Truncate content to fit within token budget
   */
  truncateContent(content: string, maxTokens: number, strategy: TruncationStrategy): string {
    const maxChars = tokensToChars(maxTokens);

    if (content.length <= maxChars) {
      return content;
    }

    switch (strategy) {
      case 'end':
        return `${content.slice(0, maxChars - 3)}...`;

      case 'middle': {
        const halfChars = Math.floor((maxChars - 20) / 2);
        return `${content.slice(0, halfChars)}\n...[truncated]...\n${content.slice(-halfChars)}`;
      }
      default:
        return this.smartTruncate(content, maxChars);
    }
  }

  /**
   * Smart truncation that preserves important parts
   */
  private smartTruncate(content: string, maxChars: number): string {
    const lines = content.split('\n');

    // If few enough lines, use simple end truncation
    if (lines.length < 10) {
      return `${content.slice(0, maxChars - 3)}...`;
    }

    // Keep first 30% and last 20%, truncate middle
    const firstPortion = Math.floor(lines.length * 0.3);
    const lastPortion = Math.floor(lines.length * 0.2);

    const firstLines = lines.slice(0, firstPortion);
    const lastLines = lines.slice(-lastPortion);
    const skipped = lines.length - firstPortion - lastPortion;

    const result = [...firstLines, `\n... [${skipped} lines omitted] ...\n`, ...lastLines].join(
      '\n',
    );

    // If still too long, do simple truncation
    if (result.length > maxChars) {
      return `${result.slice(0, maxChars - 3)}...`;
    }

    return result;
  }

  /**
   * Build a combined prompt from allocated blocks
   */
  buildPrompt(allocation: ContextAllocation): string {
    return allocation.blocks.map((block) => block.content).join('\n\n---\n\n');
  }

  /**
   * Build prompt with category headers
   */
  buildStructuredPrompt(allocation: ContextAllocation): string {
    const byCategory = new Map<string, string[]>();

    for (const block of allocation.blocks) {
      const existing = byCategory.get(block.category) ?? [];
      existing.push(block.content);
      byCategory.set(block.category, existing);
    }

    const sections: string[] = [];
    for (const [category, contents] of byCategory) {
      sections.push(`## ${category.toUpperCase()}\n\n${contents.join('\n\n')}`);
    }

    return sections.join('\n\n---\n\n');
  }

  /**
   * Get token budget information
   */
  getBudget(): TokenBudget {
    return {
      total: this.maxTokens,
      reserved: this.reservedTokens,
      available: this.availableTokens,
      categories: new Map(),
    };
  }

  /**
   * Check if content fits in context
   */
  fitsInContext(content: string): boolean {
    return estimateTokens(content) <= this.availableTokens;
  }

  /**
   * Get remaining capacity after some content
   */
  remainingCapacity(usedContent: string): number {
    return this.availableTokens - estimateTokens(usedContent);
  }
}

// ============================================
// ANALYSIS DATA FORMATTERS
// ============================================

/**
 * Format triage results for context-efficient inclusion
 */
export function formatTriageForContext(triage: {
  riskLevel: string;
  riskScore: number;
  findings: string[];
  recommendations: string[];
}): string {
  const lines = [
    `Risk: ${triage.riskLevel} (${triage.riskScore}/100)`,
    '',
    'Key Findings:',
    ...triage.findings.slice(0, 5).map((f) => `- ${f}`),
  ];

  if (triage.findings.length > 5) {
    lines.push(`... and ${triage.findings.length - 5} more findings`);
  }

  return lines.join('\n');
}

/**
 * Format strings analysis for context
 */
export function formatStringsForContext(strings: string[], maxStrings: number = 50): string {
  if (strings.length === 0) {
    return 'No suspicious strings found.';
  }

  const selected = strings.slice(0, maxStrings);
  const result = selected.map((s) => `  "${s.slice(0, 100)}"`).join('\n');

  if (strings.length > maxStrings) {
    return `${result}\n... and ${strings.length - maxStrings} more strings`;
  }

  return result;
}

/**
 * Format imports/exports for context
 */
export function formatImportsForContext(
  imports: { library: string; functions: string[] }[],
  maxPerLib: number = 10,
): string {
  return imports
    .map((imp) => {
      const funcs = imp.functions.slice(0, maxPerLib);
      const funcList = funcs.join(', ');
      const more =
        imp.functions.length > maxPerLib ? ` (+${imp.functions.length - maxPerLib} more)` : '';
      return `${imp.library}: ${funcList}${more}`;
    })
    .join('\n');
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

/**
 * Create a context manager for a specific model
 */
export function createContextManager(modelName: string): ContextWindowManager {
  // Map known models to their context sizes
  const contextSizes: Record<string, number> = {
    'qwen2.5:7b': 8192,
    'qwen2.5:7b-instruct': 8192,
    'llama3.1:8b': 8192,
    'mistral:7b': 8192,
    'codellama:7b': 16384,
    'deepseek-coder:6.7b': 16384,
  };

  const contextSize = contextSizes[modelName] ?? DEFAULT_CONTEXT_SIZE;
  return new ContextWindowManager(contextSize);
}

/**
 * Quick check if analysis data fits in context
 */
export function analysisDataFits(
  analysisJson: unknown,
  contextSize: number = DEFAULT_CONTEXT_SIZE,
): boolean {
  const tokens = estimateJsonTokens(analysisJson);
  return tokens < contextSize - RESERVED_OUTPUT_TOKENS;
}
