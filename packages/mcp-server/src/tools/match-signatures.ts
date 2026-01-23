/**
 * Match Signatures Tool
 *
 * MCP tool for matching binary files against YARA and Sigma signatures.
 * Identifies known malware families and provides severity assessment.
 *
 * @module tools/match-signatures
 *
 * @todo Phase 4: Add MISP feed integration for IOC matching
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { getLogger } from '@logtape/logtape';
import { YARAManager, type YARAManagerConfig } from '@sentinel/orchestrator';
import type { YARAScanResultSchema } from '@sentinel/shared';
import YAML from 'yaml';
import { z } from 'zod';

const logger = getLogger(['sentinel', 'tools', 'match-signatures']);

// ============================================
// INPUT SCHEMA
// ============================================

export const MatchSignaturesInputSchema = z.object({
  /** Path to binary file to scan */
  file_path: z.string().describe('Path to binary file to scan'),
  /** Timeout in seconds (default: 60) */
  timeout: z.number().positive().default(60).describe('Scan timeout in seconds'),
  /** Custom rules directory (optional) */
  rules_dir: z.string().optional().describe('Custom YARA rules directory'),
  /** Enable Sigma rule matching */
  enable_sigma: z.boolean().default(false).describe('Enable Sigma rule matching'),
  /** Sigma rules directory (optional) */
  sigma_rules_dir: z
    .string()
    .optional()
    .describe('Directory containing Sigma rule files (.yml/.yaml)'),
  /** Minimum string length for Sigma matching */
  min_string_length: z
    .number()
    .int()
    .positive()
    .default(6)
    .describe('Minimum string length for Sigma matching'),
});

export type MatchSignaturesInput = z.infer<typeof MatchSignaturesInputSchema>;

// ============================================
// SIGMA TYPES
// ============================================

type SigmaLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

type SigmaRule = {
  title?: string;
  id?: string;
  status?: string;
  description?: string;
  references?: string[];
  author?: string;
  level?: SigmaLevel | string;
  tags?: string[];
  detection?: Record<string, unknown>;
};

type SigmaFieldMatcher = {
  terms: string[];
  mode: 'contains' | 'startswith' | 'endswith' | 'equals' | 'regex';
  requireAll: boolean;
};

type SigmaSelector = {
  name: string;
  matchers: SigmaFieldMatcher[];
};

type SigmaSelectorMatch = {
  matched: boolean;
  matchedTerms: string[];
};

type SigmaMatch = {
  ruleId?: string;
  title: string;
  level: SigmaLevel;
  tags: string[];
  matchedSelectors: string[];
  matchedKeywords: string[];
  sourceFile: string;
};

type SigmaScanResult = {
  scanned: boolean;
  matches: SigmaMatch[];
  severity: SigmaLevel;
  rulesScanned: number;
  errors: string[];
};

// ============================================
// SIGMA HELPERS
// ============================================

function normalizeSigmaLevel(level?: string): SigmaLevel {
  if (!level) return 'unknown';
  const normalized = level.toLowerCase();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  return 'unknown';
}

function maxSigmaSeverity(levels: SigmaLevel[]): SigmaLevel {
  const order: SigmaLevel[] = ['unknown', 'low', 'medium', 'high', 'critical'];
  let maxIndex = 0;
  for (const level of levels) {
    const idx = order.indexOf(level);
    if (idx > maxIndex) maxIndex = idx;
  }
  return order[maxIndex] ?? 'unknown';
}

async function collectSigmaFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      const nested = await collectSigmaFiles(fullPath);
      files.push(...nested);
      continue;
    }
    const ext = extname(entry.name).toLowerCase();
    if (ext === '.yml' || ext === '.yaml') {
      files.push(fullPath);
    }
  }
  return files;
}

function extractTerms(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (typeof value === 'number' || typeof value === 'boolean') return [String(value)];
  if (Array.isArray(value)) return value.flatMap((item) => extractTerms(item));
  if (value && typeof value === 'object') {
    return Object.values(value).flatMap((item) => extractTerms(item));
  }
  return [];
}

function buildFieldMatcher(fieldKey: string, value: unknown): SigmaFieldMatcher | null {
  const parts = fieldKey.split('|');
  const modifiers = parts.slice(1).map((part) => part.toLowerCase());
  const requireAll = modifiers.includes('all');
  const mode: SigmaFieldMatcher['mode'] = modifiers.includes('startswith')
    ? 'startswith'
    : modifiers.includes('endswith')
      ? 'endswith'
      : modifiers.includes('equals')
        ? 'equals'
        : modifiers.includes('re') || modifiers.includes('regex')
          ? 'regex'
          : 'contains';

  const terms = extractTerms(value).filter((term) => term.length > 0);
  if (terms.length === 0) return null;

  return { terms, mode, requireAll };
}

function buildSelector(name: string, value: unknown): SigmaSelector | null {
  const matchers: SigmaFieldMatcher[] = [];

  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [fieldKey, fieldValue] of Object.entries(value)) {
      const matcher = buildFieldMatcher(fieldKey, fieldValue);
      if (matcher) matchers.push(matcher);
    }
  } else {
    const matcher = buildFieldMatcher(name, value);
    if (matcher) matchers.push(matcher);
  }

  if (matchers.length === 0) return null;
  return { name, matchers };
}

function matchTerm(
  term: string,
  mode: SigmaFieldMatcher['mode'],
  corpus: string[],
  corpusLower: string[],
): boolean {
  const needle = term.toLowerCase();
  if (mode === 'regex') {
    try {
      const re = new RegExp(term, 'i');
      return corpus.some((entry) => re.test(entry));
    } catch {
      return false;
    }
  }

  if (mode === 'equals') {
    return corpusLower.includes(needle);
  }
  if (mode === 'startswith') {
    return corpusLower.some((entry) => entry.startsWith(needle));
  }
  if (mode === 'endswith') {
    return corpusLower.some((entry) => entry.endsWith(needle));
  }

  return corpusLower.some((entry) => entry.includes(needle));
}

function matchFieldMatcher(
  matcher: SigmaFieldMatcher,
  corpus: string[],
  corpusLower: string[],
): SigmaSelectorMatch {
  const matchedTerms: string[] = [];
  const termMatches = matcher.terms.map((term) => {
    const matched = matchTerm(term, matcher.mode, corpus, corpusLower);
    if (matched) matchedTerms.push(term);
    return matched;
  });

  const matched = matcher.requireAll ? termMatches.every(Boolean) : termMatches.some(Boolean);
  return { matched, matchedTerms };
}

function matchSelector(
  selector: SigmaSelector,
  corpus: string[],
  corpusLower: string[],
): SigmaSelectorMatch {
  const matchedTerms: string[] = [];
  for (const matcher of selector.matchers) {
    const result = matchFieldMatcher(matcher, corpus, corpusLower);
    if (!result.matched) return { matched: false, matchedTerms: [] };
    matchedTerms.push(...result.matchedTerms);
  }
  return { matched: true, matchedTerms };
}

function evaluateOfCondition(
  condition: string,
  selectorResults: Record<string, SigmaSelectorMatch>,
): boolean | null {
  const trimmed = condition.trim();
  const ofMatch = trimmed.match(/^(1|all)\s+of\s+([\w*-]+)$/i);
  if (!ofMatch) return null;

  const mode = ofMatch[1]?.toLowerCase();
  const target = ofMatch[2] ?? '';
  const prefix = target.endsWith('*') ? target.slice(0, -1) : target;
  const matches = Object.entries(selectorResults)
    .filter(([name]) => name.startsWith(prefix))
    .map(([, result]) => result.matched);

  if (matches.length === 0) return false;
  return mode === 'all' ? matches.every(Boolean) : matches.some(Boolean);
}

function tokenizeCondition(condition: string): string[] {
  return condition.match(/\(|\)|\bnot\b|\band\b|\bor\b|[\w*.-]+/gi) ?? [];
}

const OPERATOR_PRECEDENCE: Record<string, number> = { not: 3, and: 2, or: 1 };

function isOperator(token: string): boolean {
  return token === 'and' || token === 'or' || token === 'not';
}

function shouldPopOperator(topOp: string | undefined, currentToken: string): boolean {
  if (!topOp || topOp === '(') return false;
  return (OPERATOR_PRECEDENCE[topOp] ?? 0) >= (OPERATOR_PRECEDENCE[currentToken] ?? 0);
}

function handleOperator(token: string, operators: string[], output: string[]): void {
  while (operators.length > 0 && shouldPopOperator(operators[operators.length - 1], token)) {
    output.push(operators.pop() ?? '');
  }
  operators.push(token);
}

function handleCloseParen(operators: string[], output: string[]): void {
  while (operators.length > 0 && operators[operators.length - 1] !== '(') {
    output.push(operators.pop() ?? '');
  }
  operators.pop(); // Remove the '('
}

function toRpn(tokens: string[]): string[] {
  const output: string[] = [];
  const operators: string[] = [];

  for (const raw of tokens) {
    const token = raw.toLowerCase();

    if (isOperator(token)) {
      handleOperator(token, operators, output);
    } else if (token === '(') {
      operators.push(token);
    } else if (token === ')') {
      handleCloseParen(operators, output);
    } else {
      output.push(raw);
    }
  }

  while (operators.length > 0) {
    output.push(operators.pop() ?? '');
  }

  return output;
}

function resolveSelectorToken(
  token: string,
  selectorResults: Record<string, SigmaSelectorMatch>,
): boolean {
  if (token.includes('*')) {
    const prefix = token.split('*')[0] ?? '';
    const matches = Object.entries(selectorResults)
      .filter(([name]) => name.startsWith(prefix))
      .map(([, result]) => result.matched);
    return matches.some(Boolean);
  }
  return selectorResults[token]?.matched ?? false;
}

function evaluateRpn(rpn: string[], selectorResults: Record<string, SigmaSelectorMatch>): boolean {
  const stack: boolean[] = [];
  for (const token of rpn) {
    const lower = token.toLowerCase();
    if (lower === 'and' || lower === 'or') {
      const right = stack.pop() ?? false;
      const left = stack.pop() ?? false;
      stack.push(lower === 'and' ? left && right : left || right);
      continue;
    }

    if (lower === 'not') {
      const value = stack.pop() ?? false;
      stack.push(!value);
      continue;
    }

    stack.push(resolveSelectorToken(token, selectorResults));
  }

  return stack.pop() ?? false;
}

function evaluateCondition(
  condition: string,
  selectorResults: Record<string, SigmaSelectorMatch>,
): boolean {
  const ofResult = evaluateOfCondition(condition, selectorResults);
  if (ofResult !== null) return ofResult;

  const tokens = tokenizeCondition(condition);
  const rpn = toRpn(tokens);
  return evaluateRpn(rpn, selectorResults);
}

function parseSigmaRules(content: string, sourceFile: string): SigmaRule[] {
  const documents = YAML.parseAllDocuments(content);
  const rules: SigmaRule[] = [];
  for (const doc of documents) {
    if (doc.errors && doc.errors.length > 0) continue;
    const data = doc.toJSON();
    if (data && typeof data === 'object') {
      rules.push(data as SigmaRule);
    }
  }
  if (rules.length === 0) {
    try {
      const single = YAML.parse(content);
      if (single && typeof single === 'object') {
        rules.push(single as SigmaRule);
      }
    } catch {
      logger.warn`Failed to parse Sigma rule file: ${sourceFile}`;
    }
  }
  return rules;
}

async function loadSigmaRules(
  dir: string,
): Promise<{ rules: Array<{ rule: SigmaRule; source: string }>; errors: string[] }> {
  const errors: string[] = [];
  try {
    const dirStat = await stat(dir);
    if (!dirStat.isDirectory()) {
      return { rules: [], errors: [`Sigma rules path is not a directory: ${dir}`] };
    }
  } catch {
    return { rules: [], errors: [`Sigma rules directory not found: ${dir}`] };
  }

  const files = await collectSigmaFiles(dir);
  const rules: Array<{ rule: SigmaRule; source: string }> = [];
  for (const filePath of files) {
    try {
      const content = await readFile(filePath, 'utf8');
      const parsed = parseSigmaRules(content, filePath);
      for (const rule of parsed) {
        rules.push({ rule, source: filePath });
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`Failed to load ${filePath}: ${message}`);
    }
  }
  return { rules, errors };
}

async function extractSigmaStrings(filePath: string, minLength: number): Promise<string[]> {
  const buffer = await readFile(filePath);
  const ascii: string[] = [];
  const unicode: string[] = [];
  let current = '';

  for (let i = 0; i < buffer.length; i++) {
    const byte = buffer[i];
    if (byte !== undefined && byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) ascii.push(current);
      current = '';
    }
  }
  if (current.length >= minLength) ascii.push(current);

  current = '';
  for (let i = 0; i < buffer.length - 1; i += 2) {
    const low = buffer[i];
    const high = buffer[i + 1];
    if (low !== undefined && high === 0 && low >= 32 && low <= 126) {
      current += String.fromCharCode(low);
    } else {
      if (current.length >= minLength) unicode.push(current);
      current = '';
    }
  }
  if (current.length >= minLength) unicode.push(current);

  return Array.from(new Set([...ascii, ...unicode]));
}

async function runSigmaScan(
  filePath: string,
  rulesDir: string | undefined,
  minLength: number,
): Promise<SigmaScanResult> {
  if (!rulesDir) {
    return {
      scanned: false,
      matches: [],
      severity: 'unknown',
      rulesScanned: 0,
      errors: ['Sigma rules directory not provided'],
    };
  }

  const { rules, errors } = await loadSigmaRules(rulesDir);
  if (rules.length === 0) {
    return {
      scanned: false,
      matches: [],
      severity: 'unknown',
      rulesScanned: 0,
      errors: errors.length > 0 ? errors : ['No Sigma rules found'],
    };
  }

  const corpus = await extractSigmaStrings(filePath, minLength);
  const corpusLower = corpus.map((value) => value.toLowerCase());

  const matches: SigmaMatch[] = [];
  const levels: SigmaLevel[] = [];

  for (const { rule, source } of rules) {
    const detection = rule.detection;
    if (!detection || typeof detection !== 'object') continue;

    const condition = typeof detection.condition === 'string' ? detection.condition : 'selection';
    const selectors: Record<string, SigmaSelector> = {};
    for (const [name, value] of Object.entries(detection)) {
      if (name === 'condition') continue;
      const selector = buildSelector(name, value);
      if (selector) selectors[name] = selector;
    }

    const selectorResults: Record<string, SigmaSelectorMatch> = {};
    for (const [name, selector] of Object.entries(selectors)) {
      selectorResults[name] = matchSelector(selector, corpus, corpusLower);
    }

    const matched = evaluateCondition(condition, selectorResults);
    if (!matched) continue;

    const matchedSelectors = Object.entries(selectorResults)
      .filter(([, result]) => result.matched)
      .map(([name]) => name);
    const matchedKeywords = Array.from(
      new Set(Object.values(selectorResults).flatMap((result) => result.matchedTerms)),
    );

    const level = normalizeSigmaLevel(rule.level);
    levels.push(level);

    matches.push({
      ruleId: rule.id,
      title: rule.title ?? 'Unnamed Sigma rule',
      level,
      tags: rule.tags ?? [],
      matchedSelectors,
      matchedKeywords,
      sourceFile: source,
    });
  }

  return {
    scanned: true,
    matches,
    severity: maxSigmaSeverity(levels),
    rulesScanned: rules.length,
    errors,
  };
}

// ============================================
// TOOL IMPLEMENTATION
// ============================================

let yaraManager: YARAManager | null = null;

/**
 * Get or create YARA manager instance
 */
function getManager(config?: Partial<YARAManagerConfig>): YARAManager {
  if (!yaraManager || config) {
    yaraManager = new YARAManager(config);
  }
  return yaraManager;
}

/**
 * Match binary against YARA signatures
 *
 * @param input - Tool input parameters
 * @returns YARA scan results with matches, severity, and malware families
 */
export async function matchSignatures(input: MatchSignaturesInput): Promise<{
  success: boolean;
  data?: z.infer<typeof YARAScanResultSchema>;
  sigma?: SigmaScanResult;
  error?: string;
}> {
  const { file_path, timeout, rules_dir, enable_sigma, sigma_rules_dir, min_string_length } =
    MatchSignaturesInputSchema.parse(input);

  logger.info`Scanning ${file_path} with YARA signatures`;

  try {
    // Check if file exists
    const file = Bun.file(file_path);
    const exists = await file.exists();

    if (!exists) {
      return {
        success: false,
        error: `File not found: ${file_path}`,
      };
    }

    // Initialize YARA manager with optional custom config
    const config: Partial<YARAManagerConfig> = {
      timeoutMs: timeout * 1000,
    };

    if (rules_dir) {
      config.rulesDir = rules_dir;
    }

    const manager = getManager(config);
    const result = await manager.scan(file_path);

    const sigmaResult = enable_sigma
      ? await runSigmaScan(file_path, sigma_rules_dir, min_string_length)
      : undefined;

    if (!result.ok) {
      return {
        success: false,
        error: result.error.message,
      };
    }

    logger.info`YARA scan complete: ${result.value.matches.length} matches, severity=${result.value.severity}`;

    return {
      success: true,
      data: result.value,
      sigma: sigmaResult,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.error`YARA scan failed: ${message}`;

    return {
      success: false,
      error: message,
    };
  }
}

// ============================================
// TOOL DEFINITION
// ============================================

export const matchSignaturesTool = {
  name: 'match_signatures',
  description:
    'Match binary against YARA and optional Sigma signatures to identify known malware families and behaviors. ' +
    'Provides rule names, severity assessment (critical/high/medium/low), and matched string patterns. ' +
    'Requires yara-x to be installed on the system for YARA rules.',
  inputSchema: {
    type: 'object' as const,
    properties: {
      file_path: {
        type: 'string',
        description: 'Absolute path to binary file to scan',
      },
      timeout: {
        type: 'number',
        description: 'Scan timeout in seconds (default: 60)',
        default: 60,
      },
      rules_dir: {
        type: 'string',
        description: 'Custom YARA rules directory (optional)',
      },
      enable_sigma: {
        type: 'boolean',
        description: 'Enable Sigma rule matching (default: false)',
        default: false,
      },
      sigma_rules_dir: {
        type: 'string',
        description: 'Directory containing Sigma rule files (.yml/.yaml)',
      },
      min_string_length: {
        type: 'number',
        description: 'Minimum string length for Sigma matching (default: 6)',
        default: 6,
      },
    },
    required: ['file_path'],
  },
  execute: matchSignatures,
};

export default matchSignaturesTool;
