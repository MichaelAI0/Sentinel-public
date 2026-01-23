/**
 * String Analyzer
 *
 * Enhanced string analysis with categorization, entropy scoring,
 * encoding detection, suspicious pattern matching, multi-language
 * detection, C2 protocol identification, and decryption attempts.
 *
 * @module utils/string-analyzer
 *
 * @todo Phase 4: Add ML-based string classification
 */

import { getLogger } from '@logtape/logtape';

const logger = getLogger(['sentinel', 'string-analyzer']);

// ============================================
// TYPES
// ============================================

/**
 * Detected string encoding
 */
export type StringEncoding =
  | 'ascii'
  | 'utf8'
  | 'utf16-le'
  | 'utf16-be'
  | 'base64'
  | 'hex'
  | 'unknown';

/**
 * Unicode script/language detected in string
 */
export type UnicodeScript =
  | 'latin'
  | 'cyrillic'
  | 'arabic'
  | 'chinese'
  | 'japanese'
  | 'korean'
  | 'hebrew'
  | 'thai'
  | 'devanagari'
  | 'greek'
  | 'mixed'
  | 'unknown';

/**
 * C2 protocol pattern detection result
 */
export type C2Protocol = {
  /** Protocol name or type */
  protocol: string;
  /** Confidence level (0-1) */
  confidence: number;
  /** Evidence for detection */
  evidence: string;
  /** Associated indicators */
  indicators: string[];
};

/**
 * Decryption attempt result
 */
export type DecryptionAttempt = {
  /** Method used for decryption */
  method:
    | 'xor-single'
    | 'xor-rolling'
    | 'rot13'
    | 'caesar'
    | 'rc4-guess'
    | 'base64-nested'
    | 'url-decode';
  /** Decrypted result */
  result: string;
  /** Confidence that decryption is correct (0-1) */
  confidence: number;
  /** Key or parameter used (if applicable) */
  key?: string | number;
  /** Whether result looks like valid plaintext */
  looksValid: boolean;
};

/**
 * String category based on content analysis
 */
export type StringCategory =
  | 'url'
  | 'filepath'
  | 'registry'
  | 'api'
  | 'command'
  | 'ip'
  | 'email'
  | 'guid'
  | 'crypto'
  | 'generic';

/**
 * Analyzed string with metadata
 */
export type AnalyzedString = {
  /** Original string value */
  value: string;
  /** Detected encoding */
  encoding: StringEncoding;
  /** Shannon entropy (0-8 for byte data) */
  entropy: number;
  /** Categorization */
  category: StringCategory;
  /** Whether string appears suspicious */
  suspicious: boolean;
  /** Suspicion reasons if suspicious */
  suspicionReasons: string[];
  /** Decoded value if encoded */
  decodedValue?: string;
  /** Offset in file if available */
  offset?: number;
  /** Length in bytes */
  length: number;
  /** Detected Unicode scripts/languages */
  scripts?: UnicodeScript[];
  /** C2 protocol patterns detected */
  c2Protocols?: C2Protocol[];
  /** Decryption attempt results */
  decryptionAttempts?: DecryptionAttempt[];
};

/**
 * String analysis summary
 */
export type StringAnalysisSummary = {
  /** Total strings analyzed */
  totalStrings: number;
  /** Unique strings */
  uniqueStrings: number;
  /** Suspicious strings count */
  suspiciousCount: number;
  /** Category breakdown */
  categoryBreakdown: Record<StringCategory, number>;
  /** High-value strings (most suspicious/interesting) */
  highValueStrings: AnalyzedString[];
  /** All analyzed strings */
  strings: AnalyzedString[];
  /** Unicode script/language breakdown */
  scriptBreakdown?: Record<UnicodeScript, number>;
  /** Detected C2 protocols across all strings */
  c2Protocols?: C2Protocol[];
  /** Strings with non-Latin scripts (potential multi-language malware) */
  nonLatinStrings?: AnalyzedString[];
  /** Successful decryption attempts */
  successfulDecryptions?: AnalyzedString[];
};

/**
 * Analyzer configuration
 */
export type StringAnalyzerConfig = {
  /** Minimum string length to analyze */
  minLength: number;
  /** Maximum number of strings to return */
  maxStrings: number;
  /** Whether to decode base64/hex strings */
  attemptDecode: boolean;
  /** Entropy threshold for suspicious classification */
  entropyThreshold: number;
  /** Whether to attempt decryption of obfuscated strings */
  attemptDecryption: boolean;
  /** Maximum strings to attempt decryption on (expensive operation) */
  maxDecryptionAttempts: number;
};

// ============================================
// DEFAULT CONFIGURATION
// ============================================

const DEFAULT_CONFIG: StringAnalyzerConfig = {
  minLength: 4,
  maxStrings: 1000,
  attemptDecode: true,
  entropyThreshold: 4.5,
  attemptDecryption: true,
  maxDecryptionAttempts: 100,
};

// ============================================
// SUSPICIOUS PATTERNS
// ============================================

type SuspiciousPattern = {
  pattern: RegExp;
  reason: string;
  severity: 'high' | 'medium' | 'low';
};

const SUSPICIOUS_PATTERNS: SuspiciousPattern[] = [
  // Command execution
  { pattern: /cmd\.exe/i, reason: 'Command shell reference', severity: 'high' },
  { pattern: /powershell/i, reason: 'PowerShell reference', severity: 'high' },
  { pattern: /wscript|cscript/i, reason: 'Windows Script Host', severity: 'high' },
  { pattern: /\/bin\/sh|\/bin\/bash/i, reason: 'Unix shell reference', severity: 'high' },

  // Privilege escalation
  { pattern: /runas|sudo/i, reason: 'Privilege escalation', severity: 'high' },
  { pattern: /SeDebugPrivilege/i, reason: 'Debug privilege request', severity: 'high' },

  // Process manipulation
  { pattern: /CreateRemoteThread/i, reason: 'Remote thread creation', severity: 'high' },
  { pattern: /VirtualAllocEx/i, reason: 'Remote memory allocation', severity: 'high' },
  { pattern: /WriteProcessMemory/i, reason: 'Process memory write', severity: 'high' },
  { pattern: /OpenProcess/i, reason: 'Process handle opening', severity: 'medium' },

  // Registry operations
  {
    pattern: /HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/i,
    reason: 'Startup registry key',
    severity: 'high',
  },
  { pattern: /RegSetValue|RegCreateKey/i, reason: 'Registry modification API', severity: 'medium' },

  // Network operations
  { pattern: /WSAStartup|socket\(/i, reason: 'Network socket creation', severity: 'medium' },
  { pattern: /InternetOpen|HttpSendRequest/i, reason: 'HTTP operations', severity: 'medium' },
  { pattern: /URLDownloadToFile/i, reason: 'File download API', severity: 'high' },

  // File operations
  { pattern: /DeleteFile|RemoveFile/i, reason: 'File deletion API', severity: 'medium' },
  { pattern: /CopyFile|MoveFile/i, reason: 'File manipulation API', severity: 'low' },

  // Anti-analysis
  { pattern: /IsDebuggerPresent/i, reason: 'Debugger detection', severity: 'high' },
  { pattern: /CheckRemoteDebuggerPresent/i, reason: 'Remote debugger check', severity: 'high' },
  {
    pattern: /NtQueryInformationProcess/i,
    reason: 'Process query (anti-debug)',
    severity: 'medium',
  },
  {
    pattern: /GetTickCount|QueryPerformanceCounter/i,
    reason: 'Timing check (anti-debug)',
    severity: 'low',
  },

  // Encryption indicators
  { pattern: /CryptAcquireContext|CryptEncrypt/i, reason: 'Crypto API usage', severity: 'medium' },
  { pattern: /AES|RSA|DES/i, reason: 'Encryption algorithm reference', severity: 'low' },

  // C2 indicators
  { pattern: /beacon|callback|checkin/i, reason: 'Possible C2 terminology', severity: 'medium' },
  { pattern: /\.onion/i, reason: 'Tor hidden service', severity: 'high' },
];

// ============================================
// C2 PROTOCOL PATTERNS
// ============================================

type C2PatternDef = {
  protocol: string;
  patterns: RegExp[];
  confidence: number;
  description: string;
};

const C2_PROTOCOL_PATTERNS: C2PatternDef[] = [
  // HTTP/HTTPS-based C2
  {
    protocol: 'http-beacon',
    patterns: [
      /\/api\/v\d+\/beacon/i,
      /\/gate\.php/i,
      /\/panel\/gate/i,
      /\/c2\/check/i,
      /\/(admin|bot|cc|cnc)\.php/i,
    ],
    confidence: 0.85,
    description: 'HTTP-based beaconing pattern',
  },
  // DNS tunneling
  {
    protocol: 'dns-tunnel',
    patterns: [
      /[a-z0-9]{32,}\.[a-z0-9-]+\.[a-z]{2,}/i,
      /\.dnscat\./i,
      /\.dns2tcp\./i,
      /txt\..*\.com$/i,
    ],
    confidence: 0.75,
    description: 'DNS tunneling pattern',
  },
  // Cobalt Strike
  {
    protocol: 'cobalt-strike',
    patterns: [
      /\/submit\.php\?id=/i,
      /\/pixel\.gif/i,
      /\/updates\.rss/i,
      /\/visit\.js/i,
      /\/jquery-\d+\.\d+\.\d+\.min\.js/i,
    ],
    confidence: 0.8,
    description: 'Cobalt Strike malleable C2 pattern',
  },
  // Empire/Powershell Empire
  {
    protocol: 'empire',
    patterns: [/\/news\.php/i, /\/login\/process\.php/i, /\/admin\/get\.php/i, /stager\.(ps1|py)/i],
    confidence: 0.7,
    description: 'Empire C2 framework pattern',
  },
  // Metasploit
  {
    protocol: 'metasploit',
    patterns: [/meterpreter/i, /reverse_tcp/i, /reverse_https?/i, /bind_tcp/i, /staged?_payload/i],
    confidence: 0.85,
    description: 'Metasploit framework indicator',
  },
  // Generic RAT patterns
  {
    protocol: 'rat-generic',
    patterns: [
      /keylog(ger)?/i,
      /screenshot/i,
      /webcam|camera/i,
      /clipboard/i,
      /file_?manager/i,
      /remote_?desktop/i,
      /shell_?exec/i,
    ],
    confidence: 0.7,
    description: 'Generic RAT capability indicator',
  },
  // Sliver C2
  {
    protocol: 'sliver',
    patterns: [/\.woff2?\?v=/i, /\/api\/sessions/i, /implant_?config/i],
    confidence: 0.65,
    description: 'Sliver C2 framework pattern',
  },
  // Custom/encoded C2
  {
    protocol: 'encoded-c2',
    patterns: [
      /cmd=base64/i,
      /exec=b64/i,
      /data=[A-Za-z0-9+/]{20,}={0,2}/i,
      /\?[a-z]=[A-Za-z0-9+/]{50,}/i,
    ],
    confidence: 0.6,
    description: 'Base64-encoded command pattern',
  },
];

// ============================================
// UNICODE SCRIPT RANGES (for multi-language detection)
// ============================================

type UnicodeRange = {
  script: UnicodeScript;
  ranges: Array<[number, number]>;
};

const UNICODE_SCRIPT_RANGES: UnicodeRange[] = [
  {
    script: 'latin',
    ranges: [
      [0x0041, 0x007a],
      [0x00c0, 0x00ff],
      [0x0100, 0x017f],
    ],
  },
  {
    script: 'cyrillic',
    ranges: [
      [0x0400, 0x04ff],
      [0x0500, 0x052f],
    ],
  },
  {
    script: 'arabic',
    ranges: [
      [0x0600, 0x06ff],
      [0x0750, 0x077f],
    ],
  },
  { script: 'hebrew', ranges: [[0x0590, 0x05ff]] },
  { script: 'greek', ranges: [[0x0370, 0x03ff]] },
  { script: 'devanagari', ranges: [[0x0900, 0x097f]] },
  { script: 'thai', ranges: [[0x0e00, 0x0e7f]] },
  {
    script: 'chinese',
    ranges: [
      [0x4e00, 0x9fff],
      [0x3400, 0x4dbf],
    ],
  },
  {
    script: 'japanese',
    ranges: [
      [0x3040, 0x309f],
      [0x30a0, 0x30ff],
      [0x31f0, 0x31ff],
    ],
  },
  {
    script: 'korean',
    ranges: [
      [0xac00, 0xd7af],
      [0x1100, 0x11ff],
    ],
  },
];

// ============================================
// STRING ANALYZER CLASS
// ============================================

export class StringAnalyzer {
  private readonly config: StringAnalyzerConfig;

  constructor(config: Partial<StringAnalyzerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Analyze an array of extracted strings
   */
  analyze(strings: string[]): StringAnalysisSummary {
    logger.debug`Analyzing ${strings.length} strings`;

    const seen = new Set<string>();
    const analyzed: AnalyzedString[] = [];

    for (const str of strings) {
      // Skip duplicates
      if (seen.has(str)) continue;
      seen.add(str);

      // Skip strings below minimum length
      if (str.length < this.config.minLength) continue;

      // Limit total strings
      if (analyzed.length >= this.config.maxStrings) break;

      analyzed.push(this.analyzeString(str));
    }

    // Sort by suspiciousness and entropy
    analyzed.sort((a, b) => {
      const scoreA = (a.suspicious ? 100 : 0) + a.entropy * 10;
      const scoreB = (b.suspicious ? 100 : 0) + b.entropy * 10;
      return scoreB - scoreA;
    });

    // Calculate category breakdown
    const categoryBreakdown = this.calculateCategoryBreakdown(analyzed);

    // Calculate script breakdown
    const scriptBreakdown = this.calculateScriptBreakdown(analyzed);

    // Collect all C2 protocols detected
    const allC2Protocols: C2Protocol[] = [];
    for (const str of analyzed) {
      if (str.c2Protocols) {
        allC2Protocols.push(...str.c2Protocols);
      }
    }

    // Collect non-Latin strings (potential multi-language malware)
    const nonLatinStrings = analyzed.filter((s) =>
      s.scripts?.some((script) => script !== 'latin' && script !== 'unknown'),
    );

    // Extract high-value strings (top suspicious + high entropy)
    const highValueStrings = analyzed
      .filter((s) => s.suspicious || s.entropy > this.config.entropyThreshold)
      .slice(0, 50);

    return {
      totalStrings: strings.length,
      uniqueStrings: seen.size,
      suspiciousCount: analyzed.filter((s) => s.suspicious).length,
      categoryBreakdown,
      highValueStrings,
      strings: analyzed,
      scriptBreakdown,
      c2Protocols: allC2Protocols.length > 0 ? allC2Protocols : undefined,
      nonLatinStrings: nonLatinStrings.length > 0 ? nonLatinStrings : undefined,
      successfulDecryptions: analyzed.filter((s) =>
        s.decryptionAttempts?.some((d) => d.looksValid),
      ),
    };
  }

  /**
   * Analyze a single string
   */
  analyzeString(str: string, offset?: number): AnalyzedString {
    const encoding = this.detectEncoding(str);
    const entropy = this.calculateEntropy(str);
    const category = this.categorize(str);
    const { suspicious, reasons } = this.checkSuspicious(str);
    const scripts = this.detectScripts(str);
    const c2Protocols = this.detectC2Protocols(str);

    let decodedValue: string | undefined;
    if (this.config.attemptDecode) {
      decodedValue = this.tryDecode(str, encoding);
    }

    // Attempt decryption for high-entropy or crypto-categorized strings
    let decryptionAttempts: DecryptionAttempt[] | undefined;
    if (this.config.attemptDecryption && (entropy > 4.0 || category === 'crypto')) {
      decryptionAttempts = this.attemptDecryption(str);
      if (decryptionAttempts.length === 0) {
        decryptionAttempts = undefined;
      }
    }

    return {
      value: str,
      encoding,
      entropy,
      category,
      suspicious,
      suspicionReasons: reasons,
      decodedValue,
      offset,
      length: str.length,
      scripts: scripts.length > 0 ? scripts : undefined,
      c2Protocols: c2Protocols.length > 0 ? c2Protocols : undefined,
      decryptionAttempts,
    };
  }

  /**
   * Detect string encoding
   */
  private detectEncoding(str: string): StringEncoding {
    // Check for base64 pattern
    if (this.isBase64(str)) {
      return 'base64';
    }

    // Check for hex pattern
    if (this.isHex(str)) {
      return 'hex';
    }

    // Check for UTF-16 markers
    if (str.charCodeAt(0) === 0xfeff) {
      return 'utf16-be';
    }
    if (str.charCodeAt(0) === 0xfffe) {
      return 'utf16-le';
    }

    // Check if mostly ASCII
    let nonAscii = 0;
    for (let i = 0; i < str.length; i++) {
      if (str.charCodeAt(i) > 127) nonAscii++;
    }

    if (nonAscii === 0) {
      return 'ascii';
    }
    if (nonAscii < str.length * 0.1) {
      return 'utf8';
    }

    return 'unknown';
  }

  /**
   * Calculate Shannon entropy of string
   */
  private calculateEntropy(str: string): number {
    if (str.length === 0) return 0;

    const freqs = new Map<string, number>();
    for (const char of str) {
      freqs.set(char, (freqs.get(char) ?? 0) + 1);
    }

    let entropy = 0;
    for (const count of freqs.values()) {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    }

    return Math.round(entropy * 100) / 100;
  }

  /**
   * Categorize string based on content
   */
  private categorize(str: string): StringCategory {
    // URLs
    if (/^https?:\/\/.+/i.test(str) || /^ftp:\/\/.+/i.test(str)) {
      return 'url';
    }

    // File paths
    if (/^[A-Za-z]:\\|^\/[\w/]+/.test(str)) {
      return 'filepath';
    }

    // Registry keys
    if (/^HK(EY_|LM|CU|CR|U|CC)/i.test(str)) {
      return 'registry';
    }

    // IP addresses
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$/.test(str)) {
      return 'ip';
    }

    // Email addresses
    if (/^[\w.+-]+@[\w.-]+\.\w{2,}$/.test(str)) {
      return 'email';
    }

    // GUIDs
    if (/^[{(]?[0-9a-f]{8}[-]?([0-9a-f]{4}[-]?){3}[0-9a-f]{12}[)}]?$/i.test(str)) {
      return 'guid';
    }

    // API calls
    if (/^[A-Z][a-zA-Z]+[A-Z]\w*$/.test(str) && str.length > 6) {
      return 'api';
    }

    // Commands
    if (/\.(exe|bat|cmd|ps1|sh|py)(\s|$)/i.test(str)) {
      return 'command';
    }

    // Crypto-related (keys, hashes, etc.)
    if (this.isBase64(str) && str.length > 20) {
      return 'crypto';
    }
    if (this.isHex(str) && str.length >= 32) {
      return 'crypto';
    }

    return 'generic';
  }

  /**
   * Check if string matches suspicious patterns
   */
  private checkSuspicious(str: string): { suspicious: boolean; reasons: string[] } {
    const reasons: string[] = [];

    for (const { pattern, reason, severity } of SUSPICIOUS_PATTERNS) {
      if (pattern.test(str)) {
        reasons.push(`[${severity.toUpperCase()}] ${reason}`);
      }
    }

    return {
      suspicious: reasons.length > 0,
      reasons,
    };
  }

  /**
   * Try to decode encoded string
   */
  private tryDecode(str: string, encoding: StringEncoding): string | undefined {
    try {
      switch (encoding) {
        case 'base64': {
          const decoded = Buffer.from(str, 'base64').toString('utf-8');
          // Only return if it looks like valid text
          if (/^[\x20-\x7E\s]+$/.test(decoded)) {
            return decoded;
          }
          break;
        }
        case 'hex': {
          const decoded = Buffer.from(str, 'hex').toString('utf-8');
          if (/^[\x20-\x7E\s]+$/.test(decoded)) {
            return decoded;
          }
          break;
        }
        default:
          break;
      }
    } catch {
      // Decoding failed
    }
    return undefined;
  }

  /**
   * Check if string looks like base64
   */
  private isBase64(str: string): boolean {
    if (str.length < 8 || str.length % 4 !== 0) return false;
    return /^[A-Za-z0-9+/]+=?=?$/.test(str);
  }

  /**
   * Check if string looks like hexadecimal
   */
  private isHex(str: string): boolean {
    if (str.length < 8 || str.length % 2 !== 0) return false;
    return /^[0-9a-fA-F]+$/.test(str);
  }

  /**
   * Detect Unicode scripts present in string
   */
  private detectScripts(str: string): UnicodeScript[] {
    const scriptCounts = new Map<UnicodeScript, number>();

    for (const char of str) {
      const code = char.codePointAt(0);
      if (code === undefined) continue;

      const script = this.getScriptForCodePoint(code);
      if (script !== 'unknown') {
        scriptCounts.set(script, (scriptCounts.get(script) ?? 0) + 1);
      }
    }

    // Return scripts that appear in at least 5% of the string
    const threshold = str.length * 0.05;
    const scripts: UnicodeScript[] = [];

    for (const [script, count] of scriptCounts) {
      if (count >= threshold || count >= 3) {
        scripts.push(script);
      }
    }

    // If multiple scripts detected, mark as mixed
    if (scripts.length > 1) {
      scripts.push('mixed');
    }

    return scripts.length > 0 ? scripts : ['unknown'];
  }

  /**
   * Get Unicode script for a code point
   */
  private getScriptForCodePoint(code: number): UnicodeScript {
    for (const { script, ranges } of UNICODE_SCRIPT_RANGES) {
      for (const [start, end] of ranges) {
        if (code >= start && code <= end) {
          return script;
        }
      }
    }
    return 'unknown';
  }

  /**
   * Detect C2 protocol patterns in string
   */
  private detectC2Protocols(str: string): C2Protocol[] {
    const protocols: C2Protocol[] = [];

    for (const { protocol, patterns, confidence, description } of C2_PROTOCOL_PATTERNS) {
      const matchedIndicators: string[] = [];

      for (const pattern of patterns) {
        const match = str.match(pattern);
        if (match) {
          matchedIndicators.push(match[0]);
        }
      }

      if (matchedIndicators.length > 0) {
        protocols.push({
          protocol,
          confidence,
          evidence: description,
          indicators: matchedIndicators,
        });
      }
    }

    return protocols;
  }

  /**
   * Calculate script breakdown across all analyzed strings
   */
  private calculateScriptBreakdown(strings: AnalyzedString[]): Record<UnicodeScript, number> {
    const breakdown: Record<UnicodeScript, number> = {
      latin: 0,
      cyrillic: 0,
      arabic: 0,
      chinese: 0,
      japanese: 0,
      korean: 0,
      hebrew: 0,
      thai: 0,
      devanagari: 0,
      greek: 0,
      mixed: 0,
      unknown: 0,
    };

    for (const str of strings) {
      if (str.scripts) {
        for (const script of str.scripts) {
          breakdown[script]++;
        }
      }
    }

    return breakdown;
  }

  /**
   * Calculate category breakdown
   */
  private calculateCategoryBreakdown(strings: AnalyzedString[]): Record<StringCategory, number> {
    const breakdown: Record<StringCategory, number> = {
      url: 0,
      filepath: 0,
      registry: 0,
      api: 0,
      command: 0,
      ip: 0,
      email: 0,
      guid: 0,
      crypto: 0,
      generic: 0,
    };

    for (const str of strings) {
      breakdown[str.category]++;
    }

    return breakdown;
  }

  /**
   * Attempt various decryption methods on a string
   */
  private attemptDecryption(str: string): DecryptionAttempt[] {
    const attempts: DecryptionAttempt[] = [];
    const maxAttempts = this.config.maxDecryptionAttempts ?? 5;

    // Try each decryption method
    const methods: Array<() => DecryptionAttempt | null> = [
      () => this.tryXorSingleByte(str),
      () => this.tryRot13(str),
      () => this.tryCaesar(str),
      () => this.tryNestedBase64(str),
      () => this.tryUrlDecode(str),
      () => this.tryXorRolling(str),
    ];

    for (const method of methods) {
      if (attempts.length >= maxAttempts) break;
      try {
        const result = method();
        if (result?.looksValid) {
          attempts.push(result);
        }
      } catch {
        // Decryption method failed, continue to next
      }
    }

    return attempts;
  }

  /**
   * Try single-byte XOR decryption (most common malware obfuscation)
   */
  private tryXorSingleByte(str: string): DecryptionAttempt | null {
    const bytes = Buffer.from(str, 'utf-8');

    // Try common XOR keys
    const commonKeys = [0x00, 0xff, 0x41, 0x42, 0x55, 0xaa, 0x5a, 0xa5];

    for (const key of commonKeys) {
      if (key === 0) continue; // XOR with 0 gives the same string

      const decrypted = Buffer.alloc(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        decrypted[i] = (bytes[i] ?? 0) ^ key;
      }

      const result = decrypted.toString('utf-8');
      if (this.looksLikeValidString(result)) {
        return {
          method: 'xor-single',
          result,
          key: `0x${key.toString(16).padStart(2, '0')}`,
          confidence: this.calculateDecryptionConfidence(result),
          looksValid: true,
        };
      }
    }

    return null;
  }

  /**
   * Try rolling XOR with common patterns
   */
  private tryXorRolling(str: string): DecryptionAttempt | null {
    const bytes = Buffer.from(str, 'utf-8');

    // Try common 4-byte keys
    const commonKeys = [
      [0xde, 0xad, 0xbe, 0xef],
      [0xca, 0xfe, 0xba, 0xbe],
      [0x41, 0x42, 0x43, 0x44],
      [0x12, 0x34, 0x56, 0x78],
    ];

    for (const keyBytes of commonKeys) {
      const decrypted = Buffer.alloc(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        decrypted[i] = (bytes[i] ?? 0) ^ (keyBytes[i % keyBytes.length] ?? 0);
      }

      const result = decrypted.toString('utf-8');
      if (this.looksLikeValidString(result)) {
        return {
          method: 'xor-rolling',
          result,
          key: keyBytes.map((b) => `0x${b.toString(16).padStart(2, '0')}`).join(' '),
          confidence: this.calculateDecryptionConfidence(result),
          looksValid: true,
        };
      }
    }

    return null;
  }

  /**
   * Try ROT13 decryption
   */
  private tryRot13(str: string): DecryptionAttempt | null {
    const result = str.replace(/[a-zA-Z]/g, (char) => {
      const base = char <= 'Z' ? 65 : 97;
      return String.fromCharCode(((char.charCodeAt(0) - base + 13) % 26) + base);
    });

    if (result !== str && this.looksLikeValidString(result)) {
      return {
        method: 'rot13',
        result,
        confidence: this.calculateDecryptionConfidence(result),
        looksValid: true,
      };
    }

    return null;
  }

  /**
   * Try Caesar cipher with common shifts
   */
  private tryCaesar(str: string): DecryptionAttempt | null {
    // Try shifts 1-25 (excluding 13 which is ROT13)
    for (const shift of [1, 2, 3, 5, 7, 11, 23, 25]) {
      const result = str.replace(/[a-zA-Z]/g, (char) => {
        const base = char <= 'Z' ? 65 : 97;
        return String.fromCharCode(((char.charCodeAt(0) - base + shift) % 26) + base);
      });

      if (this.looksLikeValidString(result) && this.hasKnownWords(result)) {
        return {
          method: 'caesar',
          result,
          key: shift,
          confidence: this.calculateDecryptionConfidence(result),
          looksValid: true,
        };
      }
    }

    return null;
  }

  /**
   * Try nested base64 decoding
   */
  private tryNestedBase64(str: string): DecryptionAttempt | null {
    let current = str;
    let depth = 0;
    const maxDepth = 3;

    while (depth < maxDepth && this.isBase64(current)) {
      try {
        const decoded = Buffer.from(current, 'base64').toString('utf-8');
        if (decoded === current || decoded.length === 0) break;

        if (this.looksLikeValidString(decoded) && !this.isBase64(decoded)) {
          return {
            method: 'base64-nested',
            result: decoded,
            key: `depth=${depth + 1}`,
            confidence: this.calculateDecryptionConfidence(decoded),
            looksValid: true,
          };
        }

        current = decoded;
        depth++;
      } catch {
        break;
      }
    }

    return null;
  }

  /**
   * Try URL decoding
   */
  private tryUrlDecode(str: string): DecryptionAttempt | null {
    if (!str.includes('%')) return null;

    try {
      const decoded = decodeURIComponent(str);
      if (decoded !== str && this.looksLikeValidString(decoded)) {
        return {
          method: 'url-decode',
          result: decoded,
          confidence: this.calculateDecryptionConfidence(decoded),
          looksValid: true,
        };
      }
    } catch {
      // Invalid URL encoding
    }

    return null;
  }

  /**
   * Check if decrypted string looks like valid content
   */
  private looksLikeValidString(str: string): boolean {
    // Must be mostly printable ASCII
    const printableCount = (str.match(/[\x20-\x7E]/g) ?? []).length;
    if (printableCount / str.length < 0.8) return false;

    // Should have some word-like patterns
    const wordPattern = /[a-zA-Z]{2,}/g;
    const words = str.match(wordPattern);
    if (!words || words.length < 1) return false;

    // Entropy should be lower than encrypted (natural language ~4.5)
    const entropy = this.calculateEntropy(str);
    return entropy < 5.5;
  }

  /**
   * Check if string contains known English words or malware patterns
   */
  private hasKnownWords(str: string): boolean {
    const lowerStr = str.toLowerCase();
    const knownWords = [
      'http',
      'https',
      'www',
      'cmd',
      'powershell',
      'exec',
      'system',
      'file',
      'path',
      'password',
      'user',
      'admin',
      'root',
      'shell',
      'connect',
      'download',
      'upload',
      'server',
      'client',
      'socket',
      'port',
      'address',
      'key',
      'encrypt',
      'decrypt',
      'the',
      'and',
      'for',
      'from',
      'with',
    ];

    return knownWords.some((word) => lowerStr.includes(word));
  }

  /**
   * Calculate confidence score for decrypted result
   */
  private calculateDecryptionConfidence(str: string): number {
    let confidence = 0.3; // Base confidence

    // Higher confidence if contains known words
    if (this.hasKnownWords(str)) {
      confidence += 0.3;
    }

    // Higher confidence if matches known patterns (URLs, paths, etc.)
    const category = this.categorize(str);
    if (category !== 'generic') {
      confidence += 0.2;
    }

    // Higher confidence if entropy is in natural language range
    const entropy = this.calculateEntropy(str);
    if (entropy >= 3.0 && entropy <= 5.0) {
      confidence += 0.2;
    }

    return Math.min(confidence, 1.0);
  }
}

// ============================================
// SINGLETON INSTANCE
// ============================================

let defaultAnalyzer: StringAnalyzer | null = null;

/**
 * Get or create the default string analyzer instance
 */
export function getStringAnalyzer(config?: Partial<StringAnalyzerConfig>): StringAnalyzer {
  if (!defaultAnalyzer || config) {
    defaultAnalyzer = new StringAnalyzer(config);
  }
  return defaultAnalyzer;
}
