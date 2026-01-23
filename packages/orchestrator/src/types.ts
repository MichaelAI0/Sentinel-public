/**
 * SENTINEL Agent Types
 * Shared type definitions for the multi-agent orchestration system
 */

/**
 * Risk levels for binary analysis
 */
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * Recommendations from triage agent
 */
export type TriageRecommendation = 'IGNORE' | 'INVESTIGATE' | 'ESCALATE';

/**
 * Triage agent results - fast initial assessment
 *
 * @todo Phase 3: Add dynamic analysis results (sandbox execution)
 * @todo Phase 4: Add VirusTotal/threat intel correlation
 */
export type TriageResults = {
  /** File type identification (PE32, ELF64, etc.) */
  fileType: string;
  /** SHA256 hash of the binary */
  sha256: string;
  /** MD5 hash for legacy system compatibility */
  md5: string;
  /** Overall entropy (0-8 scale, >7 indicates packing) */
  entropy: number;
  /** Assigned risk level */
  riskLevel: RiskLevel;
  /** Confidence in the risk assessment (0-1) */
  confidence: number;
  /** Suspicious strings extracted (IPs, URLs, etc.) */
  suspiciousStrings: string[];
  /** Suspicious API imports detected */
  suspiciousImports: string[];
  /** Whether packing was detected */
  isPacked: boolean;
  /** Detected packer name if identified */
  packerName?: string;
  /** Recommendation for next steps */
  recommendation: TriageRecommendation;
  /** LLM's reasoning for the decision */
  reasoning: string;
  /** Estimated time for deep analysis */
  estimatedAnalysisTime?: string;
};

/**
 * Call graph edge representing a function call relationship
 */
export type CallGraphEdge = {
  /** Target function address or name */
  target: string;
  /** Call site address within the caller function */
  callSiteAddress?: string;
  /** Type of call (direct, indirect, virtual, etc.) */
  callType: 'direct' | 'indirect' | 'virtual' | 'thunk' | 'computed';
  /** Whether this is a recursive call */
  isRecursive?: boolean;
};

/**
 * Decompiled pseudocode summary for a function
 */
export type DecompiledSummary = {
  /** Short natural language summary of what the function does */
  summary: string;
  /** Key operations identified (e.g., "file I/O", "network", "crypto") */
  operations: string[];
  /** Local variables of interest */
  keyVariables?: Array<{
    name: string;
    type?: string;
    purpose?: string;
  }>;
  /** Control flow characteristics */
  controlFlow?: {
    hasLoops: boolean;
    hasConditionals: boolean;
    hasExceptionHandling: boolean;
    estimatedPaths: number;
  };
  /** Confidence in decompilation quality (0-1) */
  confidence: number;
};

/**
 * Function information from Ghidra analysis
 */
export type FunctionInfo = {
  /** Function name (may be auto-generated) */
  name: string;
  /** Memory address */
  address: string;
  /** Function description if identified */
  description?: string;
  /** MITRE ATT&CK techniques associated */
  techniques?: string[];
  /** Whether this is a suspicious function */
  isSuspicious: boolean;
  /** Functions called by this function (call graph edges) */
  calls?: CallGraphEdge[];
  /** Functions that call this function (reverse call graph) */
  calledBy?: string[];
  /** Estimated cyclomatic complexity */
  complexity?: number;
  /** Decompiled pseudocode summary */
  decompiledSummary?: DecompiledSummary;
  /** Raw decompiled code (if available and requested) */
  decompiledCode?: string;
};

/**
 * Import table entry
 */
export type ImportEntry = {
  /** DLL/library name */
  library: string;
  /** Imported function name */
  function: string;
  /** Whether this import is suspicious */
  isSuspicious: boolean;
};

/**
 * IP address with optional geolocation data
 */
export type IpAddressInfo = {
  /** IP address (v4 or v6) */
  address: string;
  /** IP version */
  version: 4 | 6;
  /** Country code (ISO 3166-1 alpha-2) */
  countryCode?: string;
  /** Country name */
  country?: string;
  /** City name */
  city?: string;
  /** Autonomous System Number */
  asn?: number;
  /** Organization/ISP name */
  organization?: string;
  /** Whether this IP is a known Tor exit node */
  isTorExitNode?: boolean;
  /** Whether this IP is from a known VPN provider */
  isVpn?: boolean;
  /** Whether this IP is from a known hosting/datacenter */
  isHosting?: boolean;
};

/**
 * Indicators of Compromise
 *
 * @todo Phase 4: Add threat intelligence enrichment (reputation scores)
 */
export type IOCs = {
  /** IP addresses (v4 and v6) - simple string format for backwards compatibility */
  ipAddresses: string[];
  /** IP addresses with geolocation data */
  ipAddressesEnriched?: IpAddressInfo[];
  /** Domain names */
  domains: string[];
  /** URLs */
  urls: string[];
  /** File paths */
  filePaths: string[];
  /** Registry keys (Windows) */
  registryKeys: string[];
  /** Mutex names */
  mutexes: string[];
  /** Encryption keys if extracted */
  encryptionKeys?: string[];
};

/**
 * MITRE ATT&CK technique mapping with sub-technique support
 *
 * @todo Phase 4: Add mitigation recommendations
 */
export type MitreTechnique = {
  /** Technique ID (e.g., T1055 for parent, T1055.002 for sub-technique) */
  id: string;
  /** Technique name */
  name: string;
  /** Tactic category (e.g., 'execution', 'persistence') */
  tactic: string;
  /** Evidence/reason for mapping */
  evidence: string[];
  /** Confidence in mapping (0-1) */
  confidence: number;
  /** Parent technique ID if this is a sub-technique */
  parentTechniqueId?: string;
  /** Sub-technique IDs if this is a parent technique */
  subTechniques?: string[];
  /** Full technique path (tactic > technique > sub-technique) */
  path?: string;
  /** MITRE ATT&CK Matrix (enterprise, mobile, ics) */
  matrix?: 'enterprise' | 'mobile' | 'ics';
  /** Data sources that can detect this technique */
  dataSources?: string[];
};

// ============================================================================
// Phase 2: Enhanced Analysis Types
// ============================================================================

// ============================================================================
// Phase 3: Dynamic Analysis Types
// ============================================================================

/**
 * Process behavior captured during dynamic analysis
 */
export type ProcessBehavior = {
  /** Process ID */
  pid: number;
  /** Process name */
  name: string;
  /** Parent process ID */
  parentPid?: number;
  /** Command line arguments */
  commandLine?: string;
  /** Start timestamp */
  startTime: string;
  /** End timestamp (if terminated) */
  endTime?: string;
  /** Exit code (if terminated) */
  exitCode?: number;
  /** Child processes spawned */
  childProcesses?: ProcessBehavior[];
};

/**
 * File system operation captured during dynamic analysis
 */
export type FileSystemOperation = {
  /** Operation type */
  operation: 'create' | 'read' | 'write' | 'delete' | 'rename' | 'move' | 'chmod';
  /** File path */
  path: string;
  /** New path (for rename/move) */
  newPath?: string;
  /** Timestamp */
  timestamp: string;
  /** Process that performed operation */
  processPid: number;
  /** Data written (if small and captured) */
  data?: string;
  /** File size affected */
  size?: number;
};

/**
 * Registry operation captured during dynamic analysis (Windows)
 */
export type RegistryOperation = {
  /** Operation type */
  operation: 'create' | 'set' | 'delete' | 'query';
  /** Registry key path */
  keyPath: string;
  /** Value name */
  valueName?: string;
  /** Value data */
  valueData?: string;
  /** Value type (REG_SZ, REG_DWORD, etc.) */
  valueType?: string;
  /** Timestamp */
  timestamp: string;
  /** Process that performed operation */
  processPid: number;
};

/**
 * Network connection captured during dynamic analysis
 */
export type NetworkConnection = {
  /** Protocol */
  protocol: 'tcp' | 'udp' | 'icmp' | 'dns' | 'http' | 'https' | 'other';
  /** Local address */
  localAddress?: string;
  /** Local port */
  localPort?: number;
  /** Remote address */
  remoteAddress: string;
  /** Remote port */
  remotePort?: number;
  /** DNS query if DNS request */
  dnsQuery?: string;
  /** DNS response if DNS request */
  dnsResponse?: string[];
  /** HTTP request details if HTTP/S */
  httpRequest?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  /** HTTP response details if HTTP/S */
  httpResponse?: {
    statusCode: number;
    headers?: Record<string, string>;
    bodyPreview?: string;
  };
  /** Bytes sent */
  bytesSent?: number;
  /** Bytes received */
  bytesReceived?: number;
  /** Timestamp */
  timestamp: string;
  /** Process that initiated connection */
  processPid: number;
};

/**
 * API call captured during dynamic analysis
 */
export type ApiCall = {
  /** API function name */
  function: string;
  /** Module/library containing the function */
  module: string;
  /** Arguments passed */
  arguments: Array<{
    name?: string;
    value: string;
    type?: string;
  }>;
  /** Return value */
  returnValue?: string;
  /** Timestamp */
  timestamp: string;
  /** Process that made the call */
  processPid: number;
  /** Thread ID */
  threadId?: number;
  /** Whether call succeeded */
  success: boolean;
  /** MITRE technique if applicable */
  mitreTechnique?: string;
};

/**
 * Memory operation captured during dynamic analysis
 */
export type MemoryOperation = {
  /** Operation type */
  operation: 'allocate' | 'free' | 'protect' | 'read' | 'write' | 'map';
  /** Base address */
  address: string;
  /** Size in bytes */
  size: number;
  /** Memory protection flags */
  protection?: string;
  /** Target process (for cross-process operations) */
  targetPid?: number;
  /** Timestamp */
  timestamp: string;
  /** Process that performed operation */
  processPid: number;
  /** Injected code detected */
  injectedCode?: boolean;
};

/**
 * Complete dynamic analysis results
 */
export type DynamicAnalysisResults = {
  /** Sandbox/analysis environment used */
  environment: {
    sandbox: string;
    os: string;
    architecture: string;
    analysisTime: number; // seconds
  };
  /** Sample execution info */
  execution: {
    entryProcess: ProcessBehavior;
    totalProcesses: number;
    totalApiCalls: number;
    totalNetworkConnections: number;
    exitReason: 'timeout' | 'terminated' | 'completed' | 'error';
  };
  /** Process tree */
  processes: ProcessBehavior[];
  /** File system operations */
  fileOperations: FileSystemOperation[];
  /** Registry operations (Windows) */
  registryOperations: RegistryOperation[];
  /** Network activity */
  networkConnections: NetworkConnection[];
  /** API calls (may be sampled for high-volume) */
  apiCalls: ApiCall[];
  /** Memory operations of interest */
  memoryOperations: MemoryOperation[];
  /** Dropped/created files */
  droppedFiles: Array<{
    path: string;
    size: number;
    md5?: string;
    sha256?: string;
    type?: string;
  }>;
  /** Screenshots captured */
  screenshots?: Array<{
    timestamp: string;
    path: string;
  }>;
  /** Overall behavior score (0-100) */
  behaviorScore: number;
  /** Behavior classifications */
  classifications: string[];
  /** Detected evasion techniques */
  evasionTechniques: string[];
};

/**
 * YARA rule match result
 */
export type YaraMatch = {
  /** Rule name that matched */
  ruleName: string;
  /** Rule tags (e.g., 'malware', 'trojan') */
  tags: string[];
  /** Matched strings with offsets */
  matches: Array<{
    identifier: string;
    offset: number;
    data?: string;
  }>;
  /** Rule metadata if available */
  metadata?: Record<string, string | number | boolean>;
};

/**
 * Crypto detection result
 */
export type CryptoFinding = {
  /** Algorithm name (e.g., 'AES-256', 'MD5', 'RC4') */
  algorithm: string;
  /** Type of detection (constants, operations, custom) */
  type: 'constants' | 'operations' | 'xor' | 'custom';
  /** Confidence score 0-1 */
  confidence: number;
  /** Memory offset or address where detected */
  offset?: number;
  /** Additional evidence/details */
  evidence: string;
};

/**
 * Assembly pattern detection result
 */
export type AssemblyPattern = {
  /** Pattern category */
  category: 'syscall' | 'anti-debug' | 'crypto' | 'packing' | 'shellcode';
  /** Pattern name or description */
  name: string;
  /** Instructions that matched */
  instructions: string[];
  /** Memory address of pattern */
  address?: string;
  /** Associated MITRE technique if applicable */
  technique?: string;
};

/**
 * Enhanced string analysis result
 */
export type EnhancedString = {
  /** The string value */
  value: string;
  /** Detected encoding (utf8, ascii, unicode, base64) */
  encoding: string;
  /** Semantic category (url, ip, path, command, etc.) */
  category: string;
  /** Entropy score (0-8) */
  entropy: number;
  /** Whether flagged as suspicious */
  isSuspicious: boolean;
  /** Reason for suspicion if applicable */
  suspicionReason?: string;
};

/**
 * Deep analyzer agent results
 *
 * @todo Phase 4: Add ML-based classification scores
 */
export type AnalysisResults = {
  /** All identified functions */
  functions: FunctionInfo[];
  /** Import table */
  imports: ImportEntry[];
  /** Export table */
  exports: string[];
  /** Extracted IOCs */
  iocs: IOCs;
  /** MITRE ATT&CK mappings */
  mitreTechniques: MitreTechnique[];
  /** Detected malware family if matched */
  malwareFamily?: string;
  /** Confidence in family match */
  familyConfidence?: number;
  /** Identified capabilities */
  capabilities: string[];
  /** Detected anti-analysis techniques */
  antiAnalysis: string[];
  /** Sophistication level assessment */
  sophistication: 'Basic' | 'Intermediate' | 'Advanced' | 'Expert';
  /** Key findings summary */
  keyFindings: string[];
  /** Technical analysis notes from LLM */
  technicalNotes: string;

  // === Phase 2: Enhanced Analysis Fields ===
  /** YARA rule matches */
  yaraMatches?: YaraMatch[];
  /** Detected cryptographic operations */
  cryptoFindings?: CryptoFinding[];
  /** Suspicious assembly patterns */
  assemblyPatterns?: AssemblyPattern[];
  /** Enhanced string analysis results */
  enhancedStrings?: EnhancedString[];
  /** Whether binary was unpacked for analysis */
  wasUnpacked?: boolean;
  /** Original packer if detected and unpacked */
  originalPacker?: string;

  // === Phase 3: Advanced Analysis Fields ===
  /** Control flow graph data */
  cfgData?: {
    functionCFGs: Array<{
      functionName: string;
      functionAddress: string;
      basicBlocks: Array<{
        id: string;
        startAddress: string;
        instructionCount: number;
        isEntryBlock: boolean;
        isExitBlock: boolean;
      }>;
      edges: Array<{
        fromBlock: string;
        toBlock: string;
        edgeType: string;
      }>;
      mermaidDiagram?: string;
    }>;
    totalBlocks: number;
    totalEdges: number;
  };
  /** Ghidra-detected cryptographic constants */
  ghidraCrypto?: Array<{
    algorithm: string;
    type: string;
    address: string;
    confidence: number;
    nearbyFunctions: string[];
  }>;
  /** API/import call mapping */
  apiCallMapping?: {
    imports: Array<{
      library: string;
      functionName: string;
      calledBy: string[];
    }>;
    libraryGroups?: Array<{
      libraryName: string;
      functionCount: number;
      functions: string[];
    }>;
  };
  /** Multi-model specialist analysis findings */
  specialistFindings?: string[];
  /** Overall assessment from synthesis model */
  overallAssessment?: string;
  /** Malware likelihood from multi-model analysis (0-1) */
  malwareLikelihood?: number;
  /** Behavioral analysis hints */
  behaviorHints?: Array<{
    behavior: string;
    confidence: number;
    reasoning: string;
    risks: string[];
    relatedTechniques: string[];
  }>;
  /** Dynamic analysis results from sandbox execution */
  dynamicAnalysis?: DynamicAnalysisResults;
  /** Behavioral indicators from execution traces */
  behavioralIndicators?: Array<{
    indicator: string;
    category:
      | 'persistence'
      | 'defense-evasion'
      | 'discovery'
      | 'collection'
      | 'exfiltration'
      | 'c2'
      | 'execution';
    severity: 'high' | 'medium' | 'low';
    evidence: string[];
  }>;
};

/**
 * Report output paths
 *
 * @todo Phase 4: Add PDF export path
 * @todo Phase 4: Add MISP event export path
 */
export type ReportPaths = {
  /** Path to Markdown report */
  markdown: string;
  /** Path to JSON report */
  json: string;
  /** Path to STIX 2.1 bundle */
  stix: string;
};

/**
 * Complete analysis state - shared across all agents via LangGraph
 *
 * @todo Phase 3: Add sandbox execution state
 * @todo Phase 4: Add multi-sample correlation state
 */
export type AnalysisState = {
  // === Input ===
  /** Path to the binary file */
  binaryPath: string;
  /** Original filename */
  filename: string;

  // === Triage Phase ===
  /** Results from triage agent */
  triageResults: TriageResults | null;
  /** Whether triage is complete */
  triageComplete: boolean;

  // === Analysis Phase ===
  /** Results from deep analyzer agent */
  analysisResults: AnalysisResults | null;
  /** Whether analysis is complete */
  analysisComplete: boolean;

  // === Report Phase ===
  /** Generated report paths */
  reportPaths: ReportPaths | null;
  /** Whether reports are generated */
  reportsComplete: boolean;

  // === Metadata ===
  /** Workflow start time */
  startTime: Date;
  /** Workflow end time */
  endTime?: Date;
  /** Any errors encountered */
  errors: string[];
  /** Current workflow status */
  status: 'pending' | 'triaging' | 'analyzing' | 'reporting' | 'complete' | 'failed';
};

/**
 * MCP tool call result
 */
export type ToolResult<T = unknown> = {
  success: boolean;
  data?: T;
  error?: string;
};

/**
 * Agent configuration
 *
 * @todo Phase 3: Add memory/context limit configuration
 * @todo Phase 4: Add model-specific tuning parameters
 */
export type AgentConfig = {
  /** LLM temperature (0 = deterministic) */
  temperature: number;
  /** Maximum tokens for response */
  maxTokens: number;
  /** System prompt for the agent */
  systemPrompt: string;
  /** Available tool names */
  tools: string[];
};

/**
 * Ollama configuration
 *
 * @todo Phase 4: Add multi-model fallback configuration
 * @todo Phase 4: Add GPU acceleration settings
 */
export type OllamaConfig = {
  /** Base URL for Ollama API */
  baseUrl: string;
  /** Model to use (e.g., llama3.2, codellama) */
  model: string;
  /** Request timeout in ms */
  timeout: number;
};
