// Risk Levels
export const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

// Recommendations
export const RECOMMENDATIONS = ['IGNORE', 'INVESTIGATE', 'ESCALATE'] as const;
export type Recommendation = (typeof RECOMMENDATIONS)[number];

// File Types
export const FILE_FORMATS = ['PE32', 'PE32+', 'ELF32', 'ELF64', 'UNKNOWN'] as const;
export type FileFormat = (typeof FILE_FORMATS)[number];

// Architectures
export const ARCHITECTURES = ['x86', 'x64', 'ARM', 'ARM64', 'UNKNOWN'] as const;
export type Architecture = (typeof ARCHITECTURES)[number];

// String Types
export const STRING_TYPES = ['ASCII', 'UNICODE', 'UTF8'] as const;
export type StringType = (typeof STRING_TYPES)[number];

// Suspicious Pattern Severities
export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type Severity = (typeof SEVERITIES)[number];

// Sophistication Levels
export const SOPHISTICATION_LEVELS = ['Low', 'Medium', 'Advanced', 'Expert'] as const;
export type SophisticationLevel = (typeof SOPHISTICATION_LEVELS)[number];

// Priority Levels
export const PRIORITY_LEVELS = ['low', 'normal', 'urgent', 'critical'] as const;
export type PriorityLevel = (typeof PRIORITY_LEVELS)[number];

// MITRE ATT&CK Tactics
export const MITRE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
] as const;
export type MitreTactic = (typeof MITRE_TACTICS)[number];

// Tool Names
export const TOOL_NAMES = {
  // Binary Utils
  CALCULATE_HASHES: 'calculate_hashes',
  DETECT_FILE_TYPE: 'detect_file_type',
  EXTRACT_PE_HEADERS: 'extract_pe_headers',
  EXTRACT_ELF_HEADERS: 'extract_elf_headers',
  // Ghidra
  ANALYZE_BINARY: 'analyze_binary',
  EXTRACT_STRINGS: 'extract_strings',
  ANALYZE_FUNCTIONS: 'analyze_functions',
  DETECT_PACKING: 'detect_packing',
  // Reports
  GENERATE_MARKDOWN_REPORT: 'generate_markdown_report',
  GENERATE_JSON_REPORT: 'generate_json_report',
  GENERATE_STIX_REPORT: 'generate_stix_report',
  MAP_TO_MITRE_ATTACK: 'map_to_mitre_attack',
} as const;

export type ToolName = (typeof TOOL_NAMES)[keyof typeof TOOL_NAMES];

// Agent Names
export const AGENT_NAMES = {
  TRIAGE: 'triage_agent',
  ANALYZER: 'analyzer_agent',
  REPORT: 'report_agent',
} as const;

export type AgentName = (typeof AGENT_NAMES)[keyof typeof AGENT_NAMES];

// Hash Algorithms
export const HASH_ALGORITHMS = ['MD5', 'SHA1', 'SHA256', 'SSDEEP'] as const;
export type HashAlgorithm = (typeof HASH_ALGORITHMS)[number];

// Endianness
export const ENDIANNESS = ['LITTLE', 'BIG', 'UNKNOWN'] as const;
export type Endianness = (typeof ENDIANNESS)[number];

// Operating Systems
export const OPERATING_SYSTEMS = ['WINDOWS', 'LINUX', 'MACOS', 'UNKNOWN'] as const;
export type OperatingSystem = (typeof OPERATING_SYSTEMS)[number];

// TLP Markings for STIX
export const TLP_MARKINGS = ['WHITE', 'GREEN', 'AMBER', 'RED'] as const;
export type TlpMarking = (typeof TLP_MARKINGS)[number];

// Confidence Levels
export const CONFIDENCE_LEVELS = ['LOW', 'MEDIUM', 'HIGH'] as const;
export type ConfidenceLevel = (typeof CONFIDENCE_LEVELS)[number];
