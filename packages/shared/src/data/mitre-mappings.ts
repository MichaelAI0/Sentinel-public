/**
 * Centralized MITRE ATT&CK Mappings
 *
 * Single source of truth for all technique definitions and API-to-technique mappings.
 * Used by both analyzer-agent.ts and mitre-mapper.ts.
 *
 * @module mitre-mappings
 */

// ============================================================================
// Technique Definition Type
// ============================================================================

/**
 * MITRE ATT&CK Technique Definition
 */
export type TechniqueDef = {
  /** Technique ID (e.g., T1055, T1055.012) */
  id: string;
  /** Human-readable technique name */
  name: string;
  /** ATT&CK Tactic category */
  tactic: string;
};

// ============================================================================
// Technique Definitions
// ============================================================================

/**
 * Comprehensive MITRE ATT&CK technique definitions
 *
 * Keys are camelCase identifiers for programmatic access.
 * Values contain the official technique ID, name, and tactic.
 */
export const TECHNIQUES = {
  // === Defense Evasion ===
  processInjection: {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
  },
  processHollowing: {
    id: 'T1055.012',
    name: 'Process Hollowing',
    tactic: 'Defense Evasion',
  },
  obfuscatedFiles: {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    tactic: 'Defense Evasion',
  },
  deobfuscateDecode: {
    id: 'T1140',
    name: 'Deobfuscate/Decode Files or Information',
    tactic: 'Defense Evasion',
  },
  sandboxEvasion: {
    id: 'T1497',
    name: 'Virtualization/Sandbox Evasion',
    tactic: 'Defense Evasion',
  },
  systemChecks: {
    id: 'T1497.001',
    name: 'System Checks',
    tactic: 'Defense Evasion',
  },
  timeBasedEvasion: {
    id: 'T1497.003',
    name: 'Time Based Evasion',
    tactic: 'Defense Evasion',
  },
  encryptionForObfuscation: {
    id: 'T1027.011',
    name: 'Encryption/Obfuscation',
    tactic: 'Defense Evasion',
  },

  // === Persistence ===
  runKeys: {
    id: 'T1547.001',
    name: 'Registry Run Keys / Startup Folder',
    tactic: 'Persistence',
  },
  windowsService: {
    id: 'T1543.003',
    name: 'Windows Service',
    tactic: 'Persistence',
  },

  // === Execution ===
  commandInterpreter: {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
  },

  // === Command and Control ===
  webProtocols: {
    id: 'T1071.001',
    name: 'Application Layer Protocol: Web Protocols',
    tactic: 'Command and Control',
  },
  nonAppProtocols: {
    id: 'T1095',
    name: 'Non-Application Layer Protocol',
    tactic: 'Command and Control',
  },
  ingressToolTransfer: {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
  },

  // === Impact ===
  encryptionForImpact: {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
  },

  // === Discovery ===
  processDiscovery: {
    id: 'T1057',
    name: 'Process Discovery',
    tactic: 'Discovery',
  },
  fileDiscovery: {
    id: 'T1083',
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
  },
  systemInfoDiscovery: {
    id: 'T1082',
    name: 'System Information Discovery',
    tactic: 'Discovery',
  },
} as const satisfies Record<string, TechniqueDef>;

// ============================================================================
// API-to-Technique Mappings
// ============================================================================

/**
 * Maps Windows/Linux API function names to MITRE techniques.
 *
 * Used for quick lookups when analyzing function names or imports.
 * Keys are case-sensitive API names.
 */
export const API_TECHNIQUE_MAP: Record<string, TechniqueDef> = {
  // === Process Injection (T1055) ===
  CreateRemoteThread: TECHNIQUES.processInjection,
  VirtualAllocEx: TECHNIQUES.processInjection,
  WriteProcessMemory: TECHNIQUES.processInjection,
  QueueUserAPC: TECHNIQUES.processInjection,
  SetThreadContext: TECHNIQUES.processInjection,

  // === Process Hollowing (T1055.012) ===
  NtUnmapViewOfSection: TECHNIQUES.processHollowing,
  ZwUnmapViewOfSection: TECHNIQUES.processHollowing,

  // === Registry Persistence (T1547.001) ===
  RegSetValue: TECHNIQUES.runKeys,
  RegCreateKey: TECHNIQUES.runKeys,
  RegSetValueEx: TECHNIQUES.runKeys,

  // === Windows Service (T1543.003) ===
  CreateService: TECHNIQUES.windowsService,
  OpenSCManager: TECHNIQUES.windowsService,

  // === Anti-Debug / System Checks (T1497.001) ===
  IsDebuggerPresent: TECHNIQUES.systemChecks,
  CheckRemoteDebuggerPresent: TECHNIQUES.systemChecks,

  // === Time-Based Evasion (T1497.003) ===
  GetTickCount: TECHNIQUES.timeBasedEvasion,
  QueryPerformanceCounter: TECHNIQUES.timeBasedEvasion,
  Sleep: TECHNIQUES.timeBasedEvasion,

  // === Web Protocols (T1071.001) ===
  InternetOpen: TECHNIQUES.webProtocols,
  InternetConnect: TECHNIQUES.webProtocols,
  HttpOpenRequest: TECHNIQUES.webProtocols,
  WinHttpOpen: TECHNIQUES.webProtocols,
  WinHttpSendRequest: TECHNIQUES.webProtocols,

  // === Ingress Tool Transfer (T1105) ===
  URLDownloadToFile: TECHNIQUES.ingressToolTransfer,
  URLDownloadToFileA: TECHNIQUES.ingressToolTransfer,
  URLDownloadToFileW: TECHNIQUES.ingressToolTransfer,

  // === Non-Application Layer Protocol (T1095) ===
  socket: TECHNIQUES.nonAppProtocols,
  connect: TECHNIQUES.nonAppProtocols,
  send: TECHNIQUES.nonAppProtocols,
  recv: TECHNIQUES.nonAppProtocols,

  // === Encryption for Impact (T1486) ===
  CryptEncrypt: TECHNIQUES.encryptionForImpact,

  // === Deobfuscation (T1140) ===
  CryptDecrypt: TECHNIQUES.deobfuscateDecode,
};

// ============================================================================
// Suspicious API Categories (for grouped lookups)
// ============================================================================

/**
 * Suspicious APIs grouped by behavior category.
 *
 * Used for detecting patterns when multiple related APIs are present.
 */
export const SUSPICIOUS_API_GROUPS = {
  injection: [
    'CreateRemoteThread',
    'VirtualAllocEx',
    'WriteProcessMemory',
    'QueueUserAPC',
    'SetThreadContext',
  ],
  hollowing: ['NtUnmapViewOfSection', 'ZwUnmapViewOfSection'],
  persistence: ['RegSetValue', 'RegCreateKey', 'RegSetValueEx', 'CreateService', 'OpenSCManager'],
  networkWeb: [
    'InternetOpen',
    'InternetConnect',
    'HttpOpenRequest',
    'WinHttpOpen',
    'WinHttpSendRequest',
  ],
  networkRaw: ['socket', 'connect', 'send', 'recv'],
  antiDebug: ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'],
  time: ['GetTickCount', 'QueryPerformanceCounter', 'Sleep'],
  crypto: ['CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptAcquireContext'],
  download: ['URLDownloadToFile', 'URLDownloadToFileA', 'URLDownloadToFileW'],
} as const;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Look up a technique by API name (case-insensitive)
 */
export function getTechniqueByAPI(apiName: string): TechniqueDef | undefined {
  // Try exact match first
  if (apiName in API_TECHNIQUE_MAP) {
    return API_TECHNIQUE_MAP[apiName];
  }

  // Try case-insensitive match
  const lowerName = apiName.toLowerCase();
  for (const [key, value] of Object.entries(API_TECHNIQUE_MAP)) {
    if (key.toLowerCase() === lowerName) {
      return value;
    }
  }

  return undefined;
}

/**
 * Get all APIs that map to a specific technique ID
 */
export function getAPIsByTechnique(techniqueId: string): string[] {
  return Object.entries(API_TECHNIQUE_MAP)
    .filter(([_, technique]) => technique.id === techniqueId)
    .map(([api]) => api);
}

/**
 * Check if a function name contains any suspicious API
 */
export function containsSuspiciousAPI(functionName: string): TechniqueDef | undefined {
  const lowerName = functionName.toLowerCase();
  for (const [api, technique] of Object.entries(API_TECHNIQUE_MAP)) {
    if (lowerName.includes(api.toLowerCase())) {
      return technique;
    }
  }
  return undefined;
}

/**
 * Unified set of all suspicious Windows APIs.
 * Consolidates API lists from SUSPICIOUS_API_GROUPS and API_TECHNIQUE_MAP.
 */
export const SUSPICIOUS_APIS = new Set([
  // From API_TECHNIQUE_MAP
  ...Object.keys(API_TECHNIQUE_MAP),
  // Additional from SUSPICIOUS_API_GROUPS
  ...Object.values(SUSPICIOUS_API_GROUPS).flat(),
  // Common variants not in technique map
  'GetProcAddress',
  'LoadLibraryA',
  'LoadLibraryW',
  'LoadLibraryEx',
  'OpenProcess',
  'ReadProcessMemory',
  'WinExec',
  'ShellExecute',
  'ShellExecuteEx',
  'OpenService',
  'StartService',
  'OutputDebugString',
  'CreateFile',
  'WriteFile',
  'DeleteFile',
  'MoveFile',
  'CopyFile',
  'GetSystemDirectory',
  'GetWindowsDirectory',
  'GetTempPath',
]);
