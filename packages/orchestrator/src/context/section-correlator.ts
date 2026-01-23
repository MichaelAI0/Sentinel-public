/**
 * Section Correlator
 * Maps functions to sections and calculates entropy-based scoring enrichment
 *
 * This module provides structural enrichment by:
 * 1. Correlating each function to its containing section
 * 2. Identifying functions near high-entropy sections (potential encrypted/packed code)
 * 3. Calculating entry point distance using BFS on the call graph
 * 4. Assigning behavior clusters based on import patterns
 */

import type { BehaviorCluster, EnrichedFunction, SectionInfo } from './types.js';

/**
 * Raw function data from Ghidra analysis
 */
export type RawFunction = {
  name: string;
  address: string;
  size: number;
  callers: string[];
  callees: string[];
};

/**
 * Raw section data from Ghidra analysis
 */
export type RawSection = {
  name: string;
  virtualAddress: string;
  virtualSize: number;
  rawSize?: number;
  entropy: number;
  permissions: string;
};

/**
 * Import data for behavior clustering
 */
export type ImportInfo = {
  library: string;
  function: string;
  address?: string;
};

/**
 * Behavior cluster definitions based on import patterns
 */
const BEHAVIOR_CLUSTERS: Record<BehaviorCluster, RegExp[]> = {
  'process-injection': [
    /CreateRemoteThread/i,
    /VirtualAllocEx/i,
    /WriteProcessMemory/i,
    /NtUnmapViewOfSection/i,
    /QueueUserAPC/i,
    /NtQueueApcThread/i,
    /RtlCreateUserThread/i,
    /SetWindowsHookEx/i,
    /NtMapViewOfSection/i,
  ],
  'network-c2': [
    /InternetOpen/i,
    /InternetConnect/i,
    /HttpSendRequest/i,
    /URLDownloadToFile/i,
    /WSAStartup/i,
    /socket/i,
    /connect/i,
    /send/i,
    /recv/i,
    /WinHttpOpen/i,
    /WinHttpConnect/i,
    /getaddrinfo/i,
  ],
  'file-crypto': [
    /CryptEncrypt/i,
    /CryptDecrypt/i,
    /CryptAcquireContext/i,
    /CryptGenKey/i,
    /CryptDeriveKey/i,
    /BCryptEncrypt/i,
    /BCryptDecrypt/i,
    /CreateFile.*Write/i,
    /WriteFile/i,
    /ReadFile/i,
  ],
  persistence: [
    /RegSetValueEx/i,
    /RegCreateKeyEx/i,
    /CreateService/i,
    /StartService/i,
    /ChangeServiceConfig/i,
    /schtasks/i,
    /at\.exe/i,
    /WritePrivateProfile/i,
  ],
  'anti-analysis': [
    /IsDebuggerPresent/i,
    /CheckRemoteDebuggerPresent/i,
    /NtQueryInformationProcess/i,
    /GetTickCount/i,
    /QueryPerformanceCounter/i,
    /OutputDebugString/i,
    /FindWindow.*Olly|IDA|x64dbg/i,
    /NtSetInformationThread/i,
  ],
  'credential-access': [
    /CredRead/i,
    /CredEnum/i,
    /LsaRetrievePrivateData/i,
    /CryptUnprotectData/i,
    /NetUserEnum/i,
    /SamConnect/i,
    /MiniDumpWriteDump/i,
  ],
  discovery: [
    /GetComputerName/i,
    /GetUserName/i,
    /GetSystemInfo/i,
    /NetShareEnum/i,
    /NetServerEnum/i,
    /Process32First/i,
    /CreateToolhelp32Snapshot/i,
    /FindFirstFile/i,
    /RegEnumKeyEx/i,
  ],
  execution: [
    /CreateProcess/i,
    /ShellExecute/i,
    /WinExec/i,
    /execve/i,
    /fork/i,
    /system/i,
    /popen/i,
    /LoadLibrary/i,
    /GetProcAddress/i,
  ],
  'defense-evasion': [
    /VirtualProtect/i,
    /NtProtectVirtualMemory/i,
    /DeleteFile/i,
    /MoveFile/i,
    /SetFileAttributes.*Hidden/i,
    /NtCreateSection/i,
    /ZwUnmapViewOfSection/i,
  ],
  unknown: [],
};

/**
 * High entropy threshold for section scoring
 */
const HIGH_ENTROPY_THRESHOLD = 7.0;

/**
 * Medium entropy threshold
 */
const MEDIUM_ENTROPY_THRESHOLD = 6.0;

/**
 * Parse hex address string to number
 */
function parseAddress(addr: string): number {
  const cleaned = addr.replace(/^0x/i, '');
  return parseInt(cleaned, 16);
}

/**
 * Check if an address falls within a section's range
 */
function isAddressInSection(address: number, section: RawSection): boolean {
  const sectionStart = parseAddress(section.virtualAddress);
  const sectionEnd = sectionStart + section.virtualSize;
  return address >= sectionStart && address < sectionEnd;
}

/**
 * Find the section containing a given address
 */
function findContainingSection(address: string, sections: RawSection[]): SectionInfo | undefined {
  const addrNum = parseAddress(address);

  for (const section of sections) {
    if (isAddressInSection(addrNum, section)) {
      return {
        name: section.name,
        virtualAddress: section.virtualAddress,
        virtualSize: section.virtualSize,
        entropy: section.entropy,
        permissions: section.permissions,
      };
    }
  }

  return undefined;
}

/**
 * Check if a function is near (within 1 section of) a high-entropy section
 */
function isNearHighEntropySection(functionAddress: string, sections: RawSection[]): boolean {
  const addrNum = parseAddress(functionAddress);

  // Sort sections by address
  const sortedSections = [...sections].sort(
    (a, b) => parseAddress(a.virtualAddress) - parseAddress(b.virtualAddress),
  );

  // Find the function's section index
  let functionSectionIdx = -1;
  for (let i = 0; i < sortedSections.length; i++) {
    const section = sortedSections[i];
    if (section && isAddressInSection(addrNum, section)) {
      functionSectionIdx = i;
      break;
    }
  }

  if (functionSectionIdx === -1) return false;

  // Check adjacent sections for high entropy
  const checkIndices = [functionSectionIdx - 1, functionSectionIdx, functionSectionIdx + 1];

  for (const idx of checkIndices) {
    if (idx >= 0 && idx < sortedSections.length) {
      const section = sortedSections[idx];
      if (section && section.entropy >= HIGH_ENTROPY_THRESHOLD) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Find the entry point address from known entry point function names
 */
function findEntryPointByName(functions: RawFunction[]): string | undefined {
  const entryNames = ['entry', '_start', 'main', 'WinMain', 'DllMain', '_main', 'start'];
  for (const func of functions) {
    if (entryNames.some((name) => func.name.toLowerCase() === name.toLowerCase())) {
      return func.address;
    }
  }
  return undefined;
}

/**
 * Run BFS to calculate distances from entry point to all reachable functions
 */
function bfsFromEntryPoint(
  entryAddr: string,
  addressToFunction: Map<string, RawFunction>,
): Map<string, number> {
  const distances = new Map<string, number>();
  const queue: Array<{ address: string; distance: number }> = [{ address: entryAddr, distance: 0 }];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) break;

    if (visited.has(current.address)) continue;
    visited.add(current.address);

    distances.set(current.address, current.distance);

    const func = addressToFunction.get(current.address);
    if (!func) continue;

    // Add callees to queue
    for (const calleeAddr of func.callees) {
      if (!visited.has(calleeAddr)) {
        queue.push({ address: calleeAddr, distance: current.distance + 1 });
      }
    }
  }

  return distances;
}

/**
 * Calculate entry point distance using BFS on call graph
 * Returns -1 if function is not reachable from entry point
 */
function calculateEntryPointDistances(
  functions: RawFunction[],
  entryPointAddress?: string,
): Map<string, number> {
  // Build address to function map
  const addressToFunction = new Map<string, RawFunction>();
  for (const func of functions) {
    addressToFunction.set(func.address, func);
  }

  // Determine entry point address
  let entryAddr = entryPointAddress;
  if (!entryAddr) {
    entryAddr = findEntryPointByName(functions);
  }

  // If still no entry point, use the first function
  if (!entryAddr && functions.length > 0) {
    const firstFunc = functions[0];
    if (firstFunc) {
      entryAddr = firstFunc.address;
    }
  }

  // No entry point found, all functions are unreachable
  if (!entryAddr) {
    const distances = new Map<string, number>();
    for (const func of functions) {
      distances.set(func.address, -1);
    }
    return distances;
  }

  // Run BFS from entry point
  const distances = bfsFromEntryPoint(entryAddr, addressToFunction);

  // Mark unreachable functions
  for (const func of functions) {
    if (!distances.has(func.address)) {
      distances.set(func.address, -1);
    }
  }

  return distances;
}

/**
 * Determine behavior cluster for a function based on its callees and imports
 */
function determineBehaviorCluster(
  func: RawFunction,
  imports: ImportInfo[],
  addressToFunction: Map<string, RawFunction>,
): BehaviorCluster | undefined {
  // Collect all function names that this function calls
  const calledFunctions: string[] = [];

  for (const calleeAddr of func.callees) {
    const callee = addressToFunction.get(calleeAddr);
    if (callee) {
      calledFunctions.push(callee.name);
    }
  }

  // Also check imports
  const importFunctions = imports.map((i) => i.function);

  const allFunctions = [...calledFunctions, ...importFunctions];
  const functionText = allFunctions.join(' ');

  // Count matches for each cluster
  const clusterScores: Record<BehaviorCluster, number> = {
    'process-injection': 0,
    'network-c2': 0,
    'file-crypto': 0,
    persistence: 0,
    'anti-analysis': 0,
    'credential-access': 0,
    discovery: 0,
    execution: 0,
    'defense-evasion': 0,
    unknown: 0,
  };

  for (const [cluster, patterns] of Object.entries(BEHAVIOR_CLUSTERS)) {
    for (const pattern of patterns) {
      if (pattern.test(functionText)) {
        clusterScores[cluster as BehaviorCluster]++;
      }
    }
  }

  // Find highest scoring cluster
  let maxScore = 0;
  let bestCluster: BehaviorCluster = 'unknown';

  for (const [cluster, score] of Object.entries(clusterScores)) {
    if (score > maxScore) {
      maxScore = score;
      bestCluster = cluster as BehaviorCluster;
    }
  }

  return maxScore > 0 ? bestCluster : undefined;
}

/**
 * Enrich functions with section correlation, entry distance, and behavior clusters
 */
export function enrichFunctions(
  functions: RawFunction[],
  sections: RawSection[],
  imports: ImportInfo[],
  entryPointAddress?: string,
): EnrichedFunction[] {
  // Calculate entry point distances
  const distances = calculateEntryPointDistances(functions, entryPointAddress);

  // Build address to function map
  const addressToFunction = new Map<string, RawFunction>();
  for (const func of functions) {
    addressToFunction.set(func.address, func);
  }

  // Enrich each function
  return functions.map((func) => {
    const section = findContainingSection(func.address, sections);
    const entryPointDistance = distances.get(func.address) ?? -1;
    const behaviorCluster = determineBehaviorCluster(func, imports, addressToFunction);

    return {
      address: func.address,
      name: func.name,
      size: func.size,
      callers: func.callers,
      callees: func.callees,
      section,
      entryPointDistance,
      isEntryReachable: entryPointDistance >= 0,
      behaviorCluster,
    };
  });
}

/**
 * Calculate section entropy score for a function
 * Returns 0 if function is not in a section, otherwise returns normalized section entropy
 */
export function getSectionEntropyScore(enrichedFunc: EnrichedFunction): number {
  if (!enrichedFunc.section) return 0;

  const entropy = enrichedFunc.section.entropy;

  if (entropy >= HIGH_ENTROPY_THRESHOLD) {
    return 1.0; // Maximum score for high entropy
  }

  if (entropy >= MEDIUM_ENTROPY_THRESHOLD) {
    return 0.6; // Medium score
  }

  return 0.3; // Low score for normal entropy
}

/**
 * Calculate entry point distance score
 * Returns higher scores for functions closer to entry point
 */
export function getEntryDistanceScore(enrichedFunc: EnrichedFunction): number {
  const distance = enrichedFunc.entryPointDistance;

  if (distance < 0) {
    return 0; // Unreachable
  }

  if (distance === 0) {
    return 1.0; // Entry point itself
  }

  if (distance <= 2) {
    return 0.8; // Very close to entry
  }

  if (distance <= 5) {
    return 0.5; // Moderately close
  }

  if (distance <= 10) {
    return 0.3; // Further away
  }

  return 0.1; // Very far
}

/**
 * Get behavior cluster priority boost
 * High-risk clusters get higher boost
 */
export function getBehaviorClusterBoost(cluster: BehaviorCluster | undefined): number {
  if (!cluster) return 0;

  const boosts: Record<BehaviorCluster, number> = {
    'process-injection': 25,
    'network-c2': 20,
    'file-crypto': 18,
    'credential-access': 18,
    'anti-analysis': 15,
    persistence: 15,
    'defense-evasion': 12,
    execution: 10,
    discovery: 5,
    unknown: 0,
  };

  return boosts[cluster] ?? 0;
}

/**
 * Check if function is near high-entropy section
 */
export function checkNearHighEntropy(functionAddress: string, sections: RawSection[]): boolean {
  return isNearHighEntropySection(functionAddress, sections);
}

/**
 * Export entropy thresholds for use elsewhere
 */
export const ENTROPY_THRESHOLDS = {
  HIGH: HIGH_ENTROPY_THRESHOLD,
  MEDIUM: MEDIUM_ENTROPY_THRESHOLD,
};
