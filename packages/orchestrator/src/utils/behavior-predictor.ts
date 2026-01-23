/**
 * Behavior Predictor
 * Heuristic-based behavior prediction from static analysis patterns
 *
 * @module utils/behavior-predictor
 */

import type { AnalysisResults, MitreTechnique } from '../types.js';

export type BehaviorHint = {
  /** Predicted behavior name */
  behavior: string;
  /** Confidence score (0-1) */
  confidence: number;
  /** Reasoning for prediction */
  reasoning: string;
  /** Potential risks if behavior executes */
  risks: string[];
  /** Related MITRE ATT&CK technique IDs */
  relatedTechniques: string[];
};

type PatternMatcher = (analysis: AnalysisResults) => boolean;

type BehaviorRule = {
  behavior: string;
  baseConfidence: number;
  reasoning: string;
  risks: string[];
  relatedTechniques: string[];
  matchers: PatternMatcher[];
};

const BEHAVIOR_RULES: BehaviorRule[] = [
  {
    behavior: 'Persistence via Registry Modification',
    baseConfidence: 0.7,
    reasoning: 'Registry manipulation APIs or keys detected',
    risks: ['Survives system reboot', 'Hidden startup entry', 'Difficult to remove'],
    relatedTechniques: ['T1547.001', 'T1112'],
    matchers: [hasRegistryStrings, hasRegistryImports],
  },
  {
    behavior: 'Command & Control Communication',
    baseConfidence: 0.65,
    reasoning: 'Network communication indicators found',
    risks: ['Data exfiltration', 'Remote command execution', 'Malware updates'],
    relatedTechniques: ['T1071.001', 'T1095', 'T1573'],
    matchers: [hasNetworkStrings, hasNetworkImports, hasUrlsOrDomains],
  },
  {
    behavior: 'Process Injection',
    baseConfidence: 0.8,
    reasoning: 'Process manipulation APIs detected',
    risks: ['Code execution in trusted process', 'Defense evasion', 'Privilege escalation'],
    relatedTechniques: ['T1055', 'T1055.001', 'T1055.012'],
    matchers: [hasInjectionImports],
  },
  {
    behavior: 'Credential Theft',
    baseConfidence: 0.75,
    reasoning: 'Credential access patterns detected',
    risks: ['Account compromise', 'Lateral movement', 'Identity theft'],
    relatedTechniques: ['T1003', 'T1555', 'T1552'],
    matchers: [hasCredentialStrings, hasCredentialImports],
  },
  {
    behavior: 'File System Manipulation',
    baseConfidence: 0.5,
    reasoning: 'File operations with suspicious patterns',
    risks: ['Data destruction', 'Ransomware encryption', 'Evidence tampering'],
    relatedTechniques: ['T1486', 'T1485', 'T1070.004'],
    matchers: [hasFileManipulationStrings, hasCryptoWithFileOps],
  },
  {
    behavior: 'Anti-Analysis / Evasion',
    baseConfidence: 0.7,
    reasoning: 'Sandbox/debugger evasion techniques detected',
    risks: ['Delayed execution', 'Analysis obstruction', 'Environment fingerprinting'],
    relatedTechniques: ['T1497', 'T1497.001', 'T1622'],
    matchers: [hasAntiDebugImports, hasVirtualizationStrings, hasTimingChecks],
  },
  {
    behavior: 'Keylogging / Input Capture',
    baseConfidence: 0.75,
    reasoning: 'Input monitoring APIs detected',
    risks: ['Credential capture', 'Privacy violation', 'Sensitive data theft'],
    relatedTechniques: ['T1056.001', 'T1056'],
    matchers: [hasKeyloggerImports],
  },
  {
    behavior: 'Screen Capture',
    baseConfidence: 0.7,
    reasoning: 'Screen/window capture APIs detected',
    risks: ['Information disclosure', 'Privacy violation', 'Credential theft'],
    relatedTechniques: ['T1113'],
    matchers: [hasScreenCaptureImports],
  },
  {
    behavior: 'Service Installation',
    baseConfidence: 0.65,
    reasoning: 'Windows service manipulation detected',
    risks: ['System-level persistence', 'Privilege escalation', 'Stealth execution'],
    relatedTechniques: ['T1543.003', 'T1569.002'],
    matchers: [hasServiceImports],
  },
  {
    behavior: 'Scheduled Task Creation',
    baseConfidence: 0.6,
    reasoning: 'Task scheduler interaction detected',
    risks: ['Timed execution', 'Persistence', 'Delayed payload'],
    relatedTechniques: ['T1053.005'],
    matchers: [hasScheduledTaskStrings],
  },
];

function matchesAnyString(analysis: AnalysisResults, patterns: RegExp[]): boolean {
  const allStrings = [
    ...analysis.iocs.filePaths,
    ...analysis.iocs.registryKeys,
    ...(analysis.enhancedStrings?.map((s) => s.value) ?? []),
  ];
  return patterns.some((p) => allStrings.some((s) => p.test(s)));
}

function hasImport(analysis: AnalysisResults, patterns: RegExp[]): boolean {
  const importNames = analysis.imports.map((i) => i.function.toLowerCase());
  return patterns.some((p) => importNames.some((i) => p.test(i)));
}

function hasRegistryStrings(analysis: AnalysisResults): boolean {
  return (
    analysis.iocs.registryKeys.length > 0 ||
    matchesAnyString(analysis, [/HKEY_|RegOpenKey|RegSetValue|CurrentVersion\\Run/i])
  );
}

function hasRegistryImports(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [/regopen|regset|regcreate|regquery|regdelete/i]);
}

function hasNetworkStrings(analysis: AnalysisResults): boolean {
  return matchesAnyString(analysis, [
    /http:\/\/|https:\/\//i,
    /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,
    /:80\b|:443\b|:8080\b/,
  ]);
}

function hasNetworkImports(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [
    /internetopen|httpopen|winhttp|urldownload|socket|connect|send|recv|wsastartup/i,
  ]);
}

function hasUrlsOrDomains(analysis: AnalysisResults): boolean {
  return analysis.iocs.urls.length > 0 || analysis.iocs.domains.length > 0;
}

function hasInjectionImports(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [
    /createremotethread|virtualallocex|writeprocessmemory|ntunmapview|queueuserapc|setthreadcontext/i,
  ]);
}

function hasCredentialStrings(analysis: AnalysisResults): boolean {
  return matchesAnyString(analysis, [
    /password|credential|login|lsass|sam\b|ntds|mimikatz|sekurlsa/i,
    /\\Windows\\System32\\config\\SAM/i,
  ]);
}

function hasCredentialImports(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [/credread|credenumerate|lsalookup|samconnect|cryptunprotect/i]);
}

function hasFileManipulationStrings(analysis: AnalysisResults): boolean {
  return matchesAnyString(analysis, [
    /\.encrypted|\.locked|ransom|decrypt|bitcoin|monero/i,
    /delete.*shadow|vssadmin/i,
  ]);
}

function hasCryptoWithFileOps(analysis: AnalysisResults): boolean {
  const hasCrypto = (analysis.cryptoFindings?.length ?? 0) > 0;
  const hasFileOps = hasImport(analysis, [/createfile|writefile|readfile|deletefile/i]);
  return hasCrypto && hasFileOps;
}

function hasAntiDebugImports(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [
    /isdebuggerpresent|checkremotedebugger|ntqueryinformation|outputdebugstring/i,
  ]);
}

function hasVirtualizationStrings(analysis: AnalysisResults): boolean {
  return matchesAnyString(analysis, [/vmware|virtualbox|vbox|qemu|sandboxie|wine_/i]);
}

function hasTimingChecks(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [/gettickcount|queryperformance|rdtsc/i]);
}

function hasKeyloggerImports(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [/setwindowshook|getasynckeystate|getkeystate|getkeyboardstate/i]);
}

function hasScreenCaptureImports(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [/bitblt|getdc|getwindowdc|capturescreenshot|printwindow/i]);
}

function hasServiceImports(analysis: AnalysisResults): boolean {
  return hasImport(analysis, [/createservice|openscmanager|startservice|changeserviceconfig/i]);
}

function hasScheduledTaskStrings(analysis: AnalysisResults): boolean {
  return matchesAnyString(analysis, [/schtasks|taskschd|ITaskScheduler|at\.exe/i]);
}

export class BehaviorPredictor {
  /**
   * Predict likely runtime behaviors from static analysis results.
   */
  public predict(analysis: AnalysisResults): BehaviorHint[] {
    const hints: BehaviorHint[] = [];

    for (const rule of BEHAVIOR_RULES) {
      const matchCount = rule.matchers.filter((m) => m(analysis)).length;
      if (matchCount === 0) continue;

      const confidenceBoost = (matchCount - 1) * 0.1;
      const confidence = Math.min(1, rule.baseConfidence + confidenceBoost);

      hints.push({
        behavior: rule.behavior,
        confidence,
        reasoning: rule.reasoning,
        risks: rule.risks,
        relatedTechniques: rule.relatedTechniques,
      });
    }

    return hints.sort((a, b) => b.confidence - a.confidence);
  }

  /**
   * Augment MITRE techniques with behavior-based mappings.
   */
  public augmentTechniques(
    existingTechniques: MitreTechnique[],
    hints: BehaviorHint[],
  ): MitreTechnique[] {
    const techniqueMap = new Map<string, MitreTechnique>();
    for (const t of existingTechniques) {
      techniqueMap.set(t.id, t);
    }

    for (const hint of hints) {
      for (const techId of hint.relatedTechniques) {
        const existing = techniqueMap.get(techId);
        if (existing) {
          if (!existing.evidence.includes(hint.reasoning)) {
            existing.evidence.push(`Behavior hint: ${hint.reasoning}`);
          }
          existing.confidence = Math.max(existing.confidence, hint.confidence);
        }
      }
    }

    return [...techniqueMap.values()];
  }
}
