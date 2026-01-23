import { SUSPICIOUS_API_GROUPS, TECHNIQUES, type TechniqueDef } from '@sentinel/shared';
import type { AnalysisResults, AssemblyPattern, EnhancedString, MitreTechnique } from '../types.js';

export type AttackNavigatorTechnique = {
  techniqueID: string;
  tactic: string;
  color?: string;
  comment?: string;
};

export type AttackNavigatorLayer = {
  name: string;
  version: string;
  domain: 'enterprise-attack';
  description?: string;
  techniques: AttackNavigatorTechnique[];
};

// Note: TECHNIQUES and SUSPICIOUS_API_GROUPS now imported from @sentinel/shared
// See: packages/shared/src/data/mitre-mappings.ts

function normalize(s: string): string {
  return s.toLowerCase();
}

function toEvidenceArray(evidence: string | string[]): string[] {
  return Array.isArray(evidence) ? evidence : [evidence];
}

function addTechnique(
  bucket: Map<string, MitreTechnique>,
  def: TechniqueDef,
  evidence: string | string[],
  confidence: number,
): void {
  const existing = bucket.get(def.id);
  const newEvidence = toEvidenceArray(evidence);
  if (!existing) {
    bucket.set(def.id, {
      id: def.id,
      name: def.name,
      tactic: def.tactic,
      evidence: newEvidence,
      confidence: Math.max(0, Math.min(1, confidence)),
    });
    return;
  }

  // Prefer higher confidence, keep richer evidence.
  const bestConfidence = Math.max(existing.confidence, confidence);
  const combinedEvidence = [...new Set([...existing.evidence, ...newEvidence])];

  bucket.set(def.id, {
    ...existing,
    confidence: bestConfidence,
    evidence: combinedEvidence,
  });
}

function anyStringMatches(strings: string[], regex: RegExp): boolean {
  return strings.some((s) => regex.test(s));
}

function collectSuspiciousStrings(enhanced: EnhancedString[] | undefined): string[] {
  if (!enhanced) return [];
  return enhanced.filter((s) => s.isSuspicious).map((s) => s.value);
}

function collectAssemblyTechniques(patterns: AssemblyPattern[] | undefined): string[] {
  if (!patterns) return [];
  return patterns.flatMap((p) => (p.technique ? [p.technique] : []));
}

type MitreContext = {
  suspiciousFunctions: string[];
  suspiciousImports: string[];
  stringCorpus: string[];
  apiCandidates: string[];
};

export class MitreMapper {
  /**
   * Map AnalysisResults to MITRE ATT&CK techniques.
   *
   * This is additive: you can merge these with existing technique mappings.
   */
  public map(analysis: AnalysisResults): MitreTechnique[] {
    const out = new Map<string, MitreTechnique>();
    const context = this.buildContext(analysis);

    this.addPackingSignals(analysis, out);
    this.addStringSignals(context, out);
    this.addApiSignals(analysis, context, out);
    this.addAntiAnalysisSignals(context, out);
    this.addCryptoSignals(analysis, context, out);
    this.addDiscoverySignals(context, out);
    this.addAssemblySignals(analysis, out);

    return [...out.values()].sort((a, b) => b.confidence - a.confidence);
  }

  private buildContext(analysis: AnalysisResults): MitreContext {
    const suspiciousFunctions = analysis.functions.filter((f) => f.isSuspicious).map((f) => f.name);
    const suspiciousImports = analysis.imports
      .filter((i) => i.isSuspicious)
      .map((i) => `${i.library}:${i.function}`);
    const suspiciousStrings = collectSuspiciousStrings(analysis.enhancedStrings);
    const stringCorpus = [
      ...analysis.iocs.urls,
      ...analysis.iocs.domains,
      ...analysis.iocs.ipAddresses,
      ...analysis.iocs.filePaths,
      ...analysis.iocs.registryKeys,
      ...suspiciousStrings,
    ];
    const apiCandidates = this.buildApiCandidates(suspiciousFunctions, suspiciousImports, analysis);

    return {
      suspiciousFunctions,
      suspiciousImports,
      stringCorpus,
      apiCandidates,
    };
  }

  private buildApiCandidates(
    suspiciousFunctions: string[],
    suspiciousImports: string[],
    analysis: AnalysisResults,
  ): string[] {
    const apiCandidates = [
      ...suspiciousFunctions.map(normalize),
      ...suspiciousImports.map(normalize),
    ];

    if (analysis.apiCallMapping?.imports) {
      apiCandidates.push(
        ...analysis.apiCallMapping.imports.map((i) => normalize(`${i.library}:${i.functionName}`)),
      );
      apiCandidates.push(...analysis.apiCallMapping.imports.map((i) => normalize(i.functionName)));
    }

    return apiCandidates;
  }

  private addPackingSignals(analysis: AnalysisResults, out: Map<string, MitreTechnique>): void {
    if (analysis.wasUnpacked || analysis.originalPacker) {
      addTechnique(
        out,
        TECHNIQUES.obfuscatedFiles,
        `Binary unpacked (${analysis.originalPacker ?? 'unknown packer'})`,
        0.85,
      );
    }

    if (analysis.cfgData) {
      const complex = analysis.cfgData.functionCFGs.filter((f) => f.basicBlocks.length > 25);
      if (complex.length > 0) {
        addTechnique(
          out,
          TECHNIQUES.obfuscatedFiles,
          `Complex control flow in functions: ${complex
            .slice(0, 5)
            .map((f) => f.functionName)
            .join(', ')}`,
          0.6,
        );
      }
    }
  }

  private addStringSignals(context: MitreContext, out: Map<string, MitreTechnique>): void {
    if (
      anyStringMatches(context.stringCorpus, /\b(cmd\.exe|powershell|pwsh|wscript|cscript)\b/i) ||
      anyStringMatches(context.stringCorpus, /\b(sh|bash|zsh)\b/i)
    ) {
      addTechnique(out, TECHNIQUES.commandInterpreter, 'Command interpreter strings detected', 0.7);
    }

    if (
      anyStringMatches(context.stringCorpus, /base64/i) ||
      anyStringMatches(context.stringCorpus, /frombase64string/i) ||
      anyStringMatches(context.stringCorpus, /xor\b/i)
    ) {
      addTechnique(
        out,
        TECHNIQUES.deobfuscateDecode,
        'Decode/deobfuscation hints (base64/xor)',
        0.55,
      );
    }
  }

  private addApiSignals(
    analysis: AnalysisResults,
    context: MitreContext,
    out: Map<string, MitreTechnique>,
  ): void {
    const includesAny = (list: readonly string[]): string[] =>
      list.filter((needle) => context.apiCandidates.some((h) => h.includes(normalize(needle))));

    const injectionHits = includesAny(SUSPICIOUS_API_GROUPS.injection);
    if (injectionHits.length > 0) {
      addTechnique(
        out,
        TECHNIQUES.processInjection,
        `Injection-related APIs: ${injectionHits.slice(0, 5).join(', ')}`,
        0.8,
      );
    }

    const hollowingHits = includesAny(SUSPICIOUS_API_GROUPS.hollowing);
    if (hollowingHits.length > 0) {
      addTechnique(
        out,
        TECHNIQUES.processHollowing,
        `Process hollowing APIs: ${hollowingHits.slice(0, 5).join(', ')}`,
        0.85,
      );
    }

    const persistenceHits = includesAny(SUSPICIOUS_API_GROUPS.persistence);
    if (persistenceHits.some((h) => h.includes('reg'))) {
      addTechnique(out, TECHNIQUES.runKeys, 'Registry persistence APIs detected', 0.75);
    }
    if (persistenceHits.some((h) => h.includes('createservice') || h.includes('openscmanager'))) {
      addTechnique(out, TECHNIQUES.windowsService, 'Service creation APIs detected', 0.75);
    }

    const webHits = includesAny(SUSPICIOUS_API_GROUPS.networkWeb);
    if (webHits.length > 0 || analysis.iocs.urls.length > 0) {
      addTechnique(
        out,
        TECHNIQUES.webProtocols,
        'Web protocol indicators (HTTP/WinINet/WinHTTP)',
        0.7,
      );
    }

    const rawHits = includesAny(SUSPICIOUS_API_GROUPS.networkRaw);
    if (rawHits.length > 0) {
      addTechnique(out, TECHNIQUES.nonAppProtocols, 'Raw socket/network APIs detected', 0.55);
    }
  }

  private addAntiAnalysisSignals(context: MitreContext, out: Map<string, MitreTechnique>): void {
    const includesAny = (list: readonly string[]): string[] =>
      list.filter((needle) => context.apiCandidates.some((h) => h.includes(normalize(needle))));

    const antiDebugHits = includesAny(SUSPICIOUS_API_GROUPS.antiDebug);
    if (
      antiDebugHits.length > 0 ||
      anyStringMatches(context.stringCorpus, /\b(isdebuggerpresent|debugger)\b/i)
    ) {
      addTechnique(out, TECHNIQUES.systemChecks, 'Debugger detection APIs/strings detected', 0.75);
      addTechnique(out, TECHNIQUES.sandboxEvasion, 'Anti-analysis indicators present', 0.6);
    }

    const timeHits = includesAny(SUSPICIOUS_API_GROUPS.time);
    if (timeHits.length > 0) {
      addTechnique(
        out,
        TECHNIQUES.timeBasedEvasion,
        `Timing APIs: ${timeHits.slice(0, 5).join(', ')}`,
        0.55,
      );
    }

    if (anyStringMatches(context.stringCorpus, /(vmware|virtualbox|vbox|qemu|sandboxie)/i)) {
      addTechnique(
        out,
        TECHNIQUES.sandboxEvasion,
        'Virtualization/sandbox artifacts referenced',
        0.7,
      );
    }
  }

  private addCryptoSignals(
    analysis: AnalysisResults,
    context: MitreContext,
    out: Map<string, MitreTechnique>,
  ): void {
    if ((analysis.cryptoFindings?.length ?? 0) > 0 || (analysis.ghidraCrypto?.length ?? 0) > 0) {
      addTechnique(
        out,
        TECHNIQUES.encryptionForObfuscation,
        'Cryptographic primitives/constants detected',
        0.55,
      );

      const ransomwareHints = anyStringMatches(
        context.stringCorpus,
        /(ransom|decrypt|bitcoin|monero|\.locked|\.encrypted)/i,
      );
      if (ransomwareHints) {
        addTechnique(
          out,
          TECHNIQUES.encryptionForImpact,
          'Ransomware-style encryption indicators found',
          0.6,
        );
      }
    }
  }

  private addDiscoverySignals(context: MitreContext, out: Map<string, MitreTechnique>): void {
    if (anyStringMatches(context.stringCorpus, /(tasklist|ps\b|process\s+list)/i)) {
      addTechnique(
        out,
        TECHNIQUES.processDiscovery,
        'Process discovery command strings detected',
        0.5,
      );
    }
    if (anyStringMatches(context.stringCorpus, /(dir\b|ls\b|find\b|enumerate\s+files)/i)) {
      addTechnique(out, TECHNIQUES.fileDiscovery, 'File discovery command strings detected', 0.45);
    }
    if (anyStringMatches(context.stringCorpus, /(systeminfo|uname\b|whoami\b|hostname\b)/i)) {
      addTechnique(
        out,
        TECHNIQUES.systemInfoDiscovery,
        'System information discovery command strings detected',
        0.45,
      );
    }
  }

  private addAssemblySignals(analysis: AnalysisResults, out: Map<string, MitreTechnique>): void {
    const asmTechniqueIds = new Set(collectAssemblyTechniques(analysis.assemblyPatterns));
    if (asmTechniqueIds.has('T1055') && !out.has(TECHNIQUES.processInjection.id)) {
      addTechnique(out, TECHNIQUES.processInjection, 'Assembly patterns suggest injection', 0.65);
    }
  }

  public merge(existing: MitreTechnique[], additional: MitreTechnique[]): MitreTechnique[] {
    const bucket = new Map<string, MitreTechnique>();
    for (const tech of existing) bucket.set(tech.id, tech);
    for (const tech of additional) {
      addTechnique(bucket, tech, tech.evidence, tech.confidence);
    }
    return [...bucket.values()].sort((a, b) => b.confidence - a.confidence);
  }

  public toNavigatorLayer(
    techniques: MitreTechnique[],
    name = 'SENTINEL Analysis',
  ): AttackNavigatorLayer {
    return {
      name,
      version: '4.2',
      domain: 'enterprise-attack',
      techniques: techniques.map((t) => ({
        techniqueID: t.id,
        tactic: slugifyTactic(t.tactic),
        color: colorByConfidence(t.confidence),
        comment: t.evidence.join('; '),
      })),
    };
  }
}

function slugifyTactic(tactic: string): string {
  return tactic.trim().toLowerCase().replace(/\s+/g, '-');
}

function colorByConfidence(confidence: number): string {
  if (confidence >= 0.8) return '#ff3b30';
  if (confidence >= 0.6) return '#ffcc00';
  return '#34c759';
}
