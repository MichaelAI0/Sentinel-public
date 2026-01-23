/**
 * Report Agent
 * Professional report generation in multiple formats
 */

import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { requireFeature } from '../config/features.js';
import type {
  AnalysisState,
  AssemblyPattern,
  CryptoFinding,
  EnhancedString,
  ReportPaths,
  YaraMatch,
} from '../types.js';
import { reportLogger as logger } from '../utils/logger.js';

// ============================================================================
// Markdown Section Generators
// ============================================================================

function generateExecutiveSummary(state: AnalysisState): string {
  const { triageResults, filename } = state;
  const now = new Date().toISOString();
  let md = `# Malware Analysis Report: ${filename}

**Generated**: ${now}  
**Analyst**: SENTINEL Automated Analysis  
**Status**: ${state.status}

---

## Executive Summary

`;

  if (triageResults) {
    md += `**Risk Level**: ${triageResults.riskLevel}  
**Confidence**: ${(triageResults.confidence * 100).toFixed(0)}%  
**Recommendation**: ${triageResults.recommendation}

${triageResults.reasoning}

`;
  }
  return md;
}

function generateFileMetadata(state: AnalysisState): string {
  const { triageResults, filename } = state;
  return `---

## File Metadata

| Property | Value |
|----------|-------|
| **Filename** | ${filename} |
| **SHA256** | \`${triageResults?.sha256 ?? 'N/A'}\` |
| **MD5** | \`${triageResults?.md5 ?? 'N/A'}\` |
| **File Type** | ${triageResults?.fileType ?? 'Unknown'} |
| **Entropy** | ${triageResults?.entropy?.toFixed(2) ?? 'N/A'} |
| **Packed** | ${triageResults?.isPacked ? `Yes (${triageResults.packerName ?? 'Unknown'})` : 'No'} |

`;
}

function generateMitreSection(techniques: AnalysisState['analysisResults']): string {
  if (!techniques) return '';
  return `---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Confidence |
|--------------|------|--------|------------|
${techniques.mitreTechniques.map((t) => `| ${t.id} | ${t.name} | ${t.tactic} | ${(t.confidence * 100).toFixed(0)}% |`).join('\n')}

`;
}

function generateYaraSection(yaraMatches: YaraMatch[] | undefined): string {
  if (!yaraMatches || yaraMatches.length === 0) return '';

  let md = `---

## Signature Matches (YARA)

| Rule | Tags | Matches |
|------|------|--------|
${yaraMatches.map((y) => `| ${y.ruleName} | ${y.tags.join(', ') || 'N/A'} | ${y.matches.length} string(s) |`).join('\n')}

`;

  const significantMatches = yaraMatches.filter(
    (y) => y.tags.includes('malware') || y.tags.includes('trojan') || y.tags.includes('ransomware'),
  );
  if (significantMatches.length > 0) {
    md += `### High-Priority Rule Details\n\n`;
    for (const match of significantMatches.slice(0, 5)) {
      md += `**${match.ruleName}**\n- Tags: ${match.tags.join(', ')}\n- Matched ${match.matches.length} string(s) at offsets: ${match.matches
        .slice(0, 5)
        .map((m) => `0x${m.offset.toString(16)}`)
        .join(
          ', ',
        )}${match.matches.length > 5 ? '...' : ''}\n${match.metadata ? `- Metadata: ${JSON.stringify(match.metadata)}` : ''}\n\n`;
    }
  }
  return md;
}

function generateCryptoSection(cryptoFindings: CryptoFinding[] | undefined): string {
  if (!cryptoFindings || cryptoFindings.length === 0) return '';

  let md = `---

## Cryptographic Operations

| Algorithm | Type | Confidence | Evidence |
|-----------|------|------------|----------|
${cryptoFindings.map((c) => `| ${c.algorithm} | ${c.type} | ${(c.confidence * 100).toFixed(0)}% | ${c.evidence.slice(0, 50)}${c.evidence.length > 50 ? '...' : ''} |`).join('\n')}

`;

  const highConfCrypto = cryptoFindings.filter((c) => c.confidence > 0.7);
  if (highConfCrypto.length > 0) {
    md += `### High-Confidence Crypto Detections\n\n${highConfCrypto.map((c) => `- **${c.algorithm}** (${c.type}): ${c.evidence}`).join('\n')}\n\n> ⚠️ Cryptographic operations may indicate encryption, ransomware, or secure communication capabilities.\n\n`;
  }
  return md;
}

/** Type-safe risk level recommendations mapping */
const RISK_RECOMMENDATIONS = {
  CRITICAL: `1. **Immediate**: Block all identified C2 IPs/domains at network perimeter
2. **Immediate**: Hunt for file hashes across environment
3. **Short-term**: Implement detection rules for identified TTPs
4. **Short-term**: Check for persistence mechanisms on affected systems
5. **Long-term**: Review and enhance endpoint detection capabilities\n`,
  HIGH: `1. **Immediate**: Block all identified C2 IPs/domains at network perimeter
2. **Immediate**: Hunt for file hashes across environment
3. **Short-term**: Implement detection rules for identified TTPs
4. **Short-term**: Check for persistence mechanisms on affected systems
5. **Long-term**: Review and enhance endpoint detection capabilities\n`,
  MEDIUM: `1. **Short-term**: Monitor for identified IOCs
2. **Short-term**: Conduct additional dynamic analysis if needed
3. **Long-term**: Update threat intelligence with findings\n`,
  LOW: `1. No immediate action required
2. Consider adding to known-good baseline if verified benign\n`,
  UNKNOWN: `1. No immediate action required
2. Consider adding to known-good baseline if verified benign\n`,
} as const satisfies Record<string, string>;

type RiskLevel = keyof typeof RISK_RECOMMENDATIONS;

function generateRecommendations(riskLevel?: string): string {
  const level = (riskLevel ?? 'UNKNOWN') as RiskLevel;
  const recommendations = RISK_RECOMMENDATIONS[level] ?? RISK_RECOMMENDATIONS.UNKNOWN;
  return `---\n\n## Recommendations\n\n${recommendations}`;
}

/**
 * Generate Markdown report
 */
function generateMarkdownReport(state: AnalysisState): string {
  const { triageResults, analysisResults } = state;

  let md = generateExecutiveSummary(state);
  md += generateFileMetadata(state);
  md += `---\n\n## Threat Assessment\n\n`;

  if (analysisResults) {
    md += `| Assessment | Value |
|------------|-------|
| **Malware Family** | ${analysisResults.malwareFamily ?? 'Unknown'} |
| **Family Confidence** | ${analysisResults.familyConfidence ? `${(analysisResults.familyConfidence * 100).toFixed(0)}%` : 'N/A'} |
| **Sophistication** | ${analysisResults.sophistication} |

### Key Findings

${analysisResults.keyFindings.map((f) => `- ${f}`).join('\n')}

### Capabilities

${analysisResults.capabilities.length > 0 ? analysisResults.capabilities.map((c) => `- ${c}`).join('\n') : '_No specific capabilities identified_'}

### Anti-Analysis Techniques

${analysisResults.antiAnalysis.length > 0 ? analysisResults.antiAnalysis.map((a) => `- ${a}`).join('\n') : '_No anti-analysis techniques detected_'}

### Predicted Behaviors

${
  analysisResults.behaviorHints && analysisResults.behaviorHints.length > 0
    ? analysisResults.behaviorHints
        .map(
          (h) =>
            `- **${h.behavior}** (${(h.confidence * 100).toFixed(0)}% confidence)\n  - Reasoning: ${h.reasoning}\n  - Risks: ${h.risks.join(', ')}`,
        )
        .join('\n')
    : '_No behavioral predictions available_'
}

`;

    md += generateMitreSection(analysisResults);
    md += generateIocSection(analysisResults);
    md += generateTechnicalSection(analysisResults);
    md += generateYaraSection(analysisResults.yaraMatches);
    md += generateCryptoSection(analysisResults.cryptoFindings);
    md += generateAssemblySection(analysisResults.assemblyPatterns);
    md += generateEnhancedStringsSection(analysisResults.enhancedStrings);
    md += generateUnpackingSection(analysisResults);
  } else {
    md += `_Deep analysis was not performed (triage recommendation: ${triageResults?.recommendation ?? 'N/A'})_\n\n`;
  }

  md += generateRecommendations(triageResults?.riskLevel);
  md += generateAppendix(state);

  return md;
}

// Stub implementations for remaining section generators
function generateIocSection(analysis: NonNullable<AnalysisState['analysisResults']>): string {
  return `---

## Indicators of Compromise (IOCs)

### Network Indicators

**IP Addresses** (${analysis.iocs.ipAddresses.length}):
${analysis.iocs.ipAddresses.length > 0 ? analysis.iocs.ipAddresses.map((ip) => `- \`${ip}\``).join('\n') : '_None found_'}

**Domains** (${analysis.iocs.domains.length}):
${analysis.iocs.domains.length > 0 ? analysis.iocs.domains.map((d) => `- \`${d}\``).join('\n') : '_None found_'}

**URLs** (${analysis.iocs.urls.length}):
${analysis.iocs.urls.length > 0 ? analysis.iocs.urls.map((u) => `- \`${u}\``).join('\n') : '_None found_'}

### Host Indicators

**File Paths** (${analysis.iocs.filePaths.length}):
${analysis.iocs.filePaths.length > 0 ? analysis.iocs.filePaths.map((p) => `- \`${p}\``).join('\n') : '_None found_'}

**Registry Keys** (${analysis.iocs.registryKeys.length}):
${analysis.iocs.registryKeys.length > 0 ? analysis.iocs.registryKeys.map((r) => `- \`${r}\``).join('\n') : '_None found_'}

`;
}

function generateTechnicalSection(analysis: NonNullable<AnalysisState['analysisResults']>): string {
  const suspiciousFunctions = analysis.functions.filter((f) => f.isSuspicious);
  const suspiciousImports = analysis.imports.filter((i) => i.isSuspicious);

  return `---

## Technical Analysis

### Suspicious Functions (${suspiciousFunctions.length})

| Function | Address | Techniques |
|----------|---------|------------|
${suspiciousFunctions
  .slice(0, 30)
  .map((f) => `| ${f.name} | ${f.address} | ${f.techniques?.join(', ') ?? ''} |`)
  .join('\n')}

### Suspicious Imports (${suspiciousImports.length})

${
  suspiciousImports.length > 0
    ? suspiciousImports
        .slice(0, 30)
        .map((i) => `- \`${i.library}:${i.function}\``)
        .join('\n')
    : '_None identified_'
}

### Technical Notes

${analysis.technicalNotes}

`;
}

function generateAssemblySection(patterns: AssemblyPattern[] | undefined): string {
  if (!patterns || patterns.length === 0) return '';

  let md = `---

## Assembly Patterns

| Category | Name | Address | MITRE Technique |
|----------|------|---------|-----------------|
${patterns.map((p) => `| ${p.category} | ${p.name} | ${p.address ?? 'N/A'} | ${p.technique ?? 'N/A'} |`).join('\n')}

`;
  const antiDebugPatterns = patterns.filter((p) => p.category === 'anti-debug');
  if (antiDebugPatterns.length > 0) {
    md += `### Anti-Debug Techniques Detected

${antiDebugPatterns.map((p) => `- **${p.name}**: ${p.instructions.slice(0, 3).join(', ')}${p.instructions.length > 3 ? '...' : ''}`).join('\n')}

> ⚠️ Anti-debugging techniques indicate evasive behavior typical of malware.

`;
  }
  return md;
}

function generateEnhancedStringsSection(strings: EnhancedString[] | undefined): string {
  if (!strings || strings.length === 0) return '';

  const suspiciousStrings = strings.filter((s) => s.isSuspicious);
  const categorized = strings.reduce(
    (acc, s) => {
      acc[s.category] = (acc[s.category] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>,
  );

  let md = `---

## Enhanced String Analysis

**Total Analyzed**: ${strings.length}  
**Suspicious**: ${suspiciousStrings.length}

### String Categories

| Category | Count |
|----------|-------|
${Object.entries(categorized)
  .sort(([, a], [, b]) => b - a)
  .map(([cat, count]) => `| ${cat} | ${count} |`)
  .join('\n')}

`;
  if (suspiciousStrings.length > 0) {
    md += `### Suspicious Strings (${suspiciousStrings.length})

| String | Category | Reason |
|--------|----------|--------|
${suspiciousStrings
  .slice(0, 20)
  .map(
    (s) =>
      `| \`${s.value.slice(0, 40)}${s.value.length > 40 ? '...' : ''}\` | ${s.category} | ${s.suspicionReason ?? 'Pattern match'} |`,
  )
  .join('\n')}
${suspiciousStrings.length > 20 ? `\n_...and ${suspiciousStrings.length - 20} more_` : ''}

`;
  }
  return md;
}

function generateUnpackingSection(analysis: NonNullable<AnalysisState['analysisResults']>): string {
  if (!analysis.wasUnpacked) return '';
  return `---

## Unpacking Results

- **Was Unpacked**: Yes
- **Original Packer**: ${analysis.originalPacker ?? 'Unknown'}

> The binary was successfully unpacked before analysis, allowing for deeper inspection of the underlying code.

`;
}

function generateAppendix(state: AnalysisState): string {
  return `
---

## Appendix

### Analysis Metadata

- **Analysis Start**: ${state.startTime.toISOString()}
- **Analysis End**: ${state.endTime?.toISOString() ?? 'In Progress'}
- **Duration**: ${state.endTime ? `${((state.endTime.getTime() - state.startTime.getTime()) / 1000).toFixed(1)}s` : 'N/A'}
- **Errors**: ${state.errors.length > 0 ? state.errors.join(', ') : 'None'}

---

*Report generated by SENTINEL Automated Malware Analysis System*
`;
}

/**
 * Generate JSON report
 */
function generateJsonReport(state: AnalysisState): object {
  return {
    metadata: {
      filename: state.filename,
      binaryPath: state.binaryPath,
      analysisStart: state.startTime.toISOString(),
      analysisEnd: state.endTime?.toISOString(),
      status: state.status,
      errors: state.errors,
    },
    triage: state.triageResults
      ? {
          fileType: state.triageResults.fileType,
          sha256: state.triageResults.sha256,
          md5: state.triageResults.md5,
          entropy: state.triageResults.entropy,
          riskLevel: state.triageResults.riskLevel,
          confidence: state.triageResults.confidence,
          isPacked: state.triageResults.isPacked,
          packerName: state.triageResults.packerName,
          recommendation: state.triageResults.recommendation,
          reasoning: state.triageResults.reasoning,
          suspiciousStrings: state.triageResults.suspiciousStrings,
          suspiciousImports: state.triageResults.suspiciousImports,
        }
      : null,
    analysis: state.analysisResults
      ? {
          malwareFamily: state.analysisResults.malwareFamily,
          familyConfidence: state.analysisResults.familyConfidence,
          sophistication: state.analysisResults.sophistication,
          capabilities: state.analysisResults.capabilities,
          antiAnalysis: state.analysisResults.antiAnalysis,
          keyFindings: state.analysisResults.keyFindings,
          mitreTechniques: state.analysisResults.mitreTechniques,
          iocs: state.analysisResults.iocs,
          functionsTotal: state.analysisResults.functions.length,
          functionsSuspicious: state.analysisResults.functions.filter((f) => f.isSuspicious).length,
          importsTotal: state.analysisResults.imports.length,
          importsSuspicious: state.analysisResults.imports.filter((i) => i.isSuspicious).length,
          exportsTotal: state.analysisResults.exports.length,
          // Phase 2: Enhanced Analysis
          yaraMatches: state.analysisResults.yaraMatches ?? [],
          cryptoFindings: state.analysisResults.cryptoFindings ?? [],
          assemblyPatterns: state.analysisResults.assemblyPatterns ?? [],
          enhancedStrings: {
            total: state.analysisResults.enhancedStrings?.length ?? 0,
            suspicious:
              state.analysisResults.enhancedStrings?.filter((s) => s.isSuspicious).length ?? 0,
            categories:
              state.analysisResults.enhancedStrings?.reduce(
                (acc, s) => {
                  acc[s.category] = (acc[s.category] ?? 0) + 1;
                  return acc;
                },
                {} as Record<string, number>,
              ) ?? {},
            suspiciousItems:
              state.analysisResults.enhancedStrings?.filter((s) => s.isSuspicious).slice(0, 50) ??
              [],
          },
          wasUnpacked: state.analysisResults.wasUnpacked ?? false,
          originalPacker: state.analysisResults.originalPacker,
        }
      : null,
  };
}

/**
 * Generate STIX 2.1 bundle
 */
function generateStixBundle(state: AnalysisState): object {
  const now = new Date().toISOString();
  const objects: Array<{ type: string; id: string; [key: string]: unknown }> = [];

  // Create malware object
  if (state.triageResults) {
    objects.push({
      type: 'malware',
      spec_version: '2.1',
      id: `malware--${crypto.randomUUID()}`,
      created: now,
      modified: now,
      name: state.filename,
      malware_types: state.analysisResults?.malwareFamily ? ['trojan'] : ['unknown'],
      is_family: false,
      capabilities: state.analysisResults?.capabilities ?? [],
      hashes: {
        'SHA-256': state.triageResults.sha256,
        MD5: state.triageResults.md5,
      },
    });
  }

  // Create indicator objects for IOCs
  if (state.analysisResults?.iocs) {
    const { iocs } = state.analysisResults;

    for (const ip of iocs.ipAddresses) {
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        name: `Malicious IP: ${ip}`,
        pattern: `[ipv4-addr:value = '${ip}']`,
        pattern_type: 'stix',
        valid_from: now,
        indicator_types: ['malicious-activity'],
      });
    }

    for (const domain of iocs.domains) {
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        name: `Malicious Domain: ${domain}`,
        pattern: `[domain-name:value = '${domain}']`,
        pattern_type: 'stix',
        valid_from: now,
        indicator_types: ['malicious-activity'],
      });
    }

    for (const url of iocs.urls) {
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        name: `Malicious URL: ${url}`,
        pattern: `[url:value = '${url}']`,
        pattern_type: 'stix',
        valid_from: now,
        indicator_types: ['malicious-activity'],
      });
    }
  }

  // Create attack-pattern objects for MITRE techniques
  if (state.analysisResults?.mitreTechniques) {
    for (const technique of state.analysisResults.mitreTechniques) {
      objects.push({
        type: 'attack-pattern',
        spec_version: '2.1',
        id: `attack-pattern--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        name: technique.name,
        external_references: [
          {
            source_name: 'mitre-attack',
            external_id: technique.id,
            url: `https://attack.mitre.org/techniques/${technique.id.replace('.', '/')}/`,
          },
        ],
        kill_chain_phases: [
          {
            kill_chain_name: 'mitre-attack',
            phase_name: technique.tactic.toLowerCase().replace(' ', '-'),
          },
        ],
      });
    }
  }

  // Phase 2: Create indicators from YARA matches
  if (state.analysisResults?.yaraMatches) {
    for (const yaraMatch of state.analysisResults.yaraMatches) {
      objects.push({
        type: 'indicator',
        spec_version: '2.1',
        id: `indicator--${crypto.randomUUID()}`,
        created: now,
        modified: now,
        name: `YARA Rule: ${yaraMatch.ruleName}`,
        description: `Matched YARA rule with tags: ${yaraMatch.tags.join(', ') || 'none'}`,
        pattern: `[file:hashes.'SHA-256' = '${state.triageResults?.sha256 ?? 'unknown'}']`,
        pattern_type: 'stix',
        valid_from: now,
        indicator_types: ['malicious-activity'],
        labels: yaraMatch.tags,
      });
    }
  }

  // Phase 2: Note on cryptographic capabilities
  if (state.analysisResults?.cryptoFindings && state.analysisResults.cryptoFindings.length > 0) {
    const cryptoAlgorithms = [
      ...new Set(state.analysisResults.cryptoFindings.map((c) => c.algorithm)),
    ];
    objects.push({
      type: 'note',
      spec_version: '2.1',
      id: `note--${crypto.randomUUID()}`,
      created: now,
      modified: now,
      content: `Detected cryptographic operations: ${cryptoAlgorithms.join(', ')}. This may indicate encryption, ransomware, or secure C2 communication capabilities.`,
      object_refs: objects.filter((o) => o.type === 'malware').map((o) => o.id),
    });
  }

  // Phase 2: Note on anti-analysis techniques from assembly patterns
  const antiDebugPatterns =
    state.analysisResults?.assemblyPatterns?.filter((p) => p.category === 'anti-debug') ?? [];
  if (antiDebugPatterns.length > 0) {
    objects.push({
      type: 'note',
      spec_version: '2.1',
      id: `note--${crypto.randomUUID()}`,
      created: now,
      modified: now,
      content: `Anti-debugging techniques detected: ${antiDebugPatterns.map((p) => p.name).join(', ')}. The malware uses evasion techniques to avoid analysis.`,
      object_refs: objects.filter((o) => o.type === 'malware').map((o) => o.id),
    });
  }

  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID()}`,
    objects,
  };
}

/**
 * Run report generation
 *
 * Community Edition: Generates basic Markdown and JSON reports
 * Professional+: Full STIX 2.1 export and enhanced reporting
 */
export async function runReportAgent(state: AnalysisState): Promise<Partial<AnalysisState>> {
  // AI-powered report generation requires Professional or higher
  requireFeature('AI_REPORT');

  logger.info`Generating reports for: ${state.filename}`;

  // Use local path when running natively, container path when in Docker
  const isDocker = process.env.DOCKER_ENV === 'true';
  const defaultOutputDir = isDocker ? '/outputs' : join(process.cwd(), 'outputs');
  const outputDir = process.env.OUTPUT_DIR ?? defaultOutputDir;
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const baseFilename = state.filename.replace(/[^a-zA-Z0-9]/g, '_');
  const reportDir = join(outputDir, `${baseFilename}_${timestamp}`);

  // Ensure output directory exists
  await mkdir(reportDir, { recursive: true });

  const reportPaths: ReportPaths = {
    markdown: join(reportDir, 'report.md'),
    json: join(reportDir, 'report.json'),
    stix: join(reportDir, 'stix-bundle.json'),
  };

  try {
    // Generate and write Markdown report
    const markdown = generateMarkdownReport(state);
    await writeFile(reportPaths.markdown, markdown, 'utf-8');
    logger.info`Markdown report written to: ${reportPaths.markdown}`;

    // Generate and write JSON report
    const json = generateJsonReport(state);
    await writeFile(reportPaths.json, JSON.stringify(json, null, 2), 'utf-8');
    logger.info`JSON report written to: ${reportPaths.json}`;

    // Generate and write STIX bundle
    const stix = generateStixBundle(state);
    await writeFile(reportPaths.stix, JSON.stringify(stix, null, 2), 'utf-8');
    logger.info`STIX bundle written to: ${reportPaths.stix}`;

    logger.info`All reports generated successfully`;

    return {
      reportPaths,
      reportsComplete: true,
      status: 'complete',
      endTime: new Date(),
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logger.error`Report generation failed: ${errorMessage}`;

    return {
      reportsComplete: false,
      status: 'failed',
      errors: [...state.errors, `Report generation failed: ${errorMessage}`],
      endTime: new Date(),
    };
  }
}
