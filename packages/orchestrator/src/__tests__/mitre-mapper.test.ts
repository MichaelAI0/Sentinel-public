import { describe, expect, test } from 'bun:test';
import type { AnalysisResults, MitreTechnique } from '../types.js';
import { MitreMapper } from '../utils/mitre-mapper.js';

const baseAnalysis = (): AnalysisResults => ({
  functions: [],
  imports: [],
  exports: [],
  iocs: {
    ipAddresses: [],
    domains: [],
    urls: [],
    filePaths: [],
    registryKeys: [],
    mutexes: [],
  },
  mitreTechniques: [],
  capabilities: [],
  antiAnalysis: [],
  sophistication: 'Intermediate',
  keyFindings: [],
  technicalNotes: 'unit test',
});

describe('MitreMapper', () => {
  test('maps web protocol indicators from URLs', () => {
    const mapper = new MitreMapper();
    const analysis = baseAnalysis();
    analysis.iocs.urls = ['http://example.com/beacon'];

    const results = mapper.map(analysis);
    const ids = results.map((t) => t.id);

    expect(ids).toContain('T1071.001');
  });

  test('maps process injection APIs from suspicious functions', () => {
    const mapper = new MitreMapper();
    const analysis = baseAnalysis();
    analysis.functions = [
      {
        name: 'CreateRemoteThread',
        address: '0x401000',
        isSuspicious: true,
      },
    ];

    const results = mapper.map(analysis);
    const technique = results.find((t) => t.id === 'T1055');

    expect(technique).toBeDefined();
    expect(technique?.evidence.length).toBeGreaterThan(0);
  });

  test('merges evidence arrays for identical techniques', () => {
    const mapper = new MitreMapper();
    const base: MitreTechnique = {
      id: 'T1055',
      name: 'Process Injection',
      tactic: 'Defense Evasion',
      confidence: 0.6,
      evidence: ['Initial evidence'],
    };
    const additional: MitreTechnique = {
      id: 'T1055',
      name: 'Process Injection',
      tactic: 'Defense Evasion',
      confidence: 0.8,
      evidence: ['Follow-up evidence'],
    };

    const merged = mapper.merge([base], [additional]);
    const mergedTechnique = merged.find((t) => t.id === 'T1055');

    expect(mergedTechnique?.confidence).toBe(0.8);
    expect(mergedTechnique?.evidence).toEqual(['Initial evidence', 'Follow-up evidence']);
  });
});
