import { describe, expect, test } from 'bun:test';
import type { AnalysisResults } from '../types.js';
import { BehaviorPredictor } from '../utils/behavior-predictor.js';

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

describe('BehaviorPredictor', () => {
  const predictor = new BehaviorPredictor();

  test('predicts C2 communication from network indicators', () => {
    const analysis = baseAnalysis();
    analysis.iocs.urls = ['http://evil.com/beacon'];
    analysis.imports = [{ library: 'wininet.dll', function: 'InternetOpenA', isSuspicious: true }];

    const hints = predictor.predict(analysis);
    const c2Hint = hints.find((h) => h.behavior.includes('Command & Control'));

    expect(c2Hint).toBeDefined();
    expect(c2Hint?.confidence).toBeGreaterThan(0.5);
    expect(c2Hint?.relatedTechniques).toContain('T1071.001');
  });

  test('predicts process injection from suspicious imports', () => {
    const analysis = baseAnalysis();
    analysis.imports = [
      { library: 'kernel32.dll', function: 'CreateRemoteThread', isSuspicious: true },
      { library: 'kernel32.dll', function: 'VirtualAllocEx', isSuspicious: true },
    ];

    const hints = predictor.predict(analysis);
    const injectionHint = hints.find((h) => h.behavior.includes('Process Injection'));

    expect(injectionHint).toBeDefined();
    expect(injectionHint?.confidence).toBeGreaterThanOrEqual(0.8);
  });

  test('predicts registry persistence from registry keys', () => {
    const analysis = baseAnalysis();
    analysis.iocs.registryKeys = [
      'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    ];

    const hints = predictor.predict(analysis);
    const persistenceHint = hints.find((h) => h.behavior.includes('Registry'));

    expect(persistenceHint).toBeDefined();
    expect(persistenceHint?.risks.length).toBeGreaterThan(0);
  });

  test('predicts anti-analysis from evasion imports', () => {
    const analysis = baseAnalysis();
    analysis.imports = [
      { library: 'kernel32.dll', function: 'IsDebuggerPresent', isSuspicious: true },
    ];
    analysis.enhancedStrings = [
      { value: 'vmware', encoding: 'ascii', category: 'other', entropy: 2, isSuspicious: true },
    ];

    const hints = predictor.predict(analysis);
    const evasionHint = hints.find((h) => h.behavior.includes('Anti-Analysis'));

    expect(evasionHint).toBeDefined();
    expect(evasionHint?.relatedTechniques).toContain('T1497');
  });

  test('returns empty array for benign analysis', () => {
    const analysis = baseAnalysis();
    const hints = predictor.predict(analysis);
    expect(hints).toEqual([]);
  });

  test('sorts hints by confidence descending', () => {
    const analysis = baseAnalysis();
    analysis.imports = [
      { library: 'kernel32.dll', function: 'CreateRemoteThread', isSuspicious: true },
      { library: 'wininet.dll', function: 'InternetOpenA', isSuspicious: true },
    ];
    analysis.iocs.registryKeys = ['HKEY_LOCAL_MACHINE\\Software\\Test'];

    const hints = predictor.predict(analysis);
    for (let i = 1; i < hints.length; i++) {
      const prev = hints[i - 1];
      const curr = hints[i];
      if (prev && curr) {
        expect(prev.confidence).toBeGreaterThanOrEqual(curr.confidence);
      }
    }
  });
});
