/**
 * Assembly Extractor Tests
 *
 * Tests for assembly pattern extraction and analysis.
 */

import { describe, expect, test } from 'bun:test';
import { type AssemblyInstruction, getAssemblyExtractor } from '../utils/assembly-extractor';

describe('AssemblyExtractor', () => {
  const extractor = getAssemblyExtractor();

  describe('parseAssemblyText', () => {
    test('parses objdump format', () => {
      const text = '  401000:\t55\t\t\tpush   rbp\n  401001:\t48 89 e5\t\tmov    rbp,rsp';
      const instructions = extractor.parseAssemblyText(text);

      expect(instructions.length).toBe(2);
      expect(instructions[0]?.address).toBe('401000');
      expect(instructions[0]?.mnemonic).toBe('push');
    });

    test('parses Ghidra format', () => {
      const text = '00401000  PUSH  RBP\n00401001  MOV  RBP,RSP';
      const instructions = extractor.parseAssemblyText(text);

      expect(instructions.length).toBe(2);
      expect(instructions[0]?.address).toBe('00401000');
      expect(instructions[0]?.mnemonic).toBe('PUSH');
    });

    test('handles empty lines', () => {
      const text = '  401000:\t55\t\t\tpush   rbp\n\n  401001:\t48 89 e5\t\tmov    rbp,rsp\n';
      const instructions = extractor.parseAssemblyText(text);

      expect(instructions.length).toBe(2);
    });
  });

  describe('analyzeInstructions', () => {
    test('detects syscall instruction', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: '0f05', mnemonic: 'syscall', operands: '' },
      ];

      const patterns = extractor.analyzeInstructions(instructions);
      expect(patterns.some((p) => p.type === 'syscall')).toBe(true);
    });

    test('detects int 0x80 (Linux syscall)', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: 'cd80', mnemonic: 'int', operands: '0x80' },
      ];

      const patterns = extractor.analyzeInstructions(instructions);
      expect(patterns.some((p) => p.type === 'syscall')).toBe(true);
    });

    test('detects cpuid (anti-debug)', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: '0fa2', mnemonic: 'cpuid', operands: '' },
      ];

      const patterns = extractor.analyzeInstructions(instructions);
      expect(patterns.some((p) => p.type === 'antiDebug')).toBe(true);
    });

    test('detects rdtsc (timing check)', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: '0f31', mnemonic: 'rdtsc', operands: '' },
      ];

      const patterns = extractor.analyzeInstructions(instructions);
      expect(patterns.some((p) => p.type === 'antiDebug')).toBe(true);
    });

    test('detects aesenc (crypto)', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: '660f38dc', mnemonic: 'aesenc', operands: 'xmm0, xmm1' },
      ];

      const patterns = extractor.analyzeInstructions(instructions);
      expect(patterns.some((p) => p.type === 'crypto')).toBe(true);
    });

    test('groups multiple matching instructions', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: '', mnemonic: 'syscall', operands: '' },
        { address: '0x401010', bytes: '', mnemonic: 'syscall', operands: '' },
      ];

      const patterns = extractor.analyzeInstructions(instructions);
      const syscallPattern = patterns.find((p) => p.type === 'syscall');
      expect(syscallPattern).toBeDefined();
      expect(syscallPattern?.instructions.length).toBe(2);
    });
  });

  describe('detectLoops', () => {
    test('identifies back-jump as potential loop', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: '', mnemonic: 'mov', operands: 'ecx, 10' },
        { address: '0x401005', bytes: '', mnemonic: 'nop', operands: '' },
        { address: '0x401006', bytes: '', mnemonic: 'dec', operands: 'ecx' },
        { address: '0x401007', bytes: '', mnemonic: 'jnz', operands: '0x401005' },
      ];

      const loops = extractor.detectLoops(instructions);
      expect(loops.length).toBeGreaterThan(0);
      expect(loops[0]?.type).toBe('loop');
    });

    test('does not flag forward jumps as loops', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: '', mnemonic: 'test', operands: 'eax, eax' },
        { address: '0x401002', bytes: '', mnemonic: 'jz', operands: '0x401010' },
        { address: '0x401005', bytes: '', mnemonic: 'nop', operands: '' },
        { address: '0x401010', bytes: '', mnemonic: 'ret', operands: '' },
      ];

      const loops = extractor.detectLoops(instructions);
      expect(loops.length).toBe(0);
    });

    test('handles loop instruction', () => {
      const instructions: AssemblyInstruction[] = [
        { address: '0x401000', bytes: '', mnemonic: 'mov', operands: 'ecx, 10' },
        { address: '0x401005', bytes: '', mnemonic: 'nop', operands: '' },
        { address: '0x401006', bytes: '', mnemonic: 'loop', operands: '0x401005' },
      ];

      const loops = extractor.detectLoops(instructions);
      expect(loops.length).toBeGreaterThan(0);
    });
  });

  describe('summarize', () => {
    test('counts total instructions', () => {
      const functions = [
        {
          address: '0x401000',
          name: 'func1',
          size: 10,
          instructions: [
            { address: '0x401000', bytes: '', mnemonic: 'push', operands: 'rbp' },
            { address: '0x401001', bytes: '', mnemonic: 'ret', operands: '' },
          ],
        },
        {
          address: '0x402000',
          name: 'func2',
          size: 5,
          instructions: [{ address: '0x402000', bytes: '', mnemonic: 'ret', operands: '' }],
        },
      ];

      const summary = extractor.summarize(functions);
      expect(summary.totalFunctions).toBe(2);
      expect(summary.totalInstructions).toBe(3);
    });

    test('identifies interesting functions with high-severity patterns', () => {
      const functions = [
        {
          address: '0x401000',
          name: 'safe_func',
          size: 10,
          instructions: [
            { address: '0x401000', bytes: '', mnemonic: 'push', operands: 'rbp' },
            { address: '0x401001', bytes: '', mnemonic: 'ret', operands: '' },
          ],
        },
        {
          address: '0x402000',
          name: 'suspicious_func',
          size: 20,
          instructions: [
            { address: '0x402000', bytes: '', mnemonic: 'cli', operands: '' }, // privileged
            { address: '0x402001', bytes: '', mnemonic: 'ret', operands: '' },
          ],
        },
      ];

      const summary = extractor.summarize(functions);
      expect(summary.interestingFunctions.some((f) => f.name === 'suspicious_func')).toBe(true);
    });
  });

  describe('getAssemblyExtractor singleton', () => {
    test('returns same instance with same config', () => {
      const e1 = getAssemblyExtractor();
      const e2 = getAssemblyExtractor();
      expect(e1).toBe(e2);
    });

    test('returns new instance with different config', () => {
      const e1 = getAssemblyExtractor();
      const e2 = getAssemblyExtractor({ maxInstructions: 500 });
      expect(e1).not.toBe(e2);
    });
  });
});
