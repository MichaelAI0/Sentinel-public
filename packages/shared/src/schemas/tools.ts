import { z } from 'zod';
import {
  ARCHITECTURES,
  CONFIDENCE_LEVELS,
  ENDIANNESS,
  FILE_FORMATS,
  HASH_ALGORITHMS,
  OPERATING_SYSTEMS,
  STRING_TYPES,
  TLP_MARKINGS,
} from '../constants.js';

// ============================================
// BINARY UTILS TOOLS
// ============================================

// calculate_hashes
export const CalculateHashesInputSchema = z.object({
  binaryPath: z.string().describe('Absolute path to binary file'),
  algorithms: z.array(z.enum(HASH_ALGORITHMS)).optional().default(['MD5', 'SHA256']),
});

export const CalculateHashesOutputSchema = z.object({
  md5: z.string().optional(),
  sha1: z.string().optional(),
  sha256: z.string().optional(),
  ssdeep: z.string().optional(),
  fileSize: z.number().int().nonnegative(),
});

// detect_file_type
export const DetectFileTypeInputSchema = z.object({
  binaryPath: z.string().describe('Absolute path to binary file'),
});

export const DetectFileTypeOutputSchema = z.object({
  format: z.enum(FILE_FORMATS),
  architecture: z.enum(ARCHITECTURES),
  endianness: z.enum(ENDIANNESS),
  operatingSystem: z.enum(OPERATING_SYSTEMS),
  fileSize: z.number().int().nonnegative(),
  entropy: z.number().min(0).max(8),
  mimeType: z.string(),
});

// extract_pe_headers
export const ExtractPEHeadersInputSchema = z.object({
  binaryPath: z.string(),
  options: z
    .object({
      includeDetailedSections: z.boolean().optional().default(true),
      parseImportTable: z.boolean().optional().default(true),
      parseExportTable: z.boolean().optional().default(true),
    })
    .optional(),
});

export const ExtractPEHeadersOutputSchema = z.object({
  dosHeader: z.object({
    magic: z.string(),
    peOffset: z.number().int(),
  }),
  peHeader: z.object({
    machine: z.string(),
    numberOfSections: z.number().int(),
    timeDateStamp: z.number().int(),
    characteristics: z.array(z.string()),
  }),
  optionalHeader: z.object({
    magic: z.enum(['PE32', 'PE32+']),
    majorLinkerVersion: z.number().int(),
    minorLinkerVersion: z.number().int(),
    entryPoint: z.string(),
    imageBase: z.string(),
    subsystem: z.string(),
    dllCharacteristics: z.array(z.string()),
  }),
  sections: z.array(
    z.object({
      name: z.string(),
      virtualAddress: z.string(),
      virtualSize: z.number().int(),
      rawAddress: z.string(),
      rawSize: z.number().int(),
      characteristics: z.array(z.string()),
    }),
  ),
  imports: z
    .array(
      z.object({
        dll: z.string(),
        functions: z.array(z.string()),
      }),
    )
    .optional(),
  exports: z
    .array(
      z.object({
        name: z.string(),
        ordinal: z.number().int(),
        rva: z.string(),
      }),
    )
    .optional(),
});

// extract_elf_headers
export const ExtractELFHeadersInputSchema = z.object({
  binaryPath: z.string(),
  options: z
    .object({
      includeDetailedSections: z.boolean().optional().default(true),
      parseDynamicSection: z.boolean().optional().default(true),
    })
    .optional(),
});

export const ExtractELFHeadersOutputSchema = z.object({
  elfHeader: z.object({
    class: z.enum(['ELF32', 'ELF64']),
    data: z.enum(['LITTLE_ENDIAN', 'BIG_ENDIAN']),
    version: z.number().int(),
    osAbi: z.string(),
    type: z.enum(['EXEC', 'DYN', 'REL', 'CORE']),
    machine: z.string(),
    entryPoint: z.string(),
  }),
  programHeaders: z.array(
    z.object({
      type: z.string(),
      offset: z.number().int(),
      virtualAddress: z.string(),
      physicalAddress: z.string(),
      fileSize: z.number().int(),
      memorySize: z.number().int(),
      flags: z.array(z.string()),
    }),
  ),
  sectionHeaders: z.array(
    z.object({
      name: z.string(),
      type: z.string(),
      address: z.string(),
      offset: z.number().int(),
      size: z.number().int(),
      flags: z.array(z.string()),
    }),
  ),
  dynamicEntries: z
    .array(
      z.object({
        tag: z.string(),
        value: z.string(),
      }),
    )
    .optional(),
});

// ============================================
// GHIDRA TOOLS
// ============================================

// analyze_binary
export const AnalyzeBinaryInputSchema = z.object({
  binaryPath: z.string().describe('Absolute path to binary file'),
  options: z
    .object({
      maxFunctions: z.number().int().positive().optional().default(1000),
      includeDecompilation: z.boolean().optional().default(true),
      analyzeStrings: z.boolean().optional().default(true),
      detectPackers: z.boolean().optional().default(true),
    })
    .optional(),
});

export const AnalyzeBinaryOutputSchema = z.object({
  binaryPath: z.string(),
  fileInfo: z.object({
    format: z.enum(FILE_FORMATS),
    architecture: z.enum(ARCHITECTURES),
    size: z.number().int().nonnegative(),
    entropy: z.number().min(0).max(8),
  }),
  functions: z.array(
    z.object({
      name: z.string(),
      address: z.string(),
      size: z.number().int(),
      callers: z.array(z.string()),
      callees: z.array(z.string()),
      decompiled: z.string().optional(),
    }),
  ),
  imports: z.array(
    z.object({
      library: z.string(),
      function: z.string(),
      address: z.string().optional(),
    }),
  ),
  exports: z.array(
    z.object({
      name: z.string(),
      address: z.string(),
      ordinal: z.number().int().optional(),
    }),
  ),
  sections: z.array(
    z.object({
      name: z.string(),
      virtualAddress: z.string(),
      virtualSize: z.number().int(),
      rawSize: z.number().int(),
      entropy: z.number(),
      permissions: z.string(),
    }),
  ),
  strings: z.array(
    z.object({
      value: z.string(),
      address: z.string(),
      type: z.enum(STRING_TYPES),
    }),
  ),
  analysisMetadata: z.object({
    ghidraVersion: z.string(),
    analysisTime: z.number().int(),
    analyzedAt: z.string(),
    functionCount: z.number().int(),
  }),
});

// extract_strings
export const ExtractStringsInputSchema = z.object({
  binaryPath: z.string(),
  options: z
    .object({
      minLength: z.number().int().positive().optional().default(4),
      includeUnicode: z.boolean().optional().default(true),
      limit: z.number().int().positive().optional().default(10000),
    })
    .optional(),
});

export const ExtractStringsOutputSchema = z.object({
  strings: z.array(
    z.object({
      value: z.string(),
      offset: z.number().int(),
      type: z.enum(STRING_TYPES),
    }),
  ),
  statistics: z.object({
    totalStrings: z.number().int(),
    asciiCount: z.number().int(),
    unicodeCount: z.number().int(),
    suspiciousCount: z.number().int(),
  }),
  suspiciousStrings: z.array(
    z.object({
      value: z.string(),
      category: z.enum(['IP', 'URL', 'EMAIL', 'FILE_PATH', 'REGISTRY', 'API']),
      reason: z.string(),
    }),
  ),
});

// analyze_functions
export const AnalyzeFunctionsInputSchema = z.object({
  binaryPath: z.string(),
  functionAddresses: z.array(z.string()).describe('Array of function addresses to analyze'),
  options: z
    .object({
      includeDecompilation: z.boolean().optional().default(true),
      analyzeCalls: z.boolean().optional().default(true),
      analyzeDataFlow: z.boolean().optional().default(false),
    })
    .optional(),
});

export const AnalyzeFunctionsOutputSchema = z.object({
  functions: z.array(
    z.object({
      address: z.string(),
      name: z.string(),
      size: z.number().int(),
      decompiled: z.string(),
      assembly: z.string(),
      calls: z.array(
        z.object({
          target: z.string(),
          type: z.enum(['DIRECT', 'INDIRECT', 'JUMP_TABLE']),
        }),
      ),
      basicBlocks: z.number().int(),
      cyclomaticComplexity: z.number().int(),
      suspiciousPatterns: z.array(z.string()),
    }),
  ),
});

// detect_packing
export const DetectPackingInputSchema = z.object({
  binaryPath: z.string(),
  options: z
    .object({
      checkEntropy: z.boolean().optional().default(true),
      checkSignatures: z.boolean().optional().default(true),
      checkSectionNames: z.boolean().optional().default(true),
    })
    .optional(),
});

export const DetectPackingOutputSchema = z.object({
  isPacked: z.boolean(),
  confidence: z.number().min(0).max(1),
  indicators: z.array(
    z.object({
      type: z.enum(['ENTROPY', 'SIGNATURE', 'SECTION_NAME', 'IMPORT_RATIO']),
      value: z.unknown(),
      suspicious: z.boolean(),
      description: z.string(),
    }),
  ),
  identifiedPackers: z.array(
    z.object({
      name: z.string(),
      confidence: z.number().min(0).max(1),
    }),
  ),
});

// ============================================
// REPORT TOOLS
// ============================================

// generate_markdown_report
export const GenerateMarkdownReportInputSchema = z.object({
  analysisResults: z.object({
    binaryPath: z.string(),
    triageResults: z.unknown(),
    analysisResults: z.unknown(),
  }),
  options: z
    .object({
      includeExecutiveSummary: z.boolean().optional().default(true),
      includeFullFunctionList: z.boolean().optional().default(false),
      includeMitreMapping: z.boolean().optional().default(true),
      templateName: z.string().optional().default('standard'),
    })
    .optional(),
});

export const GenerateMarkdownReportOutputSchema = z.object({
  reportPath: z.string(),
  reportUrl: z.string().optional(),
});

// generate_json_report
export const GenerateJsonReportInputSchema = z.object({
  analysisResults: z.object({
    binaryPath: z.string(),
    triageResults: z.unknown(),
    analysisResults: z.unknown(),
  }),
  options: z
    .object({
      pretty: z.boolean().optional().default(true),
    })
    .optional(),
});

export const GenerateJsonReportOutputSchema = z.object({
  reportPath: z.string(),
  reportSize: z.number().int(),
});

// generate_stix_report
export const GenerateStixReportInputSchema = z.object({
  analysisResults: z.object({
    binaryPath: z.string(),
    triageResults: z.unknown(),
    analysisResults: z.unknown(),
  }),
  options: z
    .object({
      confidenceLevel: z.enum(CONFIDENCE_LEVELS).optional().default('MEDIUM'),
      tlpMarking: z.enum(TLP_MARKINGS).optional().default('AMBER'),
    })
    .optional(),
});

export const GenerateStixReportOutputSchema = z.object({
  reportPath: z.string(),
  stixVersion: z.string(),
  bundleId: z.string(),
});

// map_to_mitre_attack
export const MapToMitreAttackInputSchema = z.object({
  observations: z.object({
    imports: z.array(z.string()),
    strings: z.array(z.string()),
    functionNames: z.array(z.string()),
    behaviors: z.array(z.string()),
  }),
});

export const MapToMitreAttackOutputSchema = z.object({
  techniques: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      tactic: z.string(),
      confidence: z.number().min(0).max(1),
      evidence: z.array(z.string()),
    }),
  ),
  tactics: z.array(z.string()),
  navigatorLayer: z.object({
    name: z.string(),
    versions: z.object({
      attack: z.string(),
      navigator: z.string(),
      layer: z.string(),
    }),
    domain: z.string(),
    techniques: z.array(z.unknown()),
  }),
});

// ============================================
// TYPE EXPORTS
// ============================================

export type CalculateHashesInput = z.infer<typeof CalculateHashesInputSchema>;
export type CalculateHashesOutput = z.infer<typeof CalculateHashesOutputSchema>;
export type DetectFileTypeInput = z.infer<typeof DetectFileTypeInputSchema>;
export type DetectFileTypeOutput = z.infer<typeof DetectFileTypeOutputSchema>;
export type ExtractPEHeadersInput = z.infer<typeof ExtractPEHeadersInputSchema>;
export type ExtractPEHeadersOutput = z.infer<typeof ExtractPEHeadersOutputSchema>;
export type ExtractELFHeadersInput = z.infer<typeof ExtractELFHeadersInputSchema>;
export type ExtractELFHeadersOutput = z.infer<typeof ExtractELFHeadersOutputSchema>;
export type AnalyzeBinaryInput = z.infer<typeof AnalyzeBinaryInputSchema>;
export type AnalyzeBinaryOutput = z.infer<typeof AnalyzeBinaryOutputSchema>;
export type ExtractStringsInput = z.infer<typeof ExtractStringsInputSchema>;
export type ExtractStringsOutput = z.infer<typeof ExtractStringsOutputSchema>;
export type AnalyzeFunctionsInput = z.infer<typeof AnalyzeFunctionsInputSchema>;
export type AnalyzeFunctionsOutput = z.infer<typeof AnalyzeFunctionsOutputSchema>;
export type DetectPackingInput = z.infer<typeof DetectPackingInputSchema>;
export type DetectPackingOutput = z.infer<typeof DetectPackingOutputSchema>;
export type GenerateMarkdownReportInput = z.infer<typeof GenerateMarkdownReportInputSchema>;
export type GenerateMarkdownReportOutput = z.infer<typeof GenerateMarkdownReportOutputSchema>;
export type GenerateJsonReportInput = z.infer<typeof GenerateJsonReportInputSchema>;
export type GenerateJsonReportOutput = z.infer<typeof GenerateJsonReportOutputSchema>;
export type GenerateStixReportInput = z.infer<typeof GenerateStixReportInputSchema>;
export type GenerateStixReportOutput = z.infer<typeof GenerateStixReportOutputSchema>;
export type MapToMitreAttackInput = z.infer<typeof MapToMitreAttackInputSchema>;
export type MapToMitreAttackOutput = z.infer<typeof MapToMitreAttackOutputSchema>;

// ============================================
// LOWERCASE ALIASES (for consistency with tool implementations)
// ============================================

export const calculateHashesInputSchema = CalculateHashesInputSchema;
export const calculateHashesOutputSchema = CalculateHashesOutputSchema;
export const detectFileTypeInputSchema = DetectFileTypeInputSchema;
export const detectFileTypeOutputSchema = DetectFileTypeOutputSchema;
export const extractPEHeadersInputSchema = ExtractPEHeadersInputSchema;
export const extractPEHeadersOutputSchema = ExtractPEHeadersOutputSchema;
export const extractELFHeadersInputSchema = ExtractELFHeadersInputSchema;
export const extractELFHeadersOutputSchema = ExtractELFHeadersOutputSchema;
export const analyzeBinaryInputSchema = AnalyzeBinaryInputSchema;
export const analyzeBinaryOutputSchema = AnalyzeBinaryOutputSchema;
export const extractStringsInputSchema = ExtractStringsInputSchema;
export const extractStringsOutputSchema = ExtractStringsOutputSchema;
export const analyzeFunctionsInputSchema = AnalyzeFunctionsInputSchema;
export const analyzeFunctionsOutputSchema = AnalyzeFunctionsOutputSchema;
export const detectPackingInputSchema = DetectPackingInputSchema;
export const detectPackingOutputSchema = DetectPackingOutputSchema;
export const generateMarkdownReportInputSchema = GenerateMarkdownReportInputSchema;
export const generateMarkdownReportOutputSchema = GenerateMarkdownReportOutputSchema;
export const generateJsonReportInputSchema = GenerateJsonReportInputSchema;
export const generateJsonReportOutputSchema = GenerateJsonReportOutputSchema;
export const generateStixReportInputSchema = GenerateStixReportInputSchema;
export const generateStixReportOutputSchema = GenerateStixReportOutputSchema;
export const mapToMitreAttackInputSchema = MapToMitreAttackInputSchema;
export const mapToMitreAttackOutputSchema = MapToMitreAttackOutputSchema;
