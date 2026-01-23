/**
 * Crypto Detector
 *
 * Detects cryptographic operations in binaries through:
 * - Constant signatures (AES S-boxes, ChaCha20/Poly1305, prime numbers, etc.)
 * - Entropy analysis of data blocks
 * - Pattern matching for crypto algorithms
 * - Custom encryption detection via entropy + structure analysis
 * - Certificate and key extraction
 *
 * @module utils/crypto-detector
 *
 * @todo Phase 4: Add ransomware key extraction attempts
 * @todo Phase 4: Add hardware crypto instruction analysis (AES-NI)
 */

import { getLogger } from '@logtape/logtape';

const logger = getLogger(['sentinel', 'crypto-detector']);

// ============================================
// TYPES
// ============================================

/**
 * Cryptographic algorithm categories
 */
export type CryptoAlgorithm =
  | 'aes'
  | 'des'
  | 'blowfish'
  | 'rc4'
  | 'rsa'
  | 'sha1'
  | 'sha256'
  | 'sha512'
  | 'md5'
  | 'crc32'
  | 'chacha20'
  | 'base64'
  | 'xor'
  | 'unknown';

/**
 * Crypto detection result
 */
export type CryptoDetection = {
  /** Detected algorithm */
  algorithm: CryptoAlgorithm;
  /** Confidence level (0-1) */
  confidence: number;
  /** Detection method */
  method: 'constant' | 'entropy' | 'pattern' | 'instruction';
  /** File offset where detected */
  offset?: number;
  /** Size of detected block */
  size?: number;
  /** Additional details */
  details: string;
};

/**
 * Crypto analysis summary
 */
export type CryptoAnalysisSummary = {
  /** All detections */
  detections: CryptoDetection[];
  /** Whether any crypto was found */
  hasCrypto: boolean;
  /** Summary by algorithm */
  algorithmCounts: Record<CryptoAlgorithm, number>;
  /** High-confidence detections */
  highConfidence: CryptoDetection[];
  /** Likely encryption/obfuscation */
  likelyEncrypted: boolean;
  /** Custom encryption indicators */
  customEncryption?: CustomEncryptionIndicator[];
  /** Extracted certificates */
  certificates?: ExtractedCertificate[];
  /** Extracted cryptographic keys */
  extractedKeys?: ExtractedKey[];
};

/**
 * Custom encryption indicator
 */
export type CustomEncryptionIndicator = {
  /** Type of custom encryption pattern */
  type:
    | 'rolling-xor'
    | 'custom-block'
    | 'obfuscated-strings'
    | 'packed-data'
    | 'encrypted-resource';
  /** Confidence level (0-1) */
  confidence: number;
  /** Offset in file */
  offset: number;
  /** Size of encrypted region */
  size: number;
  /** Evidence for detection */
  evidence: string;
  /** Entropy of the block */
  entropy: number;
  /** Suggested key size if detectable */
  suggestedKeySize?: number;
};

/**
 * Extracted certificate from binary
 */
export type ExtractedCertificate = {
  /** Certificate format */
  format: 'x509' | 'pkcs7' | 'pkcs12' | 'pem' | 'der';
  /** Subject distinguished name */
  subject?: string;
  /** Issuer distinguished name */
  issuer?: string;
  /** Serial number (hex) */
  serialNumber?: string;
  /** Not valid before date */
  notBefore?: string;
  /** Not valid after date */
  notAfter?: string;
  /** Whether certificate is self-signed */
  isSelfSigned?: boolean;
  /** SHA-256 fingerprint */
  fingerprint?: string;
  /** File offset where found */
  offset: number;
  /** Size in bytes */
  size: number;
  /** Raw certificate data (base64) */
  rawData?: string;
};

/**
 * Extracted cryptographic key
 */
export type ExtractedKey = {
  /** Key type */
  type: 'rsa-public' | 'rsa-private' | 'ec-public' | 'ec-private' | 'symmetric' | 'unknown';
  /** Key format */
  format: 'pem' | 'der' | 'raw' | 'pkcs8';
  /** Key size in bits */
  keySize?: number;
  /** Algorithm if identifiable */
  algorithm?: string;
  /** File offset where found */
  offset: number;
  /** Size in bytes */
  size: number;
  /** Whether key appears to be valid/usable */
  appearsValid: boolean;
  /** Key fingerprint if calculable */
  fingerprint?: string;
};

/**
 * Detector configuration
 */
export type CryptoDetectorConfig = {
  /** Minimum block size to analyze */
  minBlockSize: number;
  /** Maximum blocks to check */
  maxBlocks: number;
  /** Entropy threshold for "encrypted" blocks */
  entropyThreshold: number;
  /** Minimum confidence to report */
  minConfidence: number;
};

// ============================================
// DEFAULT CONFIGURATION
// ============================================

const DEFAULT_CONFIG: CryptoDetectorConfig = {
  minBlockSize: 16,
  maxBlocks: 100,
  entropyThreshold: 7.5,
  minConfidence: 0.5,
};

// ============================================
// CRYPTOGRAPHIC CONSTANTS
// ============================================

/**
 * Crypto constant signature for detection
 */
type CryptoConstant = {
  algorithm: CryptoAlgorithm;
  name: string;
  /** First N bytes of constant (for matching) */
  signature: number[];
  /** Full constant length */
  length: number;
  confidence: number;
};

/**
 * Well-known cryptographic constants
 */
const CRYPTO_CONSTANTS: CryptoConstant[] = [
  // AES S-box (first 16 bytes)
  {
    algorithm: 'aes',
    name: 'AES S-box',
    signature: [
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
      0x76,
    ],
    length: 256,
    confidence: 0.95,
  },

  // AES inverse S-box (first 16 bytes)
  {
    algorithm: 'aes',
    name: 'AES Inverse S-box',
    signature: [
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
      0xfb,
    ],
    length: 256,
    confidence: 0.95,
  },

  // DES S-box 1 (first 16 bytes of S1)
  {
    algorithm: 'des',
    name: 'DES S-box',
    signature: [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    length: 64,
    confidence: 0.85,
  },

  // MD5 sine constants (first 4 values, as little-endian uint32)
  {
    algorithm: 'md5',
    name: 'MD5 Constants',
    signature: [0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8],
    length: 256,
    confidence: 0.9,
  },

  // SHA-256 initial hash values (first 8 bytes)
  {
    algorithm: 'sha256',
    name: 'SHA-256 Initial Values',
    signature: [0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb],
    length: 32,
    confidence: 0.9,
  },

  // SHA-1 initial hash values
  {
    algorithm: 'sha1',
    name: 'SHA-1 Initial Values',
    signature: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
    length: 20,
    confidence: 0.85,
  },

  // Blowfish P-array initial values
  {
    algorithm: 'blowfish',
    name: 'Blowfish P-array',
    signature: [0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3],
    length: 72,
    confidence: 0.85,
  },

  // CRC32 polynomial table (first bytes)
  {
    algorithm: 'crc32',
    name: 'CRC32 Table',
    signature: [0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77],
    length: 1024,
    confidence: 0.8,
  },

  // ChaCha20 "expand 32-byte k" constant (sigma)
  {
    algorithm: 'chacha20',
    name: 'ChaCha20 Sigma',
    signature: [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33], // "expand 3"
    length: 16,
    confidence: 0.9,
  },

  // ChaCha20 "expand 16-byte k" constant (tau)
  {
    algorithm: 'chacha20',
    name: 'ChaCha20 Tau',
    signature: [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x31], // "expand 1"
    length: 16,
    confidence: 0.85,
  },

  // Base64 alphabet
  {
    algorithm: 'base64',
    name: 'Base64 Alphabet',
    signature: [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48], // "ABCDEFGH"
    length: 64,
    confidence: 0.6,
  },

  // RC4 initial state (0-255)
  {
    algorithm: 'rc4',
    name: 'RC4 Initial State',
    signature: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    length: 256,
    confidence: 0.5, // Lower - could be any sequential array
  },
];

// ============================================
// CRYPTO DETECTOR CLASS
// ============================================

export class CryptoDetector {
  private readonly config: CryptoDetectorConfig;

  constructor(config: Partial<CryptoDetectorConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Analyze binary data for cryptographic operations
   */
  analyze(data: Uint8Array): CryptoAnalysisSummary {
    logger.debug`Analyzing ${data.length} bytes for crypto signatures`;

    const detections: CryptoDetection[] = [];

    // Search for known constants
    const constantDetections = this.findConstants(data);
    detections.push(...constantDetections);

    // Analyze entropy of data blocks
    const entropyDetections = this.analyzeEntropy(data);
    detections.push(...entropyDetections);

    // Detect custom encryption patterns
    const customEncryption = this.detectCustomEncryption(data);

    // Extract certificates and keys
    const certificates = this.extractCertificates(data);
    const extractedKeys = this.extractKeys(data);

    // Filter by confidence
    const filtered = detections.filter((d) => d.confidence >= this.config.minConfidence);

    // Build algorithm counts
    const algorithmCounts = {} as Record<CryptoAlgorithm, number>;
    for (const detection of filtered) {
      algorithmCounts[detection.algorithm] = (algorithmCounts[detection.algorithm] || 0) + 1;
    }

    // Determine if likely encrypted
    const highEntropy = entropyDetections.some((d) => d.confidence > 0.8);
    const hasStrongCrypto = filtered.some(
      (d) => d.confidence > 0.9 && ['aes', 'des', 'blowfish', 'chacha20'].includes(d.algorithm),
    );
    const hasCustomEncryption = customEncryption.some((c) => c.confidence > 0.7);

    return {
      detections: filtered,
      hasCrypto: filtered.length > 0 || certificates.length > 0 || extractedKeys.length > 0,
      algorithmCounts,
      highConfidence: filtered.filter((d) => d.confidence >= 0.8),
      likelyEncrypted: highEntropy || hasStrongCrypto || hasCustomEncryption,
      customEncryption: customEncryption.length > 0 ? customEncryption : undefined,
      certificates: certificates.length > 0 ? certificates : undefined,
      extractedKeys: extractedKeys.length > 0 ? extractedKeys : undefined,
    };
  }

  /**
   * Search for known cryptographic constants in data
   */
  findConstants(data: Uint8Array): CryptoDetection[] {
    const detections: CryptoDetection[] = [];

    for (const constant of CRYPTO_CONSTANTS) {
      const offset = this.findSignature(data, constant.signature);

      if (offset !== -1) {
        detections.push({
          algorithm: constant.algorithm,
          confidence: constant.confidence,
          method: 'constant',
          offset,
          size: constant.length,
          details: `Found ${constant.name} at offset 0x${offset.toString(16)}`,
        });

        logger.info`Detected ${constant.name} at offset 0x${offset.toString(16)}`;
      }
    }

    return detections;
  }

  /**
   * Find signature bytes in data
   */
  private findSignature(data: Uint8Array, signature: number[]): number {
    if (signature.length === 0 || data.length < signature.length) {
      return -1;
    }

    outer: for (let i = 0; i <= data.length - signature.length; i++) {
      for (let j = 0; j < signature.length; j++) {
        if (data[i + j] !== signature[j]) {
          continue outer;
        }
      }
      return i;
    }

    return -1;
  }

  /**
   * Analyze entropy of data blocks for potential encryption
   */
  analyzeEntropy(data: Uint8Array): CryptoDetection[] {
    const detections: CryptoDetection[] = [];
    const blockSize = 256;
    const blocksToCheck = Math.min(Math.floor(data.length / blockSize), this.config.maxBlocks);

    let highEntropyBlocks = 0;
    let totalEntropy = 0;

    for (let i = 0; i < blocksToCheck; i++) {
      const start = i * blockSize;
      const block = data.slice(start, start + blockSize);
      const entropy = this.calculateEntropy(block);
      totalEntropy += entropy;

      if (entropy > this.config.entropyThreshold) {
        highEntropyBlocks++;
      }
    }

    if (blocksToCheck > 0) {
      const avgEntropy = totalEntropy / blocksToCheck;
      const highEntropyRatio = highEntropyBlocks / blocksToCheck;

      if (highEntropyRatio > 0.5) {
        detections.push({
          algorithm: 'unknown',
          confidence: Math.min(highEntropyRatio, 0.95),
          method: 'entropy',
          details: `High entropy detected: ${(highEntropyRatio * 100).toFixed(1)}% of blocks have entropy > ${this.config.entropyThreshold}. Average: ${avgEntropy.toFixed(2)}`,
        });
      }
    }

    return detections;
  }

  /**
   * Calculate Shannon entropy of data block
   */
  calculateEntropy(data: Uint8Array): number {
    if (data.length === 0) return 0;

    const frequency = new Array<number>(256).fill(0);
    for (const byte of data) {
      const current = frequency[byte];
      if (current !== undefined) {
        frequency[byte] = current + 1;
      }
    }

    let entropy = 0;
    const len = data.length;

    for (const count of frequency) {
      if (count > 0) {
        const probability = count / len;
        entropy -= probability * Math.log2(probability);
      }
    }

    return entropy;
  }

  /**
   * Detect custom encryption patterns through entropy and structure analysis
   */
  detectCustomEncryption(data: Uint8Array): CustomEncryptionIndicator[] {
    const indicators: CustomEncryptionIndicator[] = [];
    const blockSize = 256;
    const minHighEntropyRun = 3; // Minimum consecutive high-entropy blocks

    // Analyze for high-entropy regions that look like custom encryption
    let currentRun = 0;
    let runStart = 0;
    let runEntropy = 0;

    for (let i = 0; i < data.length - blockSize; i += blockSize) {
      const block = data.slice(i, i + blockSize);
      const entropy = this.calculateEntropy(block);

      if (entropy > 7.0) {
        if (currentRun === 0) {
          runStart = i;
          runEntropy = 0;
        }
        currentRun++;
        runEntropy += entropy;
      } else if (currentRun >= minHighEntropyRun) {
        // End of high-entropy run
        const avgEntropy = runEntropy / currentRun;
        const runSize = currentRun * blockSize;

        // Check if it looks like custom block encryption (aligned blocks)
        const isBlockAligned = runStart % 16 === 0 && runSize % 16 === 0;
        const encryptionType = this.classifyEncryptedRegion(
          data.slice(runStart, runStart + runSize),
          avgEntropy,
          isBlockAligned,
        );

        indicators.push({
          type: encryptionType,
          confidence: Math.min(0.5 + (avgEntropy - 7.0) * 0.3, 0.9),
          offset: runStart,
          size: runSize,
          evidence: `High entropy region (${avgEntropy.toFixed(2)}) spanning ${runSize} bytes`,
          entropy: avgEntropy,
          suggestedKeySize: isBlockAligned ? (runSize % 32 === 0 ? 256 : 128) : undefined,
        });

        currentRun = 0;
      } else {
        currentRun = 0;
      }
    }

    // Detect rolling XOR (repeating patterns in XOR output)
    const rollingXorIndicators = this.detectRollingXor(data);
    indicators.push(...rollingXorIndicators);

    // Detect obfuscated strings (high entropy interspersed with structure)
    const obfuscatedStrings = this.detectObfuscatedStrings(data);
    indicators.push(...obfuscatedStrings);

    return indicators;
  }

  /**
   * Classify an encrypted region based on its characteristics
   */
  private classifyEncryptedRegion(
    _data: Uint8Array,
    entropy: number,
    isBlockAligned: boolean,
  ): CustomEncryptionIndicator['type'] {
    if (isBlockAligned && entropy > 7.8) {
      return 'custom-block';
    }
    if (entropy > 7.5) {
      return 'encrypted-resource';
    }
    return 'packed-data';
  }

  /**
   * Detect rolling/multi-byte XOR encryption
   */
  private detectRollingXor(data: Uint8Array): CustomEncryptionIndicator[] {
    const indicators: CustomEncryptionIndicator[] = [];
    const sampleSize = Math.min(data.length, 4096);
    const sample = data.slice(0, sampleSize);

    // Try common rolling XOR key lengths (4, 8, 16, 32 bytes)
    for (const keyLen of [4, 8, 16, 32]) {
      if (sampleSize < keyLen * 3) continue;

      // Look for repeating patterns at key length intervals
      let matches = 0;
      let checks = 0;

      for (let i = 0; i < sampleSize - keyLen * 2; i += keyLen) {
        const b1 = sample[i];
        const b2 = sample[i + keyLen];
        const b3 = sample[i + keyLen * 2];
        if (b1 !== undefined && b2 !== undefined && b3 !== undefined) {
          // Check if XOR pattern repeats
          const diff1 = b1 ^ b2;
          const diff2 = b2 ^ b3;
          if (diff1 === diff2 && diff1 !== 0) {
            matches++;
          }
          checks++;
        }
      }

      if (checks > 0 && matches / checks > 0.3) {
        indicators.push({
          type: 'rolling-xor',
          confidence: 0.6 + (matches / checks) * 0.3,
          offset: 0,
          size: sampleSize,
          evidence: `Rolling XOR pattern detected with likely key size ${keyLen} bytes (${((matches / checks) * 100).toFixed(1)}% pattern match)`,
          entropy: this.calculateEntropy(sample),
          suggestedKeySize: keyLen * 8,
        });
        break; // Only report first detected key length
      }
    }

    return indicators;
  }

  /**
   * Detect obfuscated strings (mixed high/low entropy regions)
   */
  private detectObfuscatedStrings(data: Uint8Array): CustomEncryptionIndicator[] {
    const indicators: CustomEncryptionIndicator[] = [];
    const windowSize = 64;
    const step = 32;

    let transitions = 0;
    let lastHighEntropy = false;

    for (let i = 0; i < data.length - windowSize; i += step) {
      const window = data.slice(i, i + windowSize);
      const entropy = this.calculateEntropy(window);
      const isHighEntropy = entropy > 5.5;

      if (i > 0 && isHighEntropy !== lastHighEntropy) {
        transitions++;
      }
      lastHighEntropy = isHighEntropy;
    }

    const transitionRate = transitions / (data.length / step);

    // High transition rate indicates obfuscated strings (encrypted interspersed with code)
    if (transitionRate > 0.2) {
      indicators.push({
        type: 'obfuscated-strings',
        confidence: Math.min(0.4 + transitionRate * 2, 0.85),
        offset: 0,
        size: data.length,
        evidence: `High entropy transitions (${(transitionRate * 100).toFixed(1)}% rate) suggest obfuscated strings`,
        entropy: this.calculateEntropy(data.slice(0, Math.min(data.length, 4096))),
      });
    }

    return indicators;
  }

  /**
   * Extract X.509 certificates from binary data
   */
  extractCertificates(data: Uint8Array): ExtractedCertificate[] {
    const certificates: ExtractedCertificate[] = [];

    // DER certificate magic: 0x30 0x82 (SEQUENCE with 2-byte length)
    const derMagic = [0x30, 0x82];

    // PEM certificate markers
    const pemBegin = this.findAsciiString(data, '-----BEGIN CERTIFICATE-----');
    const pemEnd = this.findAsciiString(data, '-----END CERTIFICATE-----');

    // Search for DER certificates
    for (let i = 0; i < data.length - 4; i++) {
      if (data[i] === derMagic[0] && data[i + 1] === derMagic[1]) {
        // Read length (2 bytes big-endian)
        const lenHigh = data[i + 2];
        const lenLow = data[i + 3];
        if (lenHigh === undefined || lenLow === undefined) continue;

        const certLen = (lenHigh << 8) | lenLow;
        const totalLen = certLen + 4; // Include header

        // Sanity check length
        if (totalLen > 50 && totalLen < 10000 && i + totalLen <= data.length) {
          // Check for certificate structure indicators
          const certData = data.slice(i, i + totalLen);
          if (this.looksLikeCertificate(certData)) {
            certificates.push({
              format: 'der',
              offset: i,
              size: totalLen,
              rawData: this.bufferToBase64(certData),
            });
            i += totalLen - 1; // Skip past this certificate
          }
        }
      }
    }

    // Search for PEM certificates
    for (const beginOffset of pemBegin) {
      for (const endOffset of pemEnd) {
        if (endOffset > beginOffset && endOffset - beginOffset < 10000) {
          const pemSize = endOffset - beginOffset + 25; // Include END marker
          certificates.push({
            format: 'pem',
            offset: beginOffset,
            size: pemSize,
          });
          break;
        }
      }
    }

    return certificates;
  }

  /**
   * Extract cryptographic keys from binary data
   */
  extractKeys(data: Uint8Array): ExtractedKey[] {
    const keys: ExtractedKey[] = [];

    // RSA public key markers
    const rsaPubPem = this.findAsciiString(data, '-----BEGIN PUBLIC KEY-----');
    const rsaPrivPem = this.findAsciiString(data, '-----BEGIN RSA PRIVATE KEY-----');
    const pkcs8Pem = this.findAsciiString(data, '-----BEGIN PRIVATE KEY-----');
    const ecPem = this.findAsciiString(data, '-----BEGIN EC PRIVATE KEY-----');

    // PEM RSA public keys
    for (const offset of rsaPubPem) {
      const endMarkers = this.findAsciiString(data.slice(offset), '-----END PUBLIC KEY-----');
      if (endMarkers.length > 0) {
        const size = (endMarkers[0] ?? 0) + 24;
        keys.push({
          type: 'rsa-public',
          format: 'pem',
          offset,
          size,
          appearsValid: true,
        });
      }
    }

    // PEM RSA private keys
    for (const offset of rsaPrivPem) {
      const endMarkers = this.findAsciiString(data.slice(offset), '-----END RSA PRIVATE KEY-----');
      if (endMarkers.length > 0) {
        const size = (endMarkers[0] ?? 0) + 28;
        keys.push({
          type: 'rsa-private',
          format: 'pem',
          offset,
          size,
          appearsValid: true,
          keySize: this.estimateRsaKeySize(data.slice(offset, offset + size)),
        });
      }
    }

    // PKCS#8 private keys
    for (const offset of pkcs8Pem) {
      const endMarkers = this.findAsciiString(data.slice(offset), '-----END PRIVATE KEY-----');
      if (endMarkers.length > 0) {
        const size = (endMarkers[0] ?? 0) + 24;
        keys.push({
          type: 'rsa-private',
          format: 'pkcs8',
          offset,
          size,
          appearsValid: true,
        });
      }
    }

    // EC private keys
    for (const offset of ecPem) {
      const endMarkers = this.findAsciiString(data.slice(offset), '-----END EC PRIVATE KEY-----');
      if (endMarkers.length > 0) {
        const size = (endMarkers[0] ?? 0) + 26;
        keys.push({
          type: 'ec-private',
          format: 'pem',
          offset,
          size,
          appearsValid: true,
        });
      }
    }

    // DER-encoded RSA public key (OID 1.2.840.113549.1.1.1)
    const rsaOid = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    const oidOffsets = this.findBytes(data, rsaOid);
    for (const oidOffset of oidOffsets) {
      // Look backwards for SEQUENCE header
      if (oidOffset > 4 && data[oidOffset - 4] === 0x30) {
        const startOffset = oidOffset - 4;
        keys.push({
          type: 'rsa-public',
          format: 'der',
          offset: startOffset,
          size: 200, // Estimate
          appearsValid: true,
          algorithm: 'RSA',
        });
      }
    }

    return keys;
  }

  /**
   * Check if data looks like a certificate structure
   */
  private looksLikeCertificate(data: Uint8Array): boolean {
    // Look for common certificate OIDs
    const commonOids = [
      [0x55, 0x04, 0x03], // Common Name
      [0x55, 0x04, 0x06], // Country
      [0x55, 0x04, 0x0a], // Organization
    ];

    for (const oid of commonOids) {
      if (this.findBytes(data, oid).length > 0) {
        return true;
      }
    }

    return false;
  }

  /**
   * Find ASCII string in binary data
   */
  private findAsciiString(data: Uint8Array, str: string): number[] {
    const offsets: number[] = [];
    const bytes = new TextEncoder().encode(str);

    outer: for (let i = 0; i <= data.length - bytes.length; i++) {
      for (let j = 0; j < bytes.length; j++) {
        if (data[i + j] !== bytes[j]) {
          continue outer;
        }
      }
      offsets.push(i);
    }

    return offsets;
  }

  /**
   * Find byte sequence in data
   */
  private findBytes(data: Uint8Array, bytes: number[]): number[] {
    const offsets: number[] = [];

    outer: for (let i = 0; i <= data.length - bytes.length; i++) {
      for (let j = 0; j < bytes.length; j++) {
        if (data[i + j] !== bytes[j]) {
          continue outer;
        }
      }
      offsets.push(i);
    }

    return offsets;
  }

  /**
   * Convert Uint8Array to base64 string
   */
  private bufferToBase64(data: Uint8Array): string {
    return Buffer.from(data).toString('base64');
  }

  /**
   * Estimate RSA key size from PEM data
   */
  private estimateRsaKeySize(pemData: Uint8Array): number | undefined {
    const size = pemData.length;
    // Rough estimates based on PEM key sizes
    if (size < 500) return 512;
    if (size < 900) return 1024;
    if (size < 1700) return 2048;
    if (size < 3200) return 4096;
    return 4096;
  }

  /**
   * Check for XOR encryption patterns
   */
  detectXOR(data: Uint8Array): CryptoDetection[] {
    const detections: CryptoDetection[] = [];

    // Look for single-byte XOR with common keys
    const commonXorKeys = [0xff, 0xaa, 0x55, 0x00];

    for (const key of commonXorKeys) {
      if (key === 0) continue; // Skip null XOR

      // XOR decode and check for readable strings
      const decoded = new Uint8Array(Math.min(data.length, 1000));
      let printableCount = 0;

      for (let i = 0; i < decoded.length; i++) {
        const dataByte = data[i];
        if (dataByte !== undefined) {
          decoded[i] = dataByte ^ key;
          const decodedByte = decoded[i];
          if (decodedByte !== undefined && decodedByte >= 0x20 && decodedByte <= 0x7e) {
            printableCount++;
          }
        }
      }

      const printableRatio = printableCount / decoded.length;
      if (printableRatio > 0.6) {
        detections.push({
          algorithm: 'xor',
          confidence: Math.min(printableRatio, 0.85),
          method: 'pattern',
          details: `Single-byte XOR key 0x${key.toString(16)} produces ${(printableRatio * 100).toFixed(1)}% printable characters`,
        });
      }
    }

    return detections;
  }
}

// ============================================
// SINGLETON ACCESSOR
// ============================================

let detectorInstance: CryptoDetector | null = null;

/**
 * Get or create crypto detector instance
 */
export function getCryptoDetector(config?: Partial<CryptoDetectorConfig>): CryptoDetector {
  if (!detectorInstance || config) {
    detectorInstance = new CryptoDetector(config);
  }
  return detectorInstance;
}
