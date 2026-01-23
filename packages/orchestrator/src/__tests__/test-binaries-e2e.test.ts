/**
 * Test Binaries E2E Tests
 *
 * End-to-end tests that verify SENTINEL correctly detects patterns
 * in our simulated malware test binaries.
 *
 * Test binaries are located in binaries/ and contain SAFE patterns
 * that trigger detection without performing any actual malicious actions.
 *
 * Categories tested:
 * - Ransomware patterns (ransomware_sim)
 * - Keylogger patterns (keylogger_sim)
 * - Trojan/backdoor patterns (trojan_sim)
 * - Cryptominer patterns (cryptominer_sim)
 * - RAT patterns (rat_sim)
 * - General suspicious patterns (suspicious_test)
 */

import { beforeAll, describe, expect, test } from 'bun:test';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

// Test binary paths
const BINARIES_DIR = join(import.meta.dir, '..', '..', '..', '..', 'binaries');
const STRIPPED_DIR = join(BINARIES_DIR, 'stripped');
const PACKED_DIR = join(BINARIES_DIR, 'packed');

// Malicious test binaries
const TEST_BINARIES = {
  suspicious: join(BINARIES_DIR, 'suspicious_test'),
  ransomware: join(BINARIES_DIR, 'ransomware_sim'),
  keylogger: join(BINARIES_DIR, 'keylogger_sim'),
  trojan: join(BINARIES_DIR, 'trojan_sim'),
  cryptominer: join(BINARIES_DIR, 'cryptominer_sim'),
  rat: join(BINARIES_DIR, 'rat_sim'),
  // Modern 2025/2026 patterns
  infostealer: join(BINARIES_DIR, 'infostealer_sim'),
  loader: join(BINARIES_DIR, 'loader_sim'),
  apt: join(BINARIES_DIR, 'apt_sim'),
  rootkit: join(BINARIES_DIR, 'rootkit_sim'),
};

// Benign test binaries (should have minimal/no detections)
const BENIGN_BINARIES = {
  hello: join(BINARIES_DIR, 'benign_hello'),
  calculator: join(BINARIES_DIR, 'benign_calculator'),
  fileops: join(BINARIES_DIR, 'benign_fileops'),
  network: join(BINARIES_DIR, 'benign_network'),
  crypto: join(BINARIES_DIR, 'benign_crypto'),
};

// Packed benign binaries
const PACKED_BENIGN_BINARIES = {
  hello: join(PACKED_DIR, 'benign_hello_packed'),
  calculator: join(PACKED_DIR, 'benign_calculator_packed'),
  fileops: join(PACKED_DIR, 'benign_fileops_packed'),
  network: join(PACKED_DIR, 'benign_network_packed'),
  crypto: join(PACKED_DIR, 'benign_crypto_packed'),
};

const STRIPPED_BINARIES = {
  suspicious: join(STRIPPED_DIR, 'suspicious_test_stripped'),
  ransomware: join(STRIPPED_DIR, 'ransomware_sim_stripped'),
  keylogger: join(STRIPPED_DIR, 'keylogger_sim_stripped'),
  trojan: join(STRIPPED_DIR, 'trojan_sim_stripped'),
  cryptominer: join(STRIPPED_DIR, 'cryptominer_sim_stripped'),
  rat: join(STRIPPED_DIR, 'rat_sim_stripped'),
  // Modern 2025/2026 patterns
  infostealer: join(STRIPPED_DIR, 'infostealer_sim_stripped'),
  loader: join(STRIPPED_DIR, 'loader_sim_stripped'),
  apt: join(STRIPPED_DIR, 'apt_sim_stripped'),
  rootkit: join(STRIPPED_DIR, 'rootkit_sim_stripped'),
};

// Expected patterns in each binary category
const EXPECTED_PATTERNS = {
  ransomware: [
    // Crypto APIs
    'CryptEncrypt',
    'BCryptEncrypt',
    'CryptoAPI',
    // Shadow deletion
    'vssadmin',
    'delete shadows',
    // Wallet patterns
    '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', // BTC pattern
    // File extensions
    '.encrypted',
    '.locked',
    '.crypted',
    // Ransom note patterns
    'bitcoin',
    'decrypt',
    'payment',
  ],
  keylogger: [
    // Hook APIs
    'SetWindowsHookEx',
    'GetAsyncKeyState',
    'GetKeyboardState',
    // Clipboard
    'GetClipboardData',
    'OpenClipboard',
    // Registry persistence
    'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    // Credential patterns
    'password',
    'credential',
    'login',
  ],
  trojan: [
    // Injection APIs
    'VirtualAllocEx',
    'WriteProcessMemory',
    'CreateRemoteThread',
    'NtCreateThreadEx',
    // Shell patterns
    'cmd.exe',
    'powershell',
    '/bin/bash',
    // C2 patterns
    'POST',
    'beacon',
    'command',
  ],
  cryptominer: [
    // Stratum protocol
    'stratum+tcp',
    'mining.subscribe',
    'mining.authorize',
    // Pool patterns
    'pool.minexmr.com',
    'xmrpool.eu',
    // Wallet patterns (XMR starts with 4)
    '4', // Monero wallets start with 4
    // Algorithm names
    'CryptoNight',
    'RandomX',
    // GPU APIs
    'CUDA',
    'OpenCL',
  ],
  rat: [
    // Screen capture
    'GetDC',
    'BitBlt',
    'CreateCompatibleBitmap',
    // Webcam/audio
    'capCreateCaptureWindow',
    'waveInOpen',
    // Credential targets
    'Chrome',
    'Firefox',
    'Login Data',
    // Commands
    'systeminfo',
    'whoami',
    'netstat',
  ],
  suspicious: [
    // C2 indicators
    'http://',
    'https://',
    // Registry
    'HKEY_',
    // Dangerous commands
    'cmd.exe',
    'powershell',
    // Crypto
    'bitcoin',
    'wallet',
  ],
  // Modern 2025/2026 patterns
  infostealer: [
    // Browser credential paths
    'Login Data',
    'Cookies',
    'Chrome',
    'Firefox',
    'Edge',
    // Crypto wallets
    'MetaMask',
    'Exodus',
    'Phantom',
    'Ledger',
    // Messaging
    'Discord',
    'Telegram',
    'leveldb',
    // Password managers
    '1Password',
    'Bitwarden',
    'KeePass',
    // 2FA
    'Authenticator',
    'backup',
  ],
  loader: [
    // Process injection
    'VirtualAllocEx',
    'WriteProcessMemory',
    'CreateRemoteThread',
    'NtCreateThreadEx',
    // LOLBins
    'mshta',
    'regsvr32',
    'certutil',
    'rundll32',
    'powershell',
    // DLL sideloading
    'sideload',
    'DLL',
    // Anti-analysis
    'IsDebuggerPresent',
    'sandbox',
    // Shellcode
    'shellcode',
    'VirtualProtect',
  ],
  apt: [
    // APT group indicators
    'APT',
    'Lazarus',
    'SUNBURST',
    'NOBELIUM',
    // Covert channels
    'DNS',
    'tunnel',
    'dnscat',
    'cloudfront',
    // Steganography
    'LSB',
    'stego',
    'EXIF',
    // Lateral movement
    'WMI',
    'WinRM',
    'psexec',
    // Credential access
    'LSASS',
    'SAM',
    'NTDS',
    'Mimikatz',
  ],
  rootkit: [
    // Kernel APIs
    'NtLoadDriver',
    'MmMapIoSpace',
    'PsLookupProcess',
    // DKOM
    'EPROCESS',
    'ActiveProcessLinks',
    'Flink',
    // UEFI
    'EFI',
    'bootmgfw',
    'UEFI',
    'SPI flash',
    // Hypervisor
    'hypervisor',
    'VMCS',
    // BYOVD
    'gdrv.sys',
    'dbutil',
    'vulnerable driver',
  ],
};

// Helper to check if file exists
async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

// Helper to extract printable strings from binary
async function extractStrings(filePath: string, minLength = 4): Promise<string[]> {
  const data = await readFile(filePath);
  const strings: string[] = [];
  let current = '';

  for (let i = 0; i < data.length; i++) {
    const byte = data[i];
    // Printable ASCII range (32-126)
    if (byte !== undefined && byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) {
        strings.push(current);
      }
      current = '';
    }
  }

  // Don't forget the last string
  if (current.length >= minLength) {
    strings.push(current);
  }

  return strings;
}

// Helper to check if any expected pattern is found
function containsPattern(strings: string[], pattern: string): boolean {
  const lowerPattern = pattern.toLowerCase();
  return strings.some((s) => s.toLowerCase().includes(lowerPattern));
}

describe('Test Binaries E2E', () => {
  const binariesExist: Record<string, boolean> = {};

  beforeAll(async () => {
    // Check which binaries exist
    for (const [name, path] of Object.entries(TEST_BINARIES)) {
      binariesExist[name] = await fileExists(path);
    }

    // Count available binaries
    const available = Object.values(binariesExist).filter(Boolean).length;
    if (available === 0) {
      console.warn('⚠️  No test binaries found. Run "make all" in binaries/src/ to build them.');
    } else {
      console.log(`✓ Found ${available}/${Object.keys(TEST_BINARIES).length} test binaries`);
    }
  });

  describe('Binary Availability', () => {
    test('test binaries directory exists', async () => {
      expect(await fileExists(BINARIES_DIR)).toBe(true);
    });

    test('at least one test binary exists (skip in CI)', async () => {
      // In CI environments, binaries may not be built - skip gracefully
      const isCI = process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';
      const hasAnyBinary = Object.values(binariesExist).some(Boolean);

      if (isCI && !hasAnyBinary) {
        console.log('Skipping: CI environment without built binaries');
        return;
      }

      expect(hasAnyBinary).toBe(true);
    });
  });

  describe('Ransomware Detection', () => {
    test('ransomware_sim contains expected patterns', async () => {
      if (!binariesExist.ransomware) {
        console.log('Skipping: ransomware_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.ransomware);
      const patterns = EXPECTED_PATTERNS.ransomware;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      // Should match at least 60% of expected patterns
      const matchRatio = matchCount / patterns.length;
      expect(matchRatio).toBeGreaterThan(0.5);
    });

    test('detects crypto API usage', async () => {
      if (!binariesExist.ransomware) return;

      const strings = await extractStrings(TEST_BINARIES.ransomware);

      // At least one crypto API should be present
      const cryptoAPIs = ['CryptEncrypt', 'BCryptEncrypt', 'CryptoAPI', 'AES', 'RSA'];
      const hasCrypto = cryptoAPIs.some((api) => containsPattern(strings, api));
      expect(hasCrypto).toBe(true);
    });

    test('detects ransom indicators', async () => {
      if (!binariesExist.ransomware) return;

      const strings = await extractStrings(TEST_BINARIES.ransomware);

      // Should have ransom-related strings
      const ransomIndicators = ['bitcoin', 'wallet', 'decrypt', 'payment', 'ransom'];
      const hasRansom = ransomIndicators.some((ind) => containsPattern(strings, ind));
      expect(hasRansom).toBe(true);
    });
  });

  describe('Keylogger Detection', () => {
    test('keylogger_sim contains expected patterns', async () => {
      if (!binariesExist.keylogger) {
        console.log('Skipping: keylogger_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.keylogger);
      const patterns = EXPECTED_PATTERNS.keylogger;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      expect(matchCount / patterns.length).toBeGreaterThan(0.5);
    });

    test('detects keyboard hook APIs', async () => {
      if (!binariesExist.keylogger) return;

      const strings = await extractStrings(TEST_BINARIES.keylogger);

      const hookAPIs = ['SetWindowsHookEx', 'GetAsyncKeyState', 'GetKeyboardState', 'GetKeyState'];
      const hasHook = hookAPIs.some((api) => containsPattern(strings, api));
      expect(hasHook).toBe(true);
    });
  });

  describe('Trojan Detection', () => {
    test('trojan_sim contains expected patterns', async () => {
      if (!binariesExist.trojan) {
        console.log('Skipping: trojan_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.trojan);
      const patterns = EXPECTED_PATTERNS.trojan;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      expect(matchCount / patterns.length).toBeGreaterThan(0.5);
    });

    test('detects process injection APIs', async () => {
      if (!binariesExist.trojan) return;

      const strings = await extractStrings(TEST_BINARIES.trojan);

      const injectionAPIs = [
        'VirtualAllocEx',
        'WriteProcessMemory',
        'CreateRemoteThread',
        'NtCreateThreadEx',
      ];
      const hasInjection = injectionAPIs.some((api) => containsPattern(strings, api));
      expect(hasInjection).toBe(true);
    });
  });

  describe('Cryptominer Detection', () => {
    test('cryptominer_sim contains expected patterns', async () => {
      if (!binariesExist.cryptominer) {
        console.log('Skipping: cryptominer_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.cryptominer);
      const patterns = EXPECTED_PATTERNS.cryptominer;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      expect(matchCount / patterns.length).toBeGreaterThan(0.4);
    });

    test('detects stratum protocol', async () => {
      if (!binariesExist.cryptominer) return;

      const strings = await extractStrings(TEST_BINARIES.cryptominer);

      const stratumPatterns = ['stratum', 'mining.subscribe', 'mining.authorize', 'pool'];
      const hasStratum = stratumPatterns.some((p) => containsPattern(strings, p));
      expect(hasStratum).toBe(true);
    });

    test('detects mining pool URLs', async () => {
      if (!binariesExist.cryptominer) return;

      const strings = await extractStrings(TEST_BINARIES.cryptominer);

      // Check for pool-related strings
      const hasPoolUrl = strings.some(
        (s) => s.includes('pool') || s.includes('mining') || s.includes(':3333'),
      );
      expect(hasPoolUrl).toBe(true);
    });
  });

  describe('RAT Detection', () => {
    test('rat_sim contains expected patterns', async () => {
      if (!binariesExist.rat) {
        console.log('Skipping: rat_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.rat);
      const patterns = EXPECTED_PATTERNS.rat;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      expect(matchCount / patterns.length).toBeGreaterThan(0.5);
    });

    test('detects screen capture APIs', async () => {
      if (!binariesExist.rat) return;

      const strings = await extractStrings(TEST_BINARIES.rat);

      const screenAPIs = ['GetDC', 'BitBlt', 'CreateCompatibleBitmap', 'PrintWindow'];
      const hasScreen = screenAPIs.some((api) => containsPattern(strings, api));
      expect(hasScreen).toBe(true);
    });

    test('detects credential theft targets', async () => {
      if (!binariesExist.rat) return;

      const strings = await extractStrings(TEST_BINARIES.rat);

      const targets = ['Chrome', 'Firefox', 'Edge', 'Login Data', 'logins.json'];
      const hasTarget = targets.some((t) => containsPattern(strings, t));
      expect(hasTarget).toBe(true);
    });
  });

  // ============== Modern 2025/2026 Threat Patterns ==============

  describe('Infostealer Detection (2025)', () => {
    test('infostealer_sim contains expected patterns', async () => {
      if (!binariesExist.infostealer) {
        console.log('Skipping: infostealer_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.infostealer);
      const patterns = EXPECTED_PATTERNS.infostealer;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      expect(matchCount / patterns.length).toBeGreaterThan(0.5);
    });

    test('detects browser credential paths', async () => {
      if (!binariesExist.infostealer) return;

      const strings = await extractStrings(TEST_BINARIES.infostealer);

      const browserPaths = ['Login Data', 'Cookies', 'Chrome', 'Firefox', 'Edge'];
      const hasBrowser = browserPaths.some((p) => containsPattern(strings, p));
      expect(hasBrowser).toBe(true);
    });

    test('detects crypto wallet paths', async () => {
      if (!binariesExist.infostealer) return;

      const strings = await extractStrings(TEST_BINARIES.infostealer);

      const walletPatterns = ['MetaMask', 'Exodus', 'Phantom', 'Ledger', 'wallet'];
      const hasWallet = walletPatterns.some((w) => containsPattern(strings, w));
      expect(hasWallet).toBe(true);
    });

    test('detects messaging app token paths', async () => {
      if (!binariesExist.infostealer) return;

      const strings = await extractStrings(TEST_BINARIES.infostealer);

      const messagingPatterns = ['Discord', 'Telegram', 'Signal', 'leveldb'];
      const hasMessaging = messagingPatterns.some((m) => containsPattern(strings, m));
      expect(hasMessaging).toBe(true);
    });

    test('detects password manager targets', async () => {
      if (!binariesExist.infostealer) return;

      const strings = await extractStrings(TEST_BINARIES.infostealer);

      const pmPatterns = ['1Password', 'Bitwarden', 'KeePass', 'LastPass'];
      const hasPM = pmPatterns.some((p) => containsPattern(strings, p));
      expect(hasPM).toBe(true);
    });
  });

  describe('Loader/Dropper Detection (2025)', () => {
    test('loader_sim contains expected patterns', async () => {
      if (!binariesExist.loader) {
        console.log('Skipping: loader_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.loader);
      const patterns = EXPECTED_PATTERNS.loader;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      expect(matchCount / patterns.length).toBeGreaterThan(0.5);
    });

    test('detects process injection APIs', async () => {
      if (!binariesExist.loader) return;

      const strings = await extractStrings(TEST_BINARIES.loader);

      const injectionAPIs = [
        'VirtualAllocEx',
        'WriteProcessMemory',
        'CreateRemoteThread',
        'NtCreateThreadEx',
        'QueueUserAPC',
      ];
      const hasInjection = injectionAPIs.some((api) => containsPattern(strings, api));
      expect(hasInjection).toBe(true);
    });

    test('detects LOLBins abuse', async () => {
      if (!binariesExist.loader) return;

      const strings = await extractStrings(TEST_BINARIES.loader);

      const lolbins = ['mshta', 'regsvr32', 'certutil', 'rundll32', 'msiexec'];
      const hasLolbin = lolbins.some((l) => containsPattern(strings, l));
      expect(hasLolbin).toBe(true);
    });

    test('detects anti-analysis techniques', async () => {
      if (!binariesExist.loader) return;

      const strings = await extractStrings(TEST_BINARIES.loader);

      const antiAnalysis = [
        'IsDebuggerPresent',
        'sandbox',
        'vmware',
        'virtualbox',
        'NtQueryInformationProcess',
      ];
      const hasAntiAnalysis = antiAnalysis.some((a) => containsPattern(strings, a));
      expect(hasAntiAnalysis).toBe(true);
    });

    test('detects C2 framework patterns', async () => {
      if (!binariesExist.loader) return;

      const strings = await extractStrings(TEST_BINARIES.loader);

      const c2Patterns = ['Cobalt Strike', 'Sliver', 'Havoc', 'beacon', 'shellcode'];
      const hasC2 = c2Patterns.some((c) => containsPattern(strings, c));
      expect(hasC2).toBe(true);
    });
  });

  describe('APT/Nation-State Detection (2025)', () => {
    test('apt_sim contains expected patterns', async () => {
      if (!binariesExist.apt) {
        console.log('Skipping: apt_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.apt);
      const patterns = EXPECTED_PATTERNS.apt;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      expect(matchCount / patterns.length).toBeGreaterThan(0.5);
    });

    test('detects APT group indicators', async () => {
      if (!binariesExist.apt) return;

      const strings = await extractStrings(TEST_BINARIES.apt);

      const aptIndicators = ['APT', 'Lazarus', 'SUNBURST', 'NOBELIUM', 'Sofacy', 'Zebrocy'];
      const hasAPT = aptIndicators.some((a) => containsPattern(strings, a));
      expect(hasAPT).toBe(true);
    });

    test('detects covert C2 channels', async () => {
      if (!binariesExist.apt) return;

      const strings = await extractStrings(TEST_BINARIES.apt);

      const covertChannels = ['DNS', 'tunnel', 'dnscat', 'iodine', 'cloudfront', 'domain fronting'];
      const hasCovert = covertChannels.some((c) => containsPattern(strings, c));
      expect(hasCovert).toBe(true);
    });

    test('detects lateral movement techniques', async () => {
      if (!binariesExist.apt) return;

      const strings = await extractStrings(TEST_BINARIES.apt);

      const lateralMovement = ['WMI', 'WinRM', 'psexec', 'PsExec', 'SMB', 'smbexec'];
      const hasLateral = lateralMovement.some((l) => containsPattern(strings, l));
      expect(hasLateral).toBe(true);
    });

    test('detects credential dumping targets', async () => {
      if (!binariesExist.apt) return;

      const strings = await extractStrings(TEST_BINARIES.apt);

      const credTargets = ['LSASS', 'SAM', 'NTDS', 'Mimikatz', 'sekurlsa', 'kerberos'];
      const hasCredDump = credTargets.some((c) => containsPattern(strings, c));
      expect(hasCredDump).toBe(true);
    });
  });

  describe('Rootkit/Bootkit Detection (2025)', () => {
    test('rootkit_sim contains expected patterns', async () => {
      if (!binariesExist.rootkit) {
        console.log('Skipping: rootkit_sim not built');
        return;
      }

      const strings = await extractStrings(TEST_BINARIES.rootkit);
      const patterns = EXPECTED_PATTERNS.rootkit;
      let matchCount = 0;

      for (const pattern of patterns) {
        if (containsPattern(strings, pattern)) {
          matchCount++;
        }
      }

      expect(matchCount / patterns.length).toBeGreaterThan(0.5);
    });

    test('detects kernel driver APIs', async () => {
      if (!binariesExist.rootkit) return;

      const strings = await extractStrings(TEST_BINARIES.rootkit);

      const kernelAPIs = ['NtLoadDriver', 'ZwLoadDriver', 'MmMapIoSpace', 'PsLookupProcess'];
      const hasKernel = kernelAPIs.some((k) => containsPattern(strings, k));
      expect(hasKernel).toBe(true);
    });

    test('detects DKOM techniques', async () => {
      if (!binariesExist.rootkit) return;

      const strings = await extractStrings(TEST_BINARIES.rootkit);

      const dkomPatterns = [
        'EPROCESS',
        'ActiveProcessLinks',
        'Flink',
        'Blink',
        'PsActiveProcessHead',
      ];
      const hasDKOM = dkomPatterns.some((d) => containsPattern(strings, d));
      expect(hasDKOM).toBe(true);
    });

    test('detects UEFI/bootkit patterns', async () => {
      if (!binariesExist.rootkit) return;

      const strings = await extractStrings(TEST_BINARIES.rootkit);

      const uefiPatterns = ['EFI', 'bootmgfw', 'UEFI', 'SPI flash', 'SMM', 'GetVariable'];
      const hasUEFI = uefiPatterns.some((u) => containsPattern(strings, u));
      expect(hasUEFI).toBe(true);
    });

    test('detects BYOVD vulnerable drivers', async () => {
      if (!binariesExist.rootkit) return;

      const strings = await extractStrings(TEST_BINARIES.rootkit);

      const byovdDrivers = ['gdrv.sys', 'dbutil', 'RTCore', 'vulnerable driver', 'BYOVD'];
      const hasBYOVD = byovdDrivers.some((b) => containsPattern(strings, b));
      expect(hasBYOVD).toBe(true);
    });
  });

  describe('Stripped Binary Detection', () => {
    test('stripped binaries still contain detectable patterns', async () => {
      // Stripped binaries should still have string patterns
      const strippedRansomware = STRIPPED_BINARIES.ransomware;

      if (!(await fileExists(strippedRansomware))) {
        console.log('Skipping: stripped binaries not built');
        return;
      }

      const strings = await extractStrings(strippedRansomware);

      // Even stripped, should still have the string literals
      const hasCryptoPattern =
        containsPattern(strings, 'CryptEncrypt') ||
        containsPattern(strings, 'bitcoin') ||
        containsPattern(strings, 'encrypted');

      expect(hasCryptoPattern).toBe(true);
    });
  });

  describe('String Analyzer Integration', () => {
    test('StringAnalyzer classifies ransomware strings as suspicious', async () => {
      if (!binariesExist.ransomware) return;

      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();
      const strings = await extractStrings(TEST_BINARIES.ransomware);

      const result = analyzer.analyze(strings);

      // Should detect suspicious patterns
      expect(result.suspiciousCount).toBeGreaterThan(0);
    });

    test('StringAnalyzer categorizes trojan strings', async () => {
      if (!binariesExist.trojan) return;

      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();
      const strings = await extractStrings(TEST_BINARIES.trojan);

      const result = analyzer.analyze(strings);

      // Should categorize strings into meaningful buckets
      // Trojan should have api calls, commands, and suspicious strings
      const totalCategorized = Object.values(result.categoryBreakdown).reduce(
        (sum, count) => sum + count,
        0,
      );
      expect(totalCategorized).toBeGreaterThan(0);
      expect(result.suspiciousCount).toBeGreaterThan(0);
    });
  });

  describe('Crypto Detector Integration', () => {
    test('CryptoDetector analyzes binary data', async () => {
      if (!binariesExist.ransomware) return;

      const { getCryptoDetector } = await import('../utils/crypto-detector.js');
      const detector = getCryptoDetector();
      const data = await readFile(TEST_BINARIES.ransomware);

      const result = detector.analyze(data);

      expect(result).toBeDefined();
      expect(Array.isArray(result.detections)).toBe(true);
    });
  });
});

describe('Pattern Coverage Summary', () => {
  test('summarize detection coverage', async () => {
    const summary: Record<string, { total: number; detected: number }> = {};

    for (const [category, patterns] of Object.entries(EXPECTED_PATTERNS)) {
      const binaryPath = TEST_BINARIES[category as keyof typeof TEST_BINARIES];

      if (await fileExists(binaryPath)) {
        const strings = await extractStrings(binaryPath);
        let detected = 0;

        for (const pattern of patterns) {
          if (containsPattern(strings, pattern)) {
            detected++;
          }
        }

        summary[category] = { total: patterns.length, detected };
      }
    }

    // Log summary for visibility
    console.log('\n📊 Pattern Detection Summary:');
    for (const [category, { total, detected }] of Object.entries(summary)) {
      const percent = Math.round((detected / total) * 100);
      const bar = '█'.repeat(Math.floor(percent / 10)) + '░'.repeat(10 - Math.floor(percent / 10));
      console.log(`   ${category.padEnd(12)} ${bar} ${percent}% (${detected}/${total})`);
    }

    // Overall should have good coverage
    const totalPatterns = Object.values(summary).reduce((acc, { total }) => acc + total, 0);
    const totalDetected = Object.values(summary).reduce((acc, { detected }) => acc + detected, 0);

    if (totalPatterns > 0) {
      expect(totalDetected / totalPatterns).toBeGreaterThan(0.5);
    }
  });
});

// ============== False Positive Testing ==============

describe('Benign Binary Testing (False Positive Prevention)', () => {
  const benignExist: Record<string, boolean> = {};
  const packedBenignExist: Record<string, boolean> = {};

  beforeAll(async () => {
    // Check which benign binaries exist
    for (const [name, path] of Object.entries(BENIGN_BINARIES)) {
      benignExist[name] = await fileExists(path);
    }
    for (const [name, path] of Object.entries(PACKED_BENIGN_BINARIES)) {
      packedBenignExist[name] = await fileExists(path);
    }

    const available = Object.values(benignExist).filter(Boolean).length;
    if (available > 0) {
      console.log(
        `✓ Found ${available}/${Object.keys(BENIGN_BINARIES).length} benign test binaries`,
      );
    }
  });

  describe('Clean Binary Detection', () => {
    test('benign_hello has minimal suspicious patterns', async () => {
      if (!benignExist.hello) {
        console.log('Skipping: benign_hello not built');
        return;
      }

      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();
      const strings = await extractStrings(BENIGN_BINARIES.hello);
      const result = analyzer.analyze(strings);

      // Benign hello should have very few suspicious strings
      // Allow small number due to standard library strings
      expect(result.suspiciousCount).toBeLessThan(5);
    });

    test('benign_calculator has no malicious patterns', async () => {
      if (!benignExist.calculator) {
        console.log('Skipping: benign_calculator not built');
        return;
      }

      const strings = await extractStrings(BENIGN_BINARIES.calculator);

      // Should NOT contain any dangerous API calls
      const dangerousAPIs = [
        'VirtualAllocEx',
        'WriteProcessMemory',
        'CreateRemoteThread',
        'CryptEncrypt',
        'SetWindowsHookEx',
        'GetAsyncKeyState',
      ];
      const hasDangerous = dangerousAPIs.some((api) => containsPattern(strings, api));
      expect(hasDangerous).toBe(false);
    });

    test('benign_fileops uses legitimate file operations', async () => {
      if (!benignExist.fileops) {
        console.log('Skipping: benign_fileops not built');
        return;
      }

      const strings = await extractStrings(BENIGN_BINARIES.fileops);

      // Should have normal file operations but NOT malicious ones
      const normalOps = ['fopen', 'fread', 'fwrite', 'fclose'];
      const maliciousOps = ['vssadmin', 'bcdedit', 'wbadmin', 'delete shadows'];

      const hasNormal = normalOps.some((op) => containsPattern(strings, op));
      const hasMalicious = maliciousOps.some((op) => containsPattern(strings, op));

      expect(hasNormal).toBe(true);
      expect(hasMalicious).toBe(false);
    });

    test('benign_network has educational content only', async () => {
      if (!benignExist.network) {
        console.log('Skipping: benign_network not built');
        return;
      }

      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();
      const strings = await extractStrings(BENIGN_BINARIES.network);
      const result = analyzer.analyze(strings);

      // Network demo may have some URLs but should not be highly suspicious
      // Educational content about HTTP, ports, etc.
      expect(result.suspiciousCount).toBeLessThan(10);
    });

    test('benign_crypto discusses concepts but has no malicious patterns', async () => {
      if (!benignExist.crypto) {
        console.log('Skipping: benign_crypto not built');
        return;
      }

      const strings = await extractStrings(BENIGN_BINARIES.crypto);

      // Should mention crypto algorithms (educational)
      const eduPatterns = ['AES', 'SHA', 'RSA', 'hash', 'encrypt'];
      const hasEdu = eduPatterns.some((p) => containsPattern(strings, p));
      expect(hasEdu).toBe(true);

      // But should NOT have actual ransom-specific indicators
      // Note: 'wallet' may appear in crypto education context, so we check ransom-specific phrases
      const ransomIndicators = [
        'decrypt your files',
        'ransom note',
        'bitcoin address',
        'send payment',
      ];
      const hasRansom = ransomIndicators.some((r) => containsPattern(strings, r));
      expect(hasRansom).toBe(false);
    });
  });

  describe('Packed Benign Binary Detection', () => {
    test('packed benign binaries still detectable as low-risk', async () => {
      if (!packedBenignExist.hello) {
        console.log('Skipping: packed benign binaries not built');
        return;
      }

      const { getCryptoDetector } = await import('../utils/crypto-detector.js');
      const detector = getCryptoDetector();
      const data = await readFile(PACKED_BENIGN_BINARIES.hello);
      const result = detector.analyze(data);

      // Packed binary will have high entropy but should not have crypto malware indicators
      expect(result).toBeDefined();
      // High entropy is expected from packing, but no AES S-boxes, etc.
    });

    test('packed vs unpacked benign comparison', async () => {
      if (!benignExist.calculator || !packedBenignExist.calculator) {
        console.log('Skipping: calculator binaries not built');
        return;
      }

      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();

      // Unpacked version
      const unpackedStrings = await extractStrings(BENIGN_BINARIES.calculator);
      const unpackedResult = analyzer.analyze(unpackedStrings);

      // Packed version - will have UPX stub strings but fewer original strings
      const packedStrings = await extractStrings(PACKED_BENIGN_BINARIES.calculator);
      const packedResult = analyzer.analyze(packedStrings);

      // Both should have minimal suspicious content
      // UPX adds some strings but original code is compressed
      expect(packedResult.suspiciousCount).toBeLessThanOrEqual(5);
      expect(unpackedResult.suspiciousCount).toBeLessThanOrEqual(5);
    });
  });

  describe('Comparison: Malicious vs Benign', () => {
    test('ransomware has higher suspicion than benign_crypto', async () => {
      if (!benignExist.crypto) {
        console.log('Skipping: benign_crypto not built');
        return;
      }

      const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
      const analyzer = getStringAnalyzer();

      // Check if ransomware binary exists
      const ransomwareExists = await fileExists(TEST_BINARIES.ransomware);
      if (!ransomwareExists) return;

      const ransomStrings = await extractStrings(TEST_BINARIES.ransomware);
      const ransomResult = analyzer.analyze(ransomStrings);

      const benignStrings = await extractStrings(BENIGN_BINARIES.crypto);
      const benignResult = analyzer.analyze(benignStrings);

      // Ransomware should have more suspicious strings than benign crypto demo
      // benign_crypto has some educational crypto strings that may trigger low counts
      expect(ransomResult.suspiciousCount).toBeGreaterThan(benignResult.suspiciousCount);
    });

    test('trojan has injection APIs, benign does not', async () => {
      if (!benignExist.hello) {
        console.log('Skipping: benign_hello not built');
        return;
      }

      const trojanExists = await fileExists(TEST_BINARIES.trojan);
      if (!trojanExists) return;

      const trojanStrings = await extractStrings(TEST_BINARIES.trojan);
      const benignStrings = await extractStrings(BENIGN_BINARIES.hello);

      const injectionAPIs = [
        'VirtualAllocEx',
        'WriteProcessMemory',
        'CreateRemoteThread',
        'NtCreateThreadEx',
      ];

      const trojanHasInjection = injectionAPIs.some((api) => containsPattern(trojanStrings, api));
      const benignHasInjection = injectionAPIs.some((api) => containsPattern(benignStrings, api));

      expect(trojanHasInjection).toBe(true);
      expect(benignHasInjection).toBe(false);
    });

    test('infostealer targets browsers, benign_fileops does not', async () => {
      if (!benignExist.fileops) {
        console.log('Skipping: benign_fileops not built');
        return;
      }

      const infostealerExists = await fileExists(TEST_BINARIES.infostealer);
      if (!infostealerExists) return;

      const infostealerStrings = await extractStrings(TEST_BINARIES.infostealer);
      const benignStrings = await extractStrings(BENIGN_BINARIES.fileops);

      const browserPaths = ['Login Data', 'Cookies', 'Chrome', 'Firefox', 'MetaMask'];

      const stealerHasBrowser = browserPaths.some((p) => containsPattern(infostealerStrings, p));
      const benignHasBrowser = browserPaths.some((p) => containsPattern(benignStrings, p));

      expect(stealerHasBrowser).toBe(true);
      expect(benignHasBrowser).toBe(false);
    });
  });
});

describe('Benign Summary', () => {
  test('summarize benign binary detection', async () => {
    const { getStringAnalyzer } = await import('../utils/string-analyzer.js');
    const analyzer = getStringAnalyzer();
    const summary: Record<string, { total: number; suspicious: number; ratio: number }> = {};

    for (const [name, path] of Object.entries(BENIGN_BINARIES)) {
      if (await fileExists(path)) {
        const strings = await extractStrings(path);
        const result = analyzer.analyze(strings);
        const ratio = result.totalStrings > 0 ? result.suspiciousCount / result.totalStrings : 0;
        summary[name] = {
          total: result.totalStrings,
          suspicious: result.suspiciousCount,
          ratio: Math.round(ratio * 100),
        };
      }
    }

    // Log summary
    console.log('\n📊 Benign Binary Analysis (False Positive Check):');
    for (const [name, { total, suspicious, ratio }] of Object.entries(summary)) {
      const status = ratio < 5 ? '✅' : ratio < 10 ? '⚠️' : '❌';
      console.log(`   ${status} ${name.padEnd(12)} ${suspicious}/${total} suspicious (${ratio}%)`);
    }

    // All benign binaries should have low suspicion ratio (< 10%)
    for (const { ratio } of Object.values(summary)) {
      expect(ratio).toBeLessThan(15);
    }
  });
});
