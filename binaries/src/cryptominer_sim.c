/**
 * SENTINEL Test Binary - Cryptominer Simulation
 * 
 * This is a SAFE test binary that contains patterns commonly found in 
 * cryptocurrency miners to test detection capabilities. It doesn't mine anything.
 * 
 * Detection patterns:
 * - Mining pool connections
 * - Stratum protocol strings
 * - Wallet addresses
 * - High CPU usage patterns
 * - GPU/CUDA references
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Mining pool URLs (real pool names, fake connections)
const char* mining_pools[] = {
    "stratum+tcp://pool.minexmr.com:4444",
    "stratum+tcp://xmr.nanopool.org:14444",
    "stratum+tcp://xmr-us-east1.nanopool.org:14433",
    "stratum+tcp://pool.hashvault.pro:80",
    "stratum+tcp://xmrpool.eu:5555",
    "stratum+tcp://gulf.moneroocean.stream:10001",
    "stratum+tcp://eth.2miners.com:2020",
    "stratum+tcp://pool.supportxmr.com:3333"
};

// Cryptocurrency wallet addresses (fake but realistic)
const char* wallets[] = {
    // Monero (XMR) - most common for miners
    "48Rp9RNjvFb4vt6v5NQCYr5e3yd5b5N6nRQQiLhUkC3WfKLfPrRwS8BCSQ5z2B5RVT2CFG6TXvSBP5Gn9k6GyKZi9Xv3FLN",
    // Ethereum (ETH)
    "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD71",
    // Bitcoin (BTC)
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
};

// Stratum protocol messages
const char* stratum_messages[] = {
    "{\"id\":1,\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"x\"}}",
    "{\"id\":2,\"method\":\"submit\",\"params\":{\"id\":\"%s\",\"job_id\":\"%s\",\"nonce\":\"%s\",\"result\":\"%s\"}}",
    "{\"id\":3,\"method\":\"keepalived\"}",
    "{\"jsonrpc\":\"2.0\",\"method\":\"job\",\"params\":{\"blob\":\"%s\",\"job_id\":\"%s\",\"target\":\"%s\"}}"
};

// Mining algorithms
const char* algorithms[] = {
    "RandomX",      // Monero
    "CryptoNight",  // Original Monero
    "Ethash",       // Ethereum
    "Kawpow",       // Ravencoin
    "Scrypt",       // Litecoin
    "SHA256",       // Bitcoin
    "Equihash",     // Zcash
    "Argon2d"       // Verge
};

// GPU/CUDA references
const char* gpu_apis[] = {
    "cuDeviceGet",
    "cuCtxCreate",
    "cuModuleLoad",
    "cuLaunchKernel",
    "clGetPlatformIDs",
    "clGetDeviceIDs",
    "clCreateContext",
    "clCreateCommandQueue",
    "clCreateProgramWithSource",
    "nvmlDeviceGetHandleByIndex",
    "nvmlDeviceGetTemperature",
    "nvmlDeviceGetPowerUsage"
};

// Process names commonly used by miners
const char* miner_names[] = {
    "xmrig.exe",
    "xmr-stak.exe",
    "ccminer.exe",
    "cgminer.exe",
    "bfgminer.exe",
    "ethminer.exe",
    "t-rex.exe",
    "phoenixminer.exe",
    "nbminer.exe",
    "lolminer.exe"
};

// Configuration file patterns
const char* config_patterns[] = {
    "\"url\": \"stratum+tcp://",
    "\"user\": \"",
    "\"pass\": \"x\"",
    "\"algo\": \"randomx\"",
    "\"threads\": ",
    "\"cpu-affinity\": ",
    "\"max-cpu-usage\": ",
    "\"donate-level\": 0"
};

// Anti-detection techniques used by miners
const char* evasion_techniques[] = {
    "Process name masquerading (svchost.exe, explorer.exe)",
    "CPU throttling when user active",
    "Only mine when screen is locked",
    "Mining during specific hours",
    "Limiting to X% CPU to avoid detection",
    "Using Windows Task Scheduler for persistence"
};

// Cryptographic hashing functions
const char* crypto_functions[] = {
    "keccak_256",
    "blake2b_256",
    "sha3_256",
    "argon2_hash",
    "randomx_calculate_hash",
    "cn_slow_hash",
    "ethash_compute"
};

void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║     SENTINEL TEST - CRYPTOMINER SIMULATION                        ║\n");
    printf("║                                                                   ║\n");
    printf("║  This binary simulates cryptominer patterns but is COMPLETELY     ║\n");
    printf("║  SAFE. It does NOT mine any cryptocurrency.                       ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void simulate_pool_connection(void) {
    printf("[*] Would connect to mining pools:\n");
    for (int i = 0; i < 4; i++) {
        printf("    - %s\n", mining_pools[i]);
    }
}

void simulate_wallet_usage(void) {
    printf("\n[*] Wallet addresses:\n");
    printf("    XMR: %.50s...\n", wallets[0]);
    printf("    ETH: %s\n", wallets[1]);
    printf("    BTC: %s\n", wallets[2]);
}

void simulate_stratum_protocol(void) {
    printf("\n[*] Stratum protocol messages:\n");
    printf("    Login: {\"method\":\"login\",\"params\":{\"login\":\"wallet\"}}\n");
    printf("    Submit: {\"method\":\"submit\",\"params\":{\"nonce\":\"...\"}}\n");
}

void simulate_algorithm_detection(void) {
    printf("\n[*] Mining algorithms supported:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", algorithms[i]);
    }
}

void simulate_gpu_access(void) {
    printf("\n[*] GPU APIs (CUDA/OpenCL):\n");
    for (int i = 0; i < 6; i++) {
        printf("    - %s\n", gpu_apis[i]);
    }
}

void simulate_crypto_operations(void) {
    printf("\n[*] Cryptographic hash functions:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", crypto_functions[i]);
    }
}

void simulate_evasion(void) {
    printf("\n[*] Evasion techniques:\n");
    for (int i = 0; i < 4; i++) {
        printf("    - %s\n", evasion_techniques[i]);
    }
}

void simulate_config(void) {
    printf("\n[*] Configuration patterns:\n");
    printf("────────────────────────────────────────\n");
    printf("{\n");
    printf("  \"url\": \"%s\",\n", mining_pools[0]);
    printf("  \"user\": \"%.40s...\",\n", wallets[0]);
    printf("  \"pass\": \"x\",\n");
    printf("  \"algo\": \"randomx\",\n");
    printf("  \"threads\": 4,\n");
    printf("  \"max-cpu-usage\": 75\n");
    printf("}\n");
    printf("────────────────────────────────────────\n");
}

int main(void) {
    print_banner();
    
    simulate_pool_connection();
    simulate_wallet_usage();
    simulate_stratum_protocol();
    simulate_algorithm_detection();
    simulate_gpu_access();
    simulate_crypto_operations();
    simulate_evasion();
    simulate_config();
    
    printf("\n[✓] Cryptominer simulation complete.\n");
    printf("[✓] This was a SAFE test - no mining occurred.\n\n");
    
    return 0;
}
