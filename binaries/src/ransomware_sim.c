/**
 * SENTINEL Test Binary - Ransomware Simulation
 * 
 * This is a SAFE test binary that contains patterns commonly found in ransomware
 * to test detection capabilities. It doesn't encrypt or modify any files.
 * 
 * Detection patterns:
 * - File extension targeting
 * - Encryption API references
 * - Ransom note generation
 * - Shadow copy deletion commands
 * - Bitcoin wallet addresses
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// File extensions targeted by ransomware
const char* target_extensions[] = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".psd", ".ai", ".dwg", ".dxf", ".sql", ".mdb",
    ".accdb", ".sqlite", ".zip", ".rar", ".7z", ".tar",
    ".gz", ".mp3", ".mp4", ".avi", ".mkv", ".mov",
    ".vmdk", ".vdi", ".qcow2", ".ova", ".bak", ".old",
    ".pst", ".ost", ".eml", ".msg", ".one", ".onetoc2",
    ".wallet", ".dat", ".key", ".pem", ".p12", ".pfx"
};
const int num_extensions = sizeof(target_extensions) / sizeof(target_extensions[0]);

// Crypto API strings (Windows)
const char* crypto_apis[] = {
    "CryptAcquireContextA",
    "CryptAcquireContextW",
    "CryptGenRandom",
    "CryptEncrypt",
    "CryptDecrypt",
    "CryptDeriveKey",
    "CryptDestroyKey",
    "CryptExportKey",
    "CryptImportKey",
    "CryptCreateHash",
    "CryptHashData",
    "BCryptEncrypt",
    "BCryptDecrypt",
    "BCryptGenerateSymmetricKey"
};

// Shadow copy deletion commands
const char* shadow_delete_commands[] = {
    "vssadmin delete shadows /all /quiet",
    "wmic shadowcopy delete",
    "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
    "bcdedit /set {default} recoveryenabled no",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "wbadmin delete catalog -quiet"
};

// Bitcoin wallet addresses (fake but realistic format)
const char* btc_wallets[] = {
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5",
    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
};

// Monero wallet (also common)
const char* xmr_wallet = 
    "48Rp9RNjvFb4vt6v5NQCYr5e3yd5b5N6nRQQiLhUkC3WfKLfPrRwS8BCSQ5z2B5RVT2CFG6TXvSBP5Gn9k6GyKZi9Xv3FLN";

// Ransom note templates
const char* ransom_note_v1 = 
    "=== YOUR FILES HAVE BEEN ENCRYPTED ===\n\n"
    "All your documents, photos, databases, and other important files\n"
    "have been encrypted with RSA-4096 encryption.\n\n"
    "To decrypt your files, you need to pay 0.5 BTC to:\n"
    "%s\n\n"
    "After payment, email proof to: decrypt@ransomware.onion\n"
    "Include your personal ID: VICTIM-%08X\n\n"
    "You have 72 hours. After that, the price doubles.\n"
    "After 7 days, the decryption key will be permanently deleted.\n\n"
    "DO NOT:\n"
    "- Try to decrypt files yourself (will corrupt them permanently)\n"
    "- Contact law enforcement (we will destroy the key)\n"
    "- Rename encrypted files\n";

const char* ransom_note_v2 = 
    "!! ATTENTION !!\n"
    "Your network has been penetrated.\n"
    "We have downloaded sensitive data and encrypted your systems.\n\n"
    "DATA EXFILTRATED:\n"
    "- Employee records\n"
    "- Financial documents\n"
    "- Customer database\n"
    "- Source code\n\n"
    "Payment: 5 BTC within 48 hours\n"
    "Contact: support@darkweb.onion\n\n"
    "Failure to comply will result in:\n"
    "1. Public leak of stolen data\n"
    "2. Notification of clients about breach\n"
    "3. Permanent loss of encrypted files\n";

// Encrypted file extension
const char* encrypted_extension = ".LOCKED";

// Mutex to prevent multiple instances
const char* mutex_name = "Global\\{RANSOMWARE-MUTEX-12345678}";

// RC4/Salsa20 key schedule patterns (just data, not actual crypto)
unsigned char fake_key_schedule[256];

void init_fake_key_schedule(void) {
    for (int i = 0; i < 256; i++) {
        fake_key_schedule[i] = (unsigned char)(i ^ 0xDE);
    }
}

void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║     SENTINEL TEST - RANSOMWARE SIMULATION                         ║\n");
    printf("║                                                                   ║\n");
    printf("║  This binary simulates ransomware patterns but is COMPLETELY      ║\n");
    printf("║  SAFE. It does NOT encrypt or modify any files.                   ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void simulate_file_enumeration(void) {
    printf("[*] Simulating file enumeration (not actually scanning)...\n");
    printf("    Would target %d file extensions:\n", num_extensions);
    for (int i = 0; i < 10 && i < num_extensions; i++) {
        printf("      - *%s\n", target_extensions[i]);
    }
    if (num_extensions > 10) {
        printf("      ... and %d more\n", num_extensions - 10);
    }
}

void simulate_shadow_deletion(void) {
    printf("\n[*] Would execute shadow copy deletion:\n");
    printf("    %s\n", shadow_delete_commands[0]);
    printf("    %s\n", shadow_delete_commands[1]);
}

void simulate_encryption(void) {
    printf("\n[*] Would use encryption APIs:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", crypto_apis[i]);
    }
}

void simulate_ransom_note(void) {
    printf("\n[*] Would create ransom note:\n");
    printf("────────────────────────────────────────\n");
    printf(ransom_note_v1, btc_wallets[0], 0xDEADBEEF);
    printf("────────────────────────────────────────\n");
}

int main(void) {
    print_banner();
    
    init_fake_key_schedule();
    
    printf("[*] Mutex: %s\n", mutex_name);
    printf("[*] Encrypted extension: %s\n", encrypted_extension);
    printf("[*] BTC Wallet: %s\n", btc_wallets[0]);
    printf("[*] XMR Wallet: %.50s...\n", xmr_wallet);
    
    simulate_file_enumeration();
    simulate_shadow_deletion();
    simulate_encryption();
    simulate_ransom_note();
    
    printf("\n[✓] Ransomware simulation complete.\n");
    printf("[✓] This was a SAFE test - no files were harmed.\n\n");
    
    return 0;
}
