/**
 * SENTINEL Test Binary - APT/Nation-State Simulation (2025 Patterns)
 * 
 * This is a SAFE test binary that contains patterns commonly found in
 * advanced persistent threat (APT) malware and nation-state tooling.
 * It doesn't perform any malicious activity.
 * 
 * Detection patterns:
 * - Covert C2 channels
 * - Steganography indicators
 * - Custom crypto implementations
 * - Network infrastructure recon
 * - Lateral movement techniques
 * - Data staging and exfiltration
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// APT group indicators (MITRE-attributed)
const char* apt_indicators[] = {
    // APT28/Fancy Bear (Russia)
    "X-Tunnel",
    "Sofacy",
    "CHOPSTICK",
    "Zebrocy",
    
    // APT29/Cozy Bear (Russia)  
    "WellMess",
    "WellMail",
    "SUNBURST",
    "NOBELIUM",
    
    // APT41/Double Dragon (China)
    "KEYPLUG",
    "DUSTPAN",
    "BEACON",
    
    // Lazarus Group (North Korea)
    "MATA",
    "BLINDINGCAN",
    "HOPLIGHT",
    
    // APT35/Charming Kitten (Iran)
    "CharmPower",
    "HYPERSCRAPE"
};

// Covert C2 channels (MITRE T1071)
const char* covert_channels[] = {
    // DNS tunneling
    "iodine",
    "dnscat2",
    "dns2tcp",
    "TXT query",
    "MX query",
    "CNAME query",
    
    // ICMP tunneling
    "icmpsh",
    "ICMP type 0",
    "ICMP type 8",
    
    // HTTP covert channels
    "X-Forwarded-For:",
    "X-Custom-Header:",
    "Cookie: session=",
    
    // DNS over HTTPS
    "application/dns-message",
    "dns.google.com",
    "cloudflare-dns.com",
    "doh.opendns.com",
    
    // Domain fronting
    "Host: cdn.example.com",
    "appspot.com",
    "azureedge.net",
    "cloudfront.net"
};

// Steganography indicators
const char* stego_patterns[] = {
    // Image steganography
    "LSB encoding",
    "DCT coefficient",
    "JPEG marker",
    "PNG chunk",
    "EXIF metadata",
    "ICC profile",
    
    // Document steganography
    "whitespace encoding",
    "zero-width characters",
    "hidden text layer",
    
    // Network steganography
    "TCP timestamp",
    "IP ID field",
    "padding bytes"
};

// Custom crypto patterns (non-standard implementations)
const char* custom_crypto[] = {
    // Rolling XOR
    "XOR with key rotation",
    "byte-level XOR",
    
    // Custom stream ciphers
    "modified RC4",
    "custom PRNG",
    
    // Non-standard implementations
    "hand-rolled AES",
    "modified Salsa20",
    "custom ChaCha",
    
    // Hashing
    "API hashing",
    "djb2 hash",
    "sdbm hash",
    "FNV-1a hash"
};

// Network reconnaissance (MITRE T1046)
const char* recon_patterns[] = {
    // Port scanning
    "Nmap",
    "masscan",
    "connect() scan",
    "SYN scan",
    
    // Service enumeration
    "SMB enumeration",
    "LDAP query",
    "Kerberos SPN",
    "SNMP walk",
    
    // AD reconnaissance
    "BloodHound",
    "SharpHound",
    "ADExplorer",
    "ldapsearch",
    "dsquery",
    "Get-ADUser",
    "Get-ADComputer",
    "Get-ADGroup",
    
    // Network mapping
    "arp -a",
    "net view",
    "net share",
    "net user /domain"
};

// Lateral movement (MITRE T1021)
const char* lateral_movement[] = {
    // WMI
    "wmic /node:",
    "Invoke-WmiMethod",
    "Win32_Process Create",
    
    // WinRM
    "Enable-PSRemoting",
    "Invoke-Command -ComputerName",
    "Enter-PSSession",
    "winrs -r:",
    
    // SMB/Admin shares
    "\\\\<target>\\C$",
    "\\\\<target>\\ADMIN$",
    "\\\\<target>\\IPC$",
    "copy \\\\",
    "xcopy \\\\",
    
    // Pass-the-Hash
    "sekurlsa::pth",
    "Invoke-Mimikatz",
    "Invoke-TheHash",
    
    // RDP
    "mstsc /v:",
    "RDP hijacking",
    "SharpRDP",
    
    // SSH
    "ssh -i",
    "plink.exe"
};

// Credential access (MITRE T1003)
const char* credential_access[] = {
    // LSASS dumping
    "lsass.exe",
    "MiniDump",
    "comsvcs.dll",
    "procdump",
    "mimikatz",
    "sekurlsa::logonpasswords",
    
    // SAM database
    "reg save HKLM\\SAM",
    "reg save HKLM\\SYSTEM",
    "secretsdump.py",
    
    // NTDS.dit
    "ntdsutil",
    "vssadmin create shadow",
    "copy \\\\?\\GLOBALROOT\\Device\\",
    
    // Kerberos
    "kerberos::golden",
    "kerberos::silver",
    "GetUserSPNs",
    "Rubeus",
    
    // DPAPI
    "CryptUnprotectData",
    "dpapi::masterkey",
    "dpapi::cred"
};

// Data staging (MITRE T1074)
const char* data_staging[] = {
    // Archive creation
    "rar a -hp",
    "7z a -p",
    "zip -e",
    "tar czf",
    "makecab",
    
    // Compression
    "ntfsutil usn",
    "compact /c",
    
    // Staging locations
    "C:\\Windows\\Temp\\",
    "C:\\ProgramData\\",
    "%USERPROFILE%\\AppData\\Local\\Temp\\",
    "\\\\<server>\\share$\\staging"
};

// Exfiltration (MITRE T1041, T1048, T1567)
const char* exfiltration[] = {
    // Over C2
    "POST multipart/form-data",
    "chunked transfer encoding",
    
    // Alternative protocols
    "DNS exfil",
    "ICMP exfil",
    "FTP upload",
    "SCP transfer",
    
    // Cloud services
    "aws s3 cp",
    "azcopy",
    "gsutil cp",
    "rclone copy",
    "Dropbox API",
    "OneDrive API",
    "Google Drive API",
    "MEGA API"
};

// Persistence (MITRE T1547, T1053, T1543)
const char* persistence[] = {
    // Registry
    "HKCU\\...\\Run",
    "HKLM\\...\\Run",
    "Winlogon\\Shell",
    "Winlogon\\Userinit",
    
    // Scheduled tasks
    "schtasks /create",
    "at.exe",
    
    // Services
    "sc create",
    "New-Service",
    
    // WMI subscriptions
    "__EventFilter",
    "__EventConsumer",
    "__FilterToConsumerBinding",
    
    // COM hijacking
    "InprocServer32",
    "CLSID\\{",
    
    // DLL hijacking
    "DLL search order",
    "phantom DLL",
    
    // Bootkit
    "bcdedit /set",
    "bootmgr"
};

// Defense evasion (MITRE T1562)
const char* defense_evasion[] = {
    // Disable security
    "Set-MpPreference -DisableRealtimeMonitoring",
    "sc stop WinDefend",
    "netsh advfirewall set allprofiles state off",
    
    // AMSI bypass
    "amsiInitFailed",
    "[Ref].Assembly.GetType",
    "AmsiScanBuffer",
    
    // ETW bypass
    "EtwEventWrite",
    "NtTraceEvent",
    
    // Log clearing
    "wevtutil cl Security",
    "wevtutil cl System",
    "Clear-EventLog",
    
    // Timestomping
    "SetFileTime",
    "touch -d",
    "(Get-Item).LastWriteTime"
};

// Supply chain indicators
const char* supply_chain[] = {
    // Build compromise
    "build.gradle modification",
    "package.json tampering",
    "requirements.txt injection",
    
    // Update mechanism abuse
    "auto-update hijack",
    "signed installer modification",
    
    // Known supply chain attacks
    "SolarWinds Orion",
    "Codecov bash uploader",
    "ua-parser-js",
    "event-stream",
    "node-ipc"
};

void print_simulation_info(void) {
    printf("=== SENTINEL APT/Nation-State Simulation (2025 Patterns) ===\n\n");
    printf("This is a SAFE test binary for malware detection testing.\n");
    printf("It contains string patterns from advanced threats:\n");
    printf("- APT28/APT29 (Russia)\n");
    printf("- APT41 (China)\n");
    printf("- Lazarus Group (North Korea)\n");
    printf("- APT35 (Iran)\n\n");
    printf("No actual malicious activity occurs.\n\n");
}

void simulate_recon(void) {
    printf("[SIM] Network reconnaissance patterns:\n");
    for (int i = 0; i < 10 && i < (int)(sizeof(recon_patterns)/sizeof(recon_patterns[0])); i++) {
        printf("  - %s\n", recon_patterns[i]);
    }
}

void simulate_lateral(void) {
    printf("[SIM] Lateral movement patterns:\n");
    for (int i = 0; i < 10 && i < (int)(sizeof(lateral_movement)/sizeof(lateral_movement[0])); i++) {
        printf("  - %s\n", lateral_movement[i]);
    }
}

void simulate_credential_access(void) {
    printf("[SIM] Credential access patterns:\n");
    for (int i = 0; i < 10 && i < (int)(sizeof(credential_access)/sizeof(credential_access[0])); i++) {
        printf("  - %s\n", credential_access[i]);
    }
}

void simulate_exfil(void) {
    printf("[SIM] Exfiltration patterns:\n");
    for (int i = 0; i < (int)(sizeof(exfiltration)/sizeof(exfiltration[0])); i++) {
        printf("  - %s\n", exfiltration[i]);
    }
}

int main(int argc, char* argv[]) {
    print_simulation_info();
    
    printf("=== Detection Pattern Demo ===\n\n");
    
    simulate_recon();
    printf("\n");
    
    simulate_lateral();
    printf("\n");
    
    simulate_credential_access();
    printf("\n");
    
    simulate_exfil();
    printf("\n");
    
    printf("=== APT Indicators ===\n");
    for (int i = 0; i < (int)(sizeof(apt_indicators)/sizeof(apt_indicators[0])); i++) {
        printf("  - %s\n", apt_indicators[i]);
    }
    
    printf("\n=== Simulation Complete ===\n");
    printf("This binary contains patterns for testing detection capabilities.\n");
    
    return 0;
}
