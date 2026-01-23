/**
 * SENTINEL Test Binary - Loader/Dropper Simulation (2025 Patterns)
 * 
 * This is a SAFE test binary that contains patterns commonly found in
 * modern malware loaders and droppers (Emotet, QakBot, IcedID, Pikabot, Latrodectus).
 * It doesn't actually download or execute anything malicious.
 * 
 * Detection patterns:
 * - Process injection techniques
 * - Shellcode execution patterns
 * - Living off the Land (LOLBin) abuse
 * - DLL sideloading paths
 * - Memory-only execution
 * - Anti-sandbox techniques
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Process injection APIs (MITRE T1055)
const char* injection_apis[] = {
    // Classic injection
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    
    // Process hollowing
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "NtWriteVirtualMemory",
    
    // APC injection
    "QueueUserAPC",
    "NtQueueApcThread",
    
    // Thread hijacking
    "SuspendThread",
    "GetThreadContext",
    "SetThreadContext",
    "ResumeThread",
    
    // Atom bombing
    "GlobalAddAtomA",
    "GlobalGetAtomNameA",
    "NtQueueApcThread",
    
    // Early bird injection
    "NtTestAlert",
    
    // Module stomping
    "LoadLibraryExW",
    "VirtualProtect",
    
    // Syscall-based evasion
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateSection",
    "NtMapViewOfSection"
};

// Living off the Land binaries (LOLBins)
const char* lolbins[] = {
    // Execution
    "mshta.exe",
    "msiexec.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe",
    "powershell.exe",
    "pwsh.exe",
    
    // Download
    "curl.exe",
    "wget.exe",  // Windows 10+
    "bitsadmin.exe",
    "certutil.exe -urlcache -split -f",
    
    // Bypass
    "msbuild.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "cmstp.exe",
    "control.exe",
    "forfiles.exe",
    "pcalua.exe",
    
    // Persistence
    "schtasks.exe",
    "at.exe",
    "reg.exe",
    
    // Lateral movement
    "psexec.exe",
    "wmic.exe"
};

// DLL sideloading target paths (2025 campaigns)
const char* sideload_targets[] = {
    // Common legitimate apps abused for sideloading
    "OneDrive\\version.dll",
    "Microsoft\\Teams\\Update.exe",
    "Notepad++\\SciLexer.dll",
    "VLC\\libvlc.dll",
    "7-Zip\\7z.dll",
    "WinRAR\\rarext.dll",
    "Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.dll",
    "Cisco\\Webex\\webexmta.dll",
    "Zoom\\Zoom.exe",
    "Slack\\ffmpeg.dll"
};

// Shellcode patterns (XOR encoded common opcodes)
const unsigned char shellcode_stub[] = {
    0x55,                       // push ebp
    0x89, 0xe5,                 // mov ebp, esp
    0x83, 0xec, 0x20,           // sub esp, 0x20
    0x31, 0xc0,                 // xor eax, eax
    0x50,                       // push eax
    0x68, 0x63, 0x61, 0x6c, 0x63, // push "calc"
    0x54,                       // push esp
    0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, <WinExec>
    0xff, 0xd0,                 // call eax
    0x31, 0xc0,                 // xor eax, eax
    0xc9,                       // leave
    0xc3                        // ret
};

// Obfuscation techniques
const char* obfuscation_methods[] = {
    "XOR encoding",
    "RC4 encryption",
    "AES-256-CBC",
    "Base64 encoding",
    "Custom alphabet Base64",
    "Stack strings",
    "API hashing",
    "Control flow flattening",
    "Dead code insertion",
    "Opaque predicates"
};

// Anti-analysis techniques (MITRE T1497)
const char* anti_analysis[] = {
    // Time-based
    "GetTickCount",
    "QueryPerformanceCounter",
    "NtQuerySystemTime",
    "Sleep",
    "WaitForSingleObject",
    
    // Environment checks
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "GetSystemInfo",
    "GetVersion",
    
    // Hardware checks
    "cpuid",
    "__rdtsc",
    "GetSystemFirmwareTable",
    
    // Memory checks
    "VirtualQuery",
    "NtQueryVirtualMemory"
};

// VM detection strings
const char* vm_artifacts[] = {
    // VMware
    "VMwareVMware",
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "\\\\.\\HGFS",
    "\\\\.\\vmci",
    
    // VirtualBox
    "VBoxService.exe",
    "VBoxTray.exe",
    "\\\\.\\VBoxMiniRdrDN",
    "\\\\.\\VBoxGuest",
    
    // Hyper-V
    "vmms.exe",
    "vmwp.exe",
    
    // QEMU
    "QEMU",
    "BOCHS",
    
    // Sandbox vendors
    "SbieDll.dll",      // Sandboxie
    "dbghelp.dll",      // Debugging
    "api_log.dll",      // API monitoring
    "dir_watch.dll",    // Directory monitoring
    "pstorec.dll",      // Protected storage
    "vmcheck.dll"       // VM check tools
};

// Registry persistence paths
const char* persistence_registry[] = {
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKLM\\SYSTEM\\CurrentControlSet\\Services",
    "HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit"
};

// Scheduled task patterns
const char* schtask_patterns[] = {
    "schtasks /create /tn \"WindowsUpdate\" /tr",
    "schtasks /create /tn \"MicrosoftEdgeUpdateTaskMachine\" /tr",
    "schtasks /create /sc onlogon /tn",
    "schtasks /create /sc minute /mo 30"
};

// C2 communication patterns (2025)
const char* c2_patterns[] = {
    // HTTP/HTTPS C2
    "POST /api/v1/check-in",
    "GET /config/settings.json",
    "PUT /upload/beacon",
    "Cookie: PHPSESSID=",
    "User-Agent: Mozilla/5.0",
    
    // DNS tunneling
    "TXT record query",
    "nslookup -type=TXT",
    
    // DoH (DNS over HTTPS)
    "dns.google/resolve",
    "cloudflare-dns.com/dns-query",
    
    // WebSocket C2
    "wss://",
    "Upgrade: websocket",
    
    // Cloud C2 (living off trusted services)
    "api.telegram.org/bot",
    "discord.com/api/webhooks",
    "api.github.com/gists",
    "pastebin.com/raw/",
    "transfer.sh"
};

// UAC bypass techniques
const char* uac_bypass[] = {
    "eventvwr.exe",
    "fodhelper.exe",
    "computerdefaults.exe",
    "sdclt.exe",
    "slui.exe",
    "cmstp.exe /s",
    "CMSTPLUA COM interface"
};

// AMSI/ETW bypass patterns
const char* evasion_patterns[] = {
    "AmsiScanBuffer",
    "AmsiOpenSession",
    "EtwEventWrite",
    "NtTraceEvent",
    "amsi.dll",
    "clr.dll"
};

// Cobalt Strike/Sliver/Havoc beacon indicators
const char* c2_framework_patterns[] = {
    // Cobalt Strike
    "beacon.dll",
    "beacon.x64.dll",
    "%COMSPEC%",
    "IEX (New-Object Net.Webclient).DownloadString",
    "powershell -nop -w hidden -encodedcommand",
    
    // Sliver
    "sliver-client",
    "sliver-server",
    
    // Havoc
    "Havoc Framework",
    "demon.x64.dll",
    
    // Mythic
    "Athena",
    "Apollo"
};

void print_simulation_info(void) {
    printf("=== SENTINEL Loader/Dropper Simulation (2025 Patterns) ===\n\n");
    printf("This is a SAFE test binary for malware detection testing.\n");
    printf("It contains string patterns from modern loaders:\n");
    printf("- Emotet\n");
    printf("- QakBot/QBot\n");
    printf("- IcedID/BokBot\n");
    printf("- Pikabot\n");
    printf("- Latrodectus\n");
    printf("- SocGholish\n");
    printf("- Cobalt Strike beacons\n\n");
    printf("No actual malicious activity occurs.\n\n");
}

void simulate_injection_check(void) {
    printf("[SIM] Process injection API patterns:\n");
    for (int i = 0; i < (int)(sizeof(injection_apis)/sizeof(injection_apis[0])); i++) {
        printf("  - %s\n", injection_apis[i]);
    }
}

void simulate_lolbin_abuse(void) {
    printf("[SIM] LOLBin patterns:\n");
    for (int i = 0; i < 10 && i < (int)(sizeof(lolbins)/sizeof(lolbins[0])); i++) {
        printf("  - %s\n", lolbins[i]);
    }
}

void simulate_anti_analysis(void) {
    printf("[SIM] Anti-analysis techniques:\n");
    for (int i = 0; i < (int)(sizeof(vm_artifacts)/sizeof(vm_artifacts[0])); i++) {
        printf("  - VM check: %s\n", vm_artifacts[i]);
    }
}

int main(int argc, char* argv[]) {
    print_simulation_info();
    
    printf("=== Detection Pattern Demo ===\n\n");
    
    simulate_anti_analysis();
    printf("\n");
    
    simulate_injection_check();
    printf("\n");
    
    simulate_lolbin_abuse();
    printf("\n");
    
    printf("=== Shellcode stub (benign demo) ===\n");
    printf("Size: %zu bytes\n", sizeof(shellcode_stub));
    printf("First bytes: 0x%02x 0x%02x 0x%02x\n", 
           shellcode_stub[0], shellcode_stub[1], shellcode_stub[2]);
    
    printf("\n=== Simulation Complete ===\n");
    printf("This binary contains patterns for testing detection capabilities.\n");
    
    return 0;
}
