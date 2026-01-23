/**
 * SENTINEL Test Binary - Remote Access Trojan (RAT) Simulation
 * 
 * This is a SAFE test binary that contains patterns commonly found in RATs
 * to test detection capabilities. It doesn't provide any remote access.
 * 
 * Detection patterns:
 * - Remote desktop/VNC patterns
 * - Webcam/microphone access APIs
 * - Screen capture APIs
 * - File transfer patterns
 * - Command execution
 * - Persistence mechanisms
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// RAT capabilities (feature flags)
typedef struct {
    int remote_desktop;
    int file_manager;
    int webcam_capture;
    int microphone_capture;
    int keylogger;
    int screen_capture;
    int password_stealer;
    int process_manager;
    int registry_editor;
    int shell_access;
    int ddos_attack;
    int ransomware;
} RatCapabilities;

// Popular RAT names (for detection testing)
const char* known_rats[] = {
    "DarkComet",
    "njRAT",
    "Quasar RAT",
    "NanoCore",
    "AsyncRAT",
    "Remcos",
    "Agent Tesla",
    "Orcus RAT",
    "Poison Ivy",
    "Gh0st RAT",
    "BlackShades",
    "DarkTrack"
};

// Screen capture APIs
const char* screen_apis[] = {
    "GetDC",
    "CreateCompatibleDC",
    "BitBlt",
    "GetDIBits",
    "CreateCompatibleBitmap",
    "GdipCreateBitmapFromHBITMAP",
    "PrintWindow",
    "GetWindowDC"
};

// Webcam/audio capture APIs
const char* multimedia_apis[] = {
    "capCreateCaptureWindowA",
    "capDriverConnect",
    "capCaptureSequenceNoFile",
    "capFileSaveDIB",
    "waveInOpen",
    "waveInStart",
    "mciSendStringA",
    "DirectSoundCreate",
    "CoCreateInstance(CLSID_VideoInputDeviceCategory)"
};

// File transfer methods
const char* file_transfer[] = {
    "FtpPutFile",
    "FtpGetFile",
    "HttpSendRequestA",
    "InternetWriteFile",
    "InternetReadFile",
    "WinHttpSendRequest",
    "CreateFile + WriteFile + send()",
    "BITS Job (Background Intelligent Transfer)"
};

// Remote shell commands
const char* shell_commands[] = {
    "cmd.exe /c",
    "powershell.exe -ep bypass",
    "wmic process call create",
    "/bin/bash -c",
    "python -c",
    "certutil -urlcache -split -f",
    "bitsadmin /transfer"
};

// System info collection
const char* sysinfo_commands[] = {
    "systeminfo",
    "whoami /all",
    "net user",
    "net localgroup administrators",
    "ipconfig /all",
    "netstat -ano",
    "tasklist /v",
    "wmic product get name,version",
    "reg query HKLM\\SOFTWARE",
    "dir /s /b %USERPROFILE%\\Documents\\*.doc*"
};

// Password/credential theft targets
const char* credential_targets[] = {
    // Browsers
    "Chrome: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
    "Firefox: %APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json",
    "Edge: %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    // Email
    "Outlook: HKCU\\Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles",
    "Thunderbird: %APPDATA%\\Thunderbird\\Profiles",
    // FTP
    "FileZilla: %APPDATA%\\FileZilla\\recentservers.xml",
    "WinSCP: HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions",
    // Others
    "Steam: HKCU\\Software\\Valve\\Steam",
    "Discord: %APPDATA%\\Discord\\Local Storage\\leveldb"
};

// C2 protocol patterns
const char* c2_protocols[] = {
    "TCP raw socket",
    "HTTP(S) polling",
    "DNS tunneling",
    "ICMP covert channel",
    "WebSocket",
    "IRC command channel",
    "Tor hidden service",
    "Pastebin/GitHub for commands"
};

// Command types
const char* command_types[] = {
    "INFO - Get system information",
    "EXEC - Execute command",
    "UPLOAD - Upload file to victim",
    "DOWNLOAD - Download file from victim",
    "SCREENSHOT - Capture screen",
    "WEBCAM - Capture webcam",
    "KEYLOG - Start keylogger",
    "PERSIST - Install persistence",
    "UPDATE - Update RAT binary",
    "UNINSTALL - Remove RAT",
    "MSGBOX - Show message to victim",
    "OPENURL - Open URL in browser",
    "DDOS - Start DDoS attack"
};

// Mutex names (prevent multiple instances)
const char* mutex_names[] = {
    "Global\\{AsyncRAT-MUTEX}",
    "Global\\{DarkComet-MTEX}",
    "NJRAT_MUTEX_12345",
    "Quasar_MUTEX"
};

// Hidden file/folder locations
const char* hidden_locations[] = {
    "%APPDATA%\\Microsoft\\Windows\\SystemData",
    "%TEMP%\\tmp_svc",
    "%LOCALAPPDATA%\\Temp\\~DF",
    "C:\\Windows\\Temp\\svchost",
    "/tmp/.X11-unix/.rat",
    "/var/tmp/.cache"
};

// Network indicators
const char* network_iocs[] = {
    "User-Agent: Mozilla/5.0 (compatible)",
    "POST /gate.php HTTP/1.1",
    "GET /panel/command.php?id=",
    "Cookie: PHPSESSID=",
    "X-Bot-ID:",
    "Content-Type: application/x-www-form-urlencoded",
    "Base64 encoded POST body"
};

void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║     SENTINEL TEST - RAT (Remote Access Trojan) SIMULATION         ║\n");
    printf("║                                                                   ║\n");
    printf("║  This binary simulates RAT patterns but is COMPLETELY SAFE.       ║\n");
    printf("║  It does NOT provide any remote access capabilities.              ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void simulate_capabilities(void) {
    RatCapabilities caps = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0};
    
    printf("[*] RAT Capabilities (simulated):\n");
    printf("    ✓ Remote Desktop: %s\n", caps.remote_desktop ? "Enabled" : "Disabled");
    printf("    ✓ File Manager: %s\n", caps.file_manager ? "Enabled" : "Disabled");
    printf("    ✓ Webcam Capture: %s\n", caps.webcam_capture ? "Enabled" : "Disabled");
    printf("    ✓ Microphone: %s\n", caps.microphone_capture ? "Enabled" : "Disabled");
    printf("    ✓ Keylogger: %s\n", caps.keylogger ? "Enabled" : "Disabled");
    printf("    ✓ Screen Capture: %s\n", caps.screen_capture ? "Enabled" : "Disabled");
    printf("    ✓ Password Stealer: %s\n", caps.password_stealer ? "Enabled" : "Disabled");
    printf("    ✓ Process Manager: %s\n", caps.process_manager ? "Enabled" : "Disabled");
}

void simulate_screen_capture(void) {
    printf("\n[*] Screen capture APIs:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", screen_apis[i]);
    }
}

void simulate_multimedia_access(void) {
    printf("\n[*] Webcam/audio capture APIs:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", multimedia_apis[i]);
    }
}

void simulate_credential_theft(void) {
    printf("\n[*] Credential theft targets:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", credential_targets[i]);
    }
}

void simulate_c2_protocol(void) {
    printf("\n[*] C2 communication methods:\n");
    for (int i = 0; i < 4; i++) {
        printf("    - %s\n", c2_protocols[i]);
    }
}

void simulate_commands(void) {
    printf("\n[*] Supported commands:\n");
    for (int i = 0; i < 8; i++) {
        printf("    - %s\n", command_types[i]);
    }
}

void simulate_sysinfo(void) {
    printf("\n[*] System info collection:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", sysinfo_commands[i]);
    }
}

void simulate_persistence(void) {
    printf("\n[*] Mutex: %s\n", mutex_names[0]);
    printf("[*] Hidden location: %s\n", hidden_locations[0]);
}

int main(void) {
    print_banner();
    
    printf("[*] Known RAT families (for comparison):\n");
    for (int i = 0; i < 6; i++) {
        printf("    - %s\n", known_rats[i]);
    }
    
    simulate_capabilities();
    simulate_screen_capture();
    simulate_multimedia_access();
    simulate_credential_theft();
    simulate_c2_protocol();
    simulate_commands();
    simulate_sysinfo();
    simulate_persistence();
    
    printf("\n[*] Network IOCs:\n");
    for (int i = 0; i < 4; i++) {
        printf("    - %s\n", network_iocs[i]);
    }
    
    printf("\n[✓] RAT simulation complete.\n");
    printf("[✓] This was a SAFE test - no remote access provided.\n\n");
    
    return 0;
}
