/**
 * SENTINEL Test Binary - Keylogger Simulation
 * 
 * This is a SAFE test binary that contains patterns commonly found in keyloggers
 * to test detection capabilities. It doesn't actually capture any keystrokes.
 * 
 * Detection patterns:
 * - Keyboard hook API references
 * - Clipboard monitoring strings
 * - Credential harvesting patterns
 * - Log file creation patterns
 * - Data exfiltration URLs
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// Keyboard hook APIs (Windows)
const char* keyboard_apis[] = {
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "GetKeyboardState",
    "GetKeyNameTextA",
    "GetKeyNameTextW",
    "MapVirtualKeyA",
    "MapVirtualKeyW",
    "ToAscii",
    "ToUnicode",
    "CallNextHookEx",
    "UnhookWindowsHookEx"
};

// Clipboard APIs
const char* clipboard_apis[] = {
    "OpenClipboard",
    "GetClipboardData",
    "CloseClipboard",
    "AddClipboardFormatListener",
    "RemoveClipboardFormatListener"
};

// Window enumeration (for window title logging)
const char* window_apis[] = {
    "GetForegroundWindow",
    "GetWindowTextA",
    "GetWindowTextW",
    "EnumWindows",
    "GetClassName"
};

// Special key representations
const char* special_keys[] = {
    "[ENTER]", "[BACKSPACE]", "[TAB]", "[ESC]",
    "[CTRL]", "[ALT]", "[SHIFT]", "[WIN]",
    "[F1]", "[F2]", "[F3]", "[F4]", "[F5]",
    "[F6]", "[F7]", "[F8]", "[F9]", "[F10]",
    "[F11]", "[F12]", "[INSERT]", "[DELETE]",
    "[HOME]", "[END]", "[PAGEUP]", "[PAGEDOWN]",
    "[UP]", "[DOWN]", "[LEFT]", "[RIGHT]",
    "[CAPSLOCK]", "[NUMLOCK]", "[SCROLLLOCK]",
    "[PRINTSCREEN]", "[PAUSE]"
};

// Credential-related strings
const char* credential_patterns[] = {
    "password", "Password", "PASSWORD", "passwd", "pwd",
    "login", "Login", "LOGIN", "logon", "Logon",
    "username", "Username", "USERNAME", "user", "User",
    "email", "Email", "EMAIL", "mail", "e-mail",
    "credit card", "creditcard", "cc number", "cvv", "cvc",
    "ssn", "social security", "bank account", "routing number",
    "pin", "PIN", "secret", "private key", "wallet"
};

// Browsers and applications to target
const char* target_apps[] = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "opera.exe", "brave.exe", "vivaldi.exe", "safari",
    "outlook.exe", "thunderbird.exe", "slack.exe", "teams.exe",
    "discord.exe", "telegram.exe", "whatsapp.exe", "signal.exe",
    "1password", "lastpass", "bitwarden", "keepass"
};

// Exfiltration endpoints (fake)
const char* exfil_urls[] = {
    "http://keylog-collector.xyz/submit",
    "https://data.evil-server.onion/upload",
    "ftp://logs.malware.net/incoming/",
    "smtp://exfil@evil.com"
};

// Log file patterns
const char* log_patterns[] = {
    "%TEMP%\\keylog.txt",
    "%APPDATA%\\svchost\\log.dat",
    "/tmp/.keylogger.log",
    "C:\\Users\\Public\\Documents\\~$temp.doc"
};

// Sample captured data format (fake)
const char* sample_log_entry = 
    "[2026-01-21 15:30:45] [Chrome - Gmail - Inbox]\n"
    "username@email.com[TAB]MyP@ssw0rd123[ENTER]\n";

// Autostart registry keys
const char* autostart_keys[] = {
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
};

// Hidden file attributes
const char* hiding_techniques[] = {
    "SetFileAttributesA(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)",
    "attrib +h +s filename",
    "mkdir %APPDATA%\\Microsoft\\Credentials\\~temp"
};

void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════════╗\n");
    printf("║     SENTINEL TEST - KEYLOGGER SIMULATION                          ║\n");
    printf("║                                                                   ║\n");
    printf("║  This binary simulates keylogger patterns but is COMPLETELY       ║\n");
    printf("║  SAFE. It does NOT capture any keystrokes.                        ║\n");
    printf("╚═══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void simulate_hook_installation(void) {
    printf("[*] Would install keyboard hooks using:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", keyboard_apis[i]);
    }
}

void simulate_clipboard_monitoring(void) {
    printf("\n[*] Would monitor clipboard using:\n");
    for (int i = 0; i < 3; i++) {
        printf("    - %s\n", clipboard_apis[i]);
    }
}

void simulate_window_tracking(void) {
    printf("\n[*] Would track active windows using:\n");
    for (int i = 0; i < 3; i++) {
        printf("    - %s\n", window_apis[i]);
    }
    
    printf("\n[*] Target applications:\n");
    for (int i = 0; i < 5; i++) {
        printf("    - %s\n", target_apps[i]);
    }
}

void simulate_credential_detection(void) {
    printf("\n[*] Would search for credential patterns:\n");
    for (int i = 0; i < 8; i++) {
        printf("    - \"%s\"\n", credential_patterns[i]);
    }
}

void simulate_logging(void) {
    printf("\n[*] Would write logs to:\n");
    printf("    %s\n", log_patterns[0]);
    
    printf("\n[*] Sample log entry format:\n");
    printf("────────────────────────────────────────\n");
    printf("%s", sample_log_entry);
    printf("────────────────────────────────────────\n");
}

void simulate_exfiltration(void) {
    printf("\n[*] Would exfiltrate data to:\n");
    printf("    %s\n", exfil_urls[0]);
}

void simulate_persistence(void) {
    printf("\n[*] Would add persistence via:\n");
    printf("    %s\n", autostart_keys[0]);
    
    printf("\n[*] Would hide files using:\n");
    printf("    %s\n", hiding_techniques[1]);
}

int main(void) {
    print_banner();
    
    simulate_hook_installation();
    simulate_clipboard_monitoring();
    simulate_window_tracking();
    simulate_credential_detection();
    simulate_logging();
    simulate_exfiltration();
    simulate_persistence();
    
    printf("\n[✓] Keylogger simulation complete.\n");
    printf("[✓] This was a SAFE test - no keystrokes were captured.\n\n");
    
    return 0;
}
