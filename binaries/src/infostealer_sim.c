/**
 * SENTINEL Test Binary - Infostealer Simulation (2025 Patterns)
 * 
 * This is a SAFE test binary that contains patterns commonly found in 
 * modern infostealers (Lumma, RedLine, Raccoon, Vidar, StealC).
 * It doesn't actually steal any data.
 * 
 * Detection patterns:
 * - Browser credential paths
 * - Crypto wallet locations
 * - Discord/Telegram token paths
 * - Password manager databases
 * - Session cookie extraction
 * - 2FA/MFA backup codes
 * - Clipboard monitoring
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Browser credential paths (Chrome, Firefox, Edge, Brave, Opera)
const char* browser_paths[] = {
    // Chrome/Chromium variants
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies",
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Web Data",
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State",
    
    // Edge
    "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cookies",
    
    // Firefox
    "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json",
    "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\key4.db",
    "%APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\cookies.sqlite",
    
    // Brave
    "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
    
    // Opera
    "%APPDATA%\\Opera Software\\Opera Stable\\Login Data",
    
    // Vivaldi
    "%LOCALAPPDATA%\\Vivaldi\\User Data\\Default\\Login Data"
};

// Cryptocurrency wallet paths (modern 2025 patterns)
const char* wallet_paths[] = {
    // Desktop wallets
    "%APPDATA%\\Exodus\\exodus.wallet",
    "%APPDATA%\\Atomic\\Local Storage\\leveldb",
    "%APPDATA%\\Electrum\\wallets",
    "%APPDATA%\\Ethereum\\keystore",
    "%APPDATA%\\com.liberty.jaxx\\IndexedDB",
    "%APPDATA%\\Guarda\\Local Storage\\leveldb",
    "%APPDATA%\\Coinomi\\Coinomi\\wallets",
    
    // Browser extension wallets (Manifest V3)
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn",  // MetaMask
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa",  // Phantom
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\hnfanknocfeofbddgcijnmhnfnkdnaad",  // Coinbase
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\ibnejdfjmmkpcnlpebklmnkoeoihofec",  // Trust Wallet
    "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\aiifbnbfobpmeekipheeijimdpnlpgpp",  // Solflare
    
    // Hardware wallet software
    "%APPDATA%\\Ledger Live",
    "%APPDATA%\\Trezor Suite"
};

// Discord/Telegram/Communication app token paths
const char* messaging_paths[] = {
    // Discord tokens
    "%APPDATA%\\discord\\Local Storage\\leveldb",
    "%APPDATA%\\discordcanary\\Local Storage\\leveldb",
    "%APPDATA%\\discordptb\\Local Storage\\leveldb",
    
    // Telegram
    "%APPDATA%\\Telegram Desktop\\tdata",
    
    // Signal
    "%APPDATA%\\Signal\\sql\\db.sqlite",
    
    // Slack
    "%APPDATA%\\Slack\\Local Storage\\leveldb",
    "%APPDATA%\\Slack\\Cookies",
    
    // Teams
    "%APPDATA%\\Microsoft\\Teams\\Cookies",
    "%APPDATA%\\Microsoft\\Teams\\Local Storage\\leveldb"
};

// Password manager databases
const char* password_manager_paths[] = {
    // 1Password
    "%LOCALAPPDATA%\\1Password\\data\\1Password10.sqlite",
    
    // Bitwarden
    "%APPDATA%\\Bitwarden\\data.json",
    
    // KeePass
    "%USERPROFILE%\\Documents\\*.kdbx",
    
    // LastPass
    "%LOCALAPPDATA%\\LastPass",
    
    // Dashlane
    "%APPDATA%\\Dashlane\\profiles"
};

// 2FA/Authenticator app paths
const char* two_factor_paths[] = {
    // Authy
    "%APPDATA%\\Authy Desktop\\Local Storage\\leveldb",
    
    // 2FA backup codes
    "%USERPROFILE%\\Desktop\\*backup*code*",
    "%USERPROFILE%\\Documents\\*2fa*",
    "%USERPROFILE%\\Downloads\\*recovery*"
};

// Gaming platform credentials (2025 targets)
const char* gaming_paths[] = {
    // Steam
    "%PROGRAMFILES(x86)%\\Steam\\config\\loginusers.vdf",
    "%PROGRAMFILES(x86)%\\Steam\\ssfn*",
    
    // Epic Games
    "%LOCALAPPDATA%\\EpicGamesLauncher\\Saved\\Config\\Windows\\GameUserSettings.ini",
    
    // Battle.net
    "%APPDATA%\\Battle.net",
    
    // Riot Games
    "%LOCALAPPDATA%\\Riot Games\\Riot Client\\Data\\RiotGamesPrivateSettings.yaml",
    
    // EA App
    "%LOCALAPPDATA%\\Electronic Arts\\EA Desktop\\cache"
};

// Cloud storage tokens
const char* cloud_paths[] = {
    // Dropbox
    "%APPDATA%\\Dropbox\\info.json",
    
    // OneDrive
    "%LOCALAPPDATA%\\Microsoft\\OneDrive\\settings\\Personal",
    
    // Google Drive
    "%LOCALAPPDATA%\\Google\\DriveFS",
    
    // AWS credentials
    "%USERPROFILE%\\.aws\\credentials",
    
    // Azure
    "%USERPROFILE%\\.azure\\accessTokens.json",
    
    // GCP
    "%APPDATA%\\gcloud\\credentials.db"
};

// SSH/VPN keys
const char* ssh_vpn_paths[] = {
    "%USERPROFILE%\\.ssh\\id_rsa",
    "%USERPROFILE%\\.ssh\\id_ed25519",
    "%USERPROFILE%\\.ssh\\known_hosts",
    "%APPDATA%\\OpenVPN\\config\\*.ovpn",
    "%APPDATA%\\WireGuard\\*.conf"
};

// File extensions to look for
const char* target_extensions[] = {
    ".txt", ".doc", ".docx", ".pdf", ".csv", ".xls", ".xlsx",
    ".json", ".xml", ".env", ".config", ".cfg", ".ini",
    ".wallet", ".dat", ".key", ".pem", ".p12", ".pfx"
};

// C2 communication patterns
const char* c2_endpoints[] = {
    "/gate.php",
    "/panel/gate.php",
    "/api/send",
    "/api/upload",
    "/stealer/gate",
    "/collect/data",
    "/exfil/submit"
};

// Anti-analysis checks (simulated)
const char* sandbox_checks[] = {
    "VMwareVMware",
    "VBoxVBoxVBox",
    "Virtual HD",
    "QEMU HARDDISK",
    "Hyper-V",
    "Xen",
    "sbiedll.dll",      // Sandboxie
    "SbieDll.dll",
    "cmdvrt32.dll",     // Comodo
    "cuckoomon.dll",    // Cuckoo sandbox
    "pstorec.dll"
};

// Process names to check for (AV/EDR)
const char* security_processes[] = {
    "MsMpEng.exe",           // Windows Defender
    "MpCmdRun.exe",
    "securityhealthservice.exe",
    "avgui.exe",             // AVG
    "avgsvc.exe",
    "avp.exe",               // Kaspersky
    "kavtray.exe",
    "bdagent.exe",           // Bitdefender
    "vsserv.exe",
    "mbam.exe",              // Malwarebytes
    "mbamservice.exe",
    "ccSvcHst.exe",          // Norton
    "ns.exe",
    "SentinelAgent.exe",     // SentinelOne
    "CrowdStrike.exe",       // CrowdStrike
    "CSFalconService.exe"
};

// Keylogger strings (detection pattern)
const char* keylogger_apis[] = {
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "GetKeyboardState",
    "RegisterRawInputDevices",
    "GetRawInputData"
};

// Clipboard monitoring
const char* clipboard_apis[] = {
    "OpenClipboard",
    "GetClipboardData",
    "SetClipboardViewer",
    "AddClipboardFormatListener"
};

// Screenshot capture
const char* screenshot_apis[] = {
    "GetDesktopWindow",
    "GetDC",
    "BitBlt",
    "CreateCompatibleBitmap",
    "GetWindowRect"
};

// Data exfiltration methods
const char* exfil_methods[] = {
    "HttpSendRequestA",
    "HttpSendRequestW",
    "InternetConnectA",
    "InternetOpenUrlA",
    "WinHttpSendRequest",
    "curl_easy_perform",
    "Telegram Bot API",
    "Discord Webhook"
};

void print_simulation_info(void) {
    printf("=== SENTINEL Infostealer Simulation (2025 Patterns) ===\n\n");
    printf("This is a SAFE test binary for malware detection testing.\n");
    printf("It contains string patterns from modern infostealers:\n");
    printf("- Lumma Stealer\n");
    printf("- RedLine Stealer\n");
    printf("- Raccoon Stealer v2\n");
    printf("- Vidar Stealer\n");
    printf("- StealC\n");
    printf("- Rhadamanthys\n\n");
    printf("No actual data theft occurs.\n\n");
}

void simulate_browser_theft(void) {
    printf("[SIM] Checking browser credential locations...\n");
    for (int i = 0; i < (int)(sizeof(browser_paths)/sizeof(browser_paths[0])); i++) {
        printf("  - Path: %s\n", browser_paths[i]);
    }
}

void simulate_wallet_theft(void) {
    printf("[SIM] Checking cryptocurrency wallet locations...\n");
    for (int i = 0; i < (int)(sizeof(wallet_paths)/sizeof(wallet_paths[0])); i++) {
        printf("  - Path: %s\n", wallet_paths[i]);
    }
}

void simulate_token_theft(void) {
    printf("[SIM] Checking messaging app token locations...\n");
    for (int i = 0; i < (int)(sizeof(messaging_paths)/sizeof(messaging_paths[0])); i++) {
        printf("  - Path: %s\n", messaging_paths[i]);
    }
}

void simulate_sandbox_evasion(void) {
    printf("[SIM] Checking for sandbox/VM indicators...\n");
    for (int i = 0; i < (int)(sizeof(sandbox_checks)/sizeof(sandbox_checks[0])); i++) {
        printf("  - Check: %s\n", sandbox_checks[i]);
    }
}

int main(int argc, char* argv[]) {
    print_simulation_info();
    
    printf("=== Detection Pattern Demo ===\n\n");
    
    simulate_sandbox_evasion();
    printf("\n");
    
    simulate_browser_theft();
    printf("\n");
    
    simulate_wallet_theft();
    printf("\n");
    
    simulate_token_theft();
    printf("\n");
    
    printf("=== Simulation Complete ===\n");
    printf("This binary contains patterns for testing detection capabilities.\n");
    
    return 0;
}
