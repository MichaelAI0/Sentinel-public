/**
 * SENTINEL Test Binary - Rootkit/Bootkit Simulation (2025 Patterns)
 * 
 * This is a SAFE test binary that contains patterns commonly found in
 * rootkits, bootkits, and kernel-level malware.
 * It doesn't perform any malicious activity.
 * 
 * Detection patterns:
 * - Kernel driver manipulation
 * - UEFI/BIOS persistence
 * - Direct kernel object manipulation (DKOM)
 * - Hypervisor-based hiding
 * - Filter driver abuse
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Kernel-level APIs (Windows)
const char* kernel_apis[] = {
    // Driver loading
    "NtLoadDriver",
    "ZwLoadDriver",
    "SeLoadDriverPrivilege",
    
    // Memory manipulation
    "MmMapIoSpace",
    "MmMapLockedPages",
    "MmAllocateContiguousMemory",
    "MmGetPhysicalAddress",
    
    // Process/thread manipulation
    "PsLookupProcessByProcessId",
    "PsLookupThreadByThreadId",
    "KeAttachProcess",
    "KeStackAttachProcess",
    "PsGetCurrentProcess",
    "PsGetCurrentThread",
    
    // Object manipulation
    "ObOpenObjectByPointer",
    "ObReferenceObjectByHandle",
    "ObDereferenceObject",
    
    // Registry callbacks
    "CmRegisterCallback",
    "CmRegisterCallbackEx",
    
    // File system callbacks
    "FltRegisterFilter",
    "IoRegisterFsRegistrationChange",
    
    // Network callbacks
    "NDIS filter driver",
    "WFP callout driver"
};

// DKOM techniques (Direct Kernel Object Manipulation)
const char* dkom_techniques[] = {
    // Process hiding
    "EPROCESS.ActiveProcessLinks",
    "PsActiveProcessHead",
    "Flink/Blink unlink",
    
    // Thread hiding
    "ETHREAD",
    "KTHREAD.ThreadListEntry",
    
    // Driver hiding
    "DRIVER_OBJECT",
    "PsLoadedModuleList",
    "MmUnloadedDrivers",
    
    // Handle table manipulation
    "HANDLE_TABLE_ENTRY",
    "ExpLookupHandleTableEntry",
    
    // Token manipulation
    "TOKEN structure",
    "SePrivilegeCheck"
};

// UEFI/BIOS persistence
const char* uefi_patterns[] = {
    // EFI system partition
    "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
    "\\EFI\\Boot\\bootx64.efi",
    
    // UEFI variables
    "GetVariable",
    "SetVariable",
    "EFI_GLOBAL_VARIABLE_GUID",
    
    // SMM (System Management Mode)
    "SMI handler",
    "SMRAM",
    "SMM_BASE",
    
    // SPI flash
    "BIOS region",
    "SPI flash write",
    "BIOSWE",
    
    // Known UEFI rootkits
    "LoJax",
    "MosaicRegressor",
    "MoonBounce",
    "CosmicStrand",
    "BlackLotus"
};

// Hypervisor-based hiding
const char* hypervisor_patterns[] = {
    // VMX instructions
    "VMXON",
    "VMXOFF",
    "VMLAUNCH",
    "VMRESUME",
    "VMREAD",
    "VMWRITE",
    "VMPTRLD",
    "VMPTRST",
    
    // VMCS manipulation
    "Virtual Machine Control Structure",
    "EPT (Extended Page Tables)",
    "VPID",
    
    // Blue Pill techniques
    "hypervisor rootkit",
    "VM escape",
    "nested virtualization"
};

// Filter driver abuse
const char* filter_drivers[] = {
    // File system filters
    "minifilter",
    "FLT_REGISTRATION",
    "FLT_OPERATION_REGISTRATION",
    "IRP_MJ_CREATE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    
    // Registry filters
    "REG_NOTIFY_CLASS",
    "RegNtPreCreateKey",
    "RegNtPreSetValueKey",
    
    // Network filters
    "NDIS intermediate driver",
    "WFP filter",
    "FWPM_LAYER",
    "FwpmFilterAdd"
};

// Anti-forensics
const char* anti_forensics[] = {
    // Log tampering
    "Event log clearing",
    "USN journal deletion",
    "MFT manipulation",
    
    // Memory evasion
    "pagefile encryption",
    "hibernation file",
    "crash dump manipulation",
    
    // Artifact removal
    "prefetch deletion",
    "shimcache clearing",
    "amcache.hve",
    "registry transaction logs"
};

// Kernel exploit patterns
const char* kernel_exploits[] = {
    // Common vulnerability classes
    "use-after-free",
    "pool overflow",
    "type confusion",
    "arbitrary write",
    "null pointer dereference",
    
    // Exploitation primitives
    "arbitrary read",
    "arbitrary write",
    "kernel ASLR bypass",
    "SMEP bypass",
    "SMAP bypass",
    "kCFG bypass",
    
    // Token stealing
    "system token",
    "PrimaryToken",
    "ImpersonationToken",
    "SeDebugPrivilege"
};

// Bootkits and MBR/VBR manipulation
const char* bootkit_patterns[] = {
    // MBR manipulation
    "MBR modification",
    "INT 13h hook",
    "boot sector",
    
    // VBR manipulation
    "Volume Boot Record",
    "NTFS bootcode",
    "bootmgr patch",
    
    // Windows Boot Manager
    "winload.exe",
    "winload.efi",
    "winresume.exe",
    
    // Boot Configuration Data
    "BCD modification",
    "bcdedit.exe",
    
    // Known bootkits
    "TDL4/TDSS",
    "Rovnix",
    "Carberp bootkit",
    "Olmasco",
    "FinFisher bootkit"
};

// Signed driver abuse (BYOVD - Bring Your Own Vulnerable Driver)
const char* byovd_drivers[] = {
    // Commonly abused signed drivers
    "gdrv.sys",           // GIGABYTE
    "aswArPot.sys",       // Avast
    "AsIO.sys",           // ASUS
    "dbutil_2_3.sys",     // Dell
    "rtcore64.sys",       // MSI
    "ene.sys",            // ENE Technology
    "WinRing0.sys",       // OpenLibSys
    "PROCEXP152.sys",     // Process Explorer
    "cpuz.sys"            // CPU-Z
};

// ETW/PPL bypass
const char* evasion_kernel[] = {
    // ETW bypass
    "EtwTi hooking",
    "EtwEventWrite patching",
    "TraceLogging disable",
    
    // PPL bypass
    "Protected Process Light",
    "ELAM driver",
    "csrss.exe impersonation",
    
    // PatchGuard/KPP
    "Kernel Patch Protection",
    "PatchGuard bypass",
    "KiScanTableForPrefix"
};

// Secure Boot bypass
const char* secureboot_bypass[] = {
    "Secure Boot policy",
    "UEFI db manipulation",
    "shim bootloader",
    "MOK (Machine Owner Key)",
    "CVE-2022-21894",      // Baton Drop
    "CVE-2023-24932"       // BlackLotus bypass
};

void print_simulation_info(void) {
    printf("=== SENTINEL Rootkit/Bootkit Simulation (2025 Patterns) ===\n\n");
    printf("This is a SAFE test binary for malware detection testing.\n");
    printf("It contains string patterns from kernel-level threats:\n");
    printf("- UEFI rootkits (MoonBounce, BlackLotus)\n");
    printf("- DKOM-based hiding\n");
    printf("- BYOVD attacks\n");
    printf("- Hypervisor rootkits\n\n");
    printf("No actual malicious activity occurs.\n\n");
}

void simulate_kernel_apis(void) {
    printf("[SIM] Kernel API patterns:\n");
    for (int i = 0; i < 10 && i < (int)(sizeof(kernel_apis)/sizeof(kernel_apis[0])); i++) {
        printf("  - %s\n", kernel_apis[i]);
    }
}

void simulate_dkom(void) {
    printf("[SIM] DKOM technique patterns:\n");
    for (int i = 0; i < (int)(sizeof(dkom_techniques)/sizeof(dkom_techniques[0])); i++) {
        printf("  - %s\n", dkom_techniques[i]);
    }
}

void simulate_uefi(void) {
    printf("[SIM] UEFI persistence patterns:\n");
    for (int i = 0; i < (int)(sizeof(uefi_patterns)/sizeof(uefi_patterns[0])); i++) {
        printf("  - %s\n", uefi_patterns[i]);
    }
}

void simulate_byovd(void) {
    printf("[SIM] BYOVD vulnerable drivers:\n");
    for (int i = 0; i < (int)(sizeof(byovd_drivers)/sizeof(byovd_drivers[0])); i++) {
        printf("  - %s\n", byovd_drivers[i]);
    }
}

int main(int argc, char* argv[]) {
    print_simulation_info();
    
    printf("=== Detection Pattern Demo ===\n\n");
    
    simulate_kernel_apis();
    printf("\n");
    
    simulate_dkom();
    printf("\n");
    
    simulate_uefi();
    printf("\n");
    
    simulate_byovd();
    printf("\n");
    
    printf("=== Bootkit Patterns ===\n");
    for (int i = 0; i < (int)(sizeof(bootkit_patterns)/sizeof(bootkit_patterns[0])); i++) {
        printf("  - %s\n", bootkit_patterns[i]);
    }
    
    printf("\n=== Simulation Complete ===\n");
    printf("This binary contains patterns for testing detection capabilities.\n");
    
    return 0;
}
