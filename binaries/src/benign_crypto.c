/**
 * SENTINEL Test Binary - Benign Cryptography Demo
 * 
 * Contains crypto-related strings in educational/legitimate context.
 * Tests if detector can distinguish malicious vs legitimate crypto usage.
 * May trigger some crypto-related detections but should be LOW severity.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Algorithm information (educational)
typedef struct {
    const char* name;
    const char* type;
    int key_size;
    int block_size;
    const char* description;
} CryptoAlgorithm;

const CryptoAlgorithm algorithms[] = {
    {"AES-128", "Symmetric", 128, 128, "Advanced Encryption Standard with 128-bit key"},
    {"AES-256", "Symmetric", 256, 128, "Advanced Encryption Standard with 256-bit key"},
    {"ChaCha20", "Stream", 256, 0, "Stream cipher by Daniel J. Bernstein"},
    {"RSA-2048", "Asymmetric", 2048, 0, "Rivest-Shamir-Adleman with 2048-bit key"},
    {"RSA-4096", "Asymmetric", 4096, 0, "Rivest-Shamir-Adleman with 4096-bit key"},
    {"Ed25519", "Signature", 256, 0, "Edwards-curve Digital Signature Algorithm"},
    {"ECDSA", "Signature", 256, 0, "Elliptic Curve Digital Signature Algorithm"},
    {"SHA-256", "Hash", 0, 256, "Secure Hash Algorithm 256-bit"},
    {"SHA-512", "Hash", 0, 512, "Secure Hash Algorithm 512-bit"},
    {"BLAKE3", "Hash", 0, 256, "Modern cryptographic hash function"},
    {"Argon2id", "KDF", 0, 0, "Password hashing function"},
    {"PBKDF2", "KDF", 0, 0, "Password-Based Key Derivation Function 2"},
};

// Hash function information
typedef struct {
    const char* name;
    int output_bits;
    int collision_resistant;
    const char* usage;
} HashInfo;

const HashInfo hash_functions[] = {
    {"MD5", 128, 0, "Legacy checksums only - NOT secure"},
    {"SHA-1", 160, 0, "Legacy systems - deprecated"},
    {"SHA-256", 256, 1, "General purpose, TLS, Bitcoin"},
    {"SHA-384", 384, 1, "Higher security applications"},
    {"SHA-512", 512, 1, "Maximum security"},
    {"SHA3-256", 256, 1, "NIST standard, post-quantum prep"},
    {"BLAKE2b", 512, 1, "Fast, secure, general purpose"},
    {"BLAKE3", 256, 1, "Very fast, secure, modern"}
};

// Simple XOR demonstration (for teaching purposes)
void xor_demo(const uint8_t* data, size_t len, uint8_t key) {
    printf("XOR encryption demo (key=0x%02X):\n", key);
    printf("  Original: ");
    for (size_t i = 0; i < len && i < 8; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n  XORed:    ");
    for (size_t i = 0; i < len && i < 8; i++) {
        printf("%02X ", data[i] ^ key);
    }
    printf("\n");
}

// ROT13 demonstration
void rot13(char* text) {
    while (*text) {
        if ((*text >= 'A' && *text <= 'Z')) {
            *text = 'A' + ((*text - 'A' + 13) % 26);
        } else if ((*text >= 'a' && *text <= 'z')) {
            *text = 'a' + ((*text - 'a' + 13) % 26);
        }
        text++;
    }
}

// Simple checksum (educational)
uint32_t simple_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += data[i];
        sum = (sum << 1) | (sum >> 31);  // Rotate left
    }
    return sum;
}

// Base64 alphabet (for reference)
const char base64_alphabet[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Simple base64 encode (partial implementation for demo)
void base64_encode_demo(const uint8_t* input, size_t len) {
    printf("Base64 encoding demo:\n");
    printf("  Input bytes: ");
    for (size_t i = 0; i < len && i < 6; i++) {
        printf("%02X ", input[i]);
    }
    printf("\n  Base64 alphabet: %s\n", base64_alphabet);
}

// Random number concepts
void explain_random() {
    printf("\nRandom Number Generation:\n");
    printf("  CSPRNG: Cryptographically Secure Pseudo-Random Number Generator\n");
    printf("  Sources: /dev/urandom, /dev/random, CryptGenRandom\n");
    printf("  Uses: Key generation, nonces, IVs, salts\n");
    printf("  Warning: Never use rand() for cryptography!\n");
}

// Key derivation concepts
void explain_kdf() {
    printf("\nKey Derivation Functions (KDF):\n");
    printf("  Purpose: Derive cryptographic keys from passwords\n");
    printf("  Argon2id: Winner of Password Hashing Competition (2015)\n");
    printf("  PBKDF2: Older standard, still widely used\n");
    printf("  scrypt: Memory-hard function\n");
    printf("  bcrypt: Popular for password hashing\n");
    printf("  Parameters: Salt, iterations/work factor, memory cost\n");
}

// Certificate concepts
void explain_certificates() {
    printf("\nX.509 Certificates:\n");
    printf("  Purpose: Bind public key to identity\n");
    printf("  Components:\n");
    printf("    - Subject: Entity the cert identifies\n");
    printf("    - Issuer: Certificate Authority (CA)\n");
    printf("    - Public Key: RSA/EC public key\n");
    printf("    - Validity Period: Not Before/Not After\n");
    printf("    - Signature: CA's digital signature\n");
    printf("  File formats: PEM (.pem, .crt), DER (.der), PKCS#12 (.p12, .pfx)\n");
}

int main(int argc, char* argv[]) {
    printf("=== Cryptography Concepts Demo ===\n\n");
    
    // List algorithms
    printf("Cryptographic Algorithms:\n");
    printf("%-12s %-12s %8s %8s\n", "Name", "Type", "Key(b)", "Block(b)");
    printf("----------------------------------------\n");
    for (int i = 0; i < 6; i++) {
        printf("%-12s %-12s %8d %8d\n",
               algorithms[i].name,
               algorithms[i].type,
               algorithms[i].key_size,
               algorithms[i].block_size);
    }
    
    // Hash functions
    printf("\nHash Functions:\n");
    for (int i = 0; i < 4; i++) {
        printf("  %s (%d-bit): %s\n",
               hash_functions[i].name,
               hash_functions[i].output_bits,
               hash_functions[i].collision_resistant ? "Secure" : "DEPRECATED");
    }
    
    // XOR demo
    printf("\n");
    uint8_t sample[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    xor_demo(sample, 5, 0x42);
    
    // ROT13 demo
    char text[] = "Hello World";
    printf("\nROT13 Demo:\n");
    printf("  Original: %s\n", text);
    rot13(text);
    printf("  ROT13:    %s\n", text);
    
    // Checksum demo
    printf("\nChecksum Demo:\n");
    printf("  Checksum of 'Hello': 0x%08X\n", simple_checksum(sample, 5));
    
    // Educational sections
    explain_random();
    explain_kdf();
    explain_certificates();
    
    printf("\n=== Demo Complete ===\n");
    printf("This program demonstrates cryptographic CONCEPTS only.\n");
    printf("No actual encryption/decryption is performed.\n");
    
    return 0;
}
