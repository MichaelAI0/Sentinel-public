# SENTINEL API Reference

> **Version:** 1.0.0  
> **Last Updated:** January 17, 2026

This document provides comprehensive API documentation for SENTINEL's components.

---

## Table of Contents

1. [Orchestrator HTTP API](#orchestrator-http-api)
2. [MCP Server Tools](#mcp-server-tools)
3. [CLI Commands](#cli-commands)
4. [Configuration](#configuration)

---

## Orchestrator HTTP API

The orchestrator provides an HTTP API for programmatic access to analysis capabilities.

### Base URL

```text
http://localhost:8080
```

### Endpoints

#### POST /analyze

Run full analysis workflow (triage → analyze → report).

**Request:**

```json
{
  "binaryPath": "/path/to/binary",
  "options": {
    "skipGhidra": false,
    "timeout": 600
  }
}
```

**Response:**

```json
{
  "status": "complete",
  "filename": "suspicious_test",
  "triage": {
    "riskLevel": "HIGH",
    "confidence": 0.85,
    "recommendation": "ESCALATE",
    "fileType": "ELF64",
    "sha256": "abc123...",
    "entropy": 6.8,
    "isPacked": false
  },
  "analysis": {
    "malwareFamily": "Mirai",
    "sophistication": "Intermediate",
    "capabilities": ["network", "persistence"],
    "mitreTechniques": [...],
    "iocs": {...},
    "yaraMatches": [...],
    "cryptoFindings": [...],
    "assemblyPatterns": [...]
  },
  "reports": {
    "markdown": "/outputs/sample_2026-01-17/report.md",
    "json": "/outputs/sample_2026-01-17/report.json",
    "stix": "/outputs/sample_2026-01-17/stix-bundle.json"
  }
}
```

**Status Codes:**

| Code | Description                                     |
| ---- | ----------------------------------------------- |
| 200  | Analysis complete                               |
| 400  | Invalid request (missing path, invalid options) |
| 404  | Binary file not found                           |
| 500  | Internal server error                           |

---

#### POST /triage

Run quick triage only (no deep analysis).

**Request:**

```json
{
  "binaryPath": "/path/to/binary"
}
```

**Response:**

```json
{
  "status": "complete",
  "filename": "sample.exe",
  "triage": {
    "riskLevel": "MEDIUM",
    "confidence": 0.75,
    "recommendation": "INVESTIGATE",
    "fileType": "PE32",
    "sha256": "def456...",
    "md5": "abc123...",
    "entropy": 5.2,
    "isPacked": false,
    "suspiciousStrings": ["http://evil.com", "cmd.exe"],
    "suspiciousImports": ["CreateRemoteThread", "VirtualAllocEx"],
    "reasoning": "File contains suspicious API imports..."
  }
}
```

---

#### GET /health

Health check endpoint.

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 3600
}
```

---

## MCP Server Tools

The MCP (Model Context Protocol) server exposes analysis tools that can be called by LLM agents.

### Tool: calculate_hashes

Calculate cryptographic hashes for a file.

**Input:**

```json
{
  "file_path": "/path/to/binary"
}
```

**Output:**

```json
{
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "ssdeep": "3::"
}
```

---

### Tool: detect_file_type

Detect file format via magic number analysis.

**Input:**

```json
{
  "file_path": "/path/to/binary"
}
```

**Output:**

```json
{
  "format": "PE32+",
  "arch": "AMD64",
  "os": "Windows",
  "endianness": "little",
  "mime": "application/x-dosexec",
  "entropy": 6.2
}
```

---

### Tool: extract_pe_headers

Extract Windows PE file headers.

**Input:**

```json
{
  "file_path": "/path/to/binary.exe"
}
```

**Output:**

```json
{
  "dosHeader": {...},
  "peHeader": {
    "machine": "AMD64",
    "numberOfSections": 5,
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "optionalHeader": {
    "entryPoint": "0x1000",
    "imageBase": "0x140000000",
    "subsystem": "CONSOLE"
  },
  "sections": [
    {
      "name": ".text",
      "virtualAddress": "0x1000",
      "rawSize": 4096,
      "characteristics": ["EXECUTE", "READ"]
    }
  ]
}
```

---

### Tool: extract_elf_headers

Extract Linux ELF file headers.

**Input:**

```json
{
  "file_path": "/path/to/binary"
}
```

**Output:**

```json
{
  "header": {
    "class": "ELF64",
    "type": "EXEC",
    "machine": "X86_64",
    "entryPoint": "0x401000"
  },
  "programHeaders": [...],
  "sectionHeaders": [...]
}
```

---

### Tool: match_signatures (YARA)

Scan file against YARA rules.

**Input:**

```json
{
  "file_path": "/path/to/binary",
  "timeout": 60,
  "rules_dir": "/custom/rules"
}
```

**Output:**

```json
{
  "success": true,
  "data": {
    "scanned": true,
    "matches": [
      {
        "rule": "Mirai_variant",
        "namespace": "malware",
        "tags": ["malware", "botnet"],
        "strings": [
          {
            "identifier": "$str1",
            "instances": [{ "offset": 1024, "length": 15 }]
          }
        ]
      }
    ]
  }
}
```

---

### Tool: unpack_binary

Detect and unpack packed executables.

**Input:**

```json
{
  "file_path": "/path/to/binary",
  "packer_type": "auto",
  "timeout": 30
}
```

**Output:**

```json
{
  "success": true,
  "detection": {
    "isPacked": true,
    "packerType": "upx",
    "confidence": 0.95,
    "method": "signature"
  },
  "unpack": {
    "success": true,
    "unpackedPath": "/tmp/unpacked_abc123",
    "originalSize": 10240,
    "unpackedSize": 45678,
    "compressionRatio": 4.46
  }
}
```

---

### Tool: detect_crypto

Detect cryptographic operations in binary.

**Input:**

```json
{
  "file_path": "/path/to/binary",
  "detect_xor": true,
  "min_confidence": 0.5
}
```

**Output:**

```json
{
  "success": true,
  "summary": {
    "hasCrypto": true,
    "detections": [
      {
        "algorithm": "aes",
        "confidence": 0.92,
        "method": "constant",
        "details": "AES S-box signature detected at offset 0x4500"
      }
    ],
    "likelyEncrypted": false
  }
}
```

---

### Tool: analyze_assembly

Analyze assembly patterns for suspicious behavior.

**Input:**

```json
{
  "assembly_text": "401000: syscall\n401002: ret",
  "function_name": "main"
}
```

**Output:**

```json
{
  "success": true,
  "summary": {
    "totalInstructions": 2,
    "patterns": [
      {
        "type": "syscall",
        "instructions": [{ "address": "401000", "mnemonic": "syscall" }],
        "description": "System call detected",
        "severity": "medium"
      }
    ]
  }
}
```

---

### Tool: analyze_strings

Analyze extracted strings for indicators.

**Input:**

```json
{
  "strings": ["http://evil.com", "cmd.exe /c", "password123"],
  "min_length": 4,
  "max_strings": 1000,
  "attempt_decode": true
}
```

**Output:**

```json
{
  "success": true,
  "summary": {
    "totalStrings": 3,
    "uniqueStrings": 3,
    "suspiciousCount": 2,
    "categoryBreakdown": {
      "url": 1,
      "command": 1,
      "generic": 1
    },
    "highValueStrings": [
      {
        "value": "http://evil.com",
        "category": "url",
        "suspicious": true,
        "entropy": 3.2
      }
    ]
  }
}
```

---

## CLI Commands

### sentinel analyze

Run full analysis workflow.

```bash
sentinel analyze <binaryPath> [options]

Options:
  -q, --quiet      Suppress non-error logs
  -V, --verbose    Show detailed progress with Phase 2 findings
  --json           Output machine-readable JSON
  --output-dir     Override output directory
```

**Examples:**

```bash
# Basic analysis
sentinel analyze ./malware.exe

# Verbose output with all findings
sentinel analyze ./malware.exe --verbose

# JSON output for automation
sentinel analyze ./malware.exe --json > result.json

# Custom output directory
sentinel analyze ./malware.exe --output-dir ./reports
```

---

### sentinel triage

Quick triage only (no deep analysis).

```bash
sentinel triage <binaryPath> [options]
```

**Examples:**

```bash
# Quick risk assessment
sentinel triage ./suspicious_file

# JSON output
sentinel triage ./suspicious_file --json
```

---

### sentinel batch

Analyze directory of samples.

```bash
sentinel batch <directory> [options]
```

**Examples:**

```bash
# Analyze all binaries in directory
sentinel batch ./samples/

# JSON report of all results
sentinel batch ./samples/ --json > batch_results.json
```

---

### sentinel check

Verify system dependencies.

```bash
sentinel check [options]
```

**Output:**

```text
SENTINEL Dependency Check

  ✓ Bun v1.3.4
  ✓ Docker v24.0.7
  ✓ Ghidra (Docker) v12.0.1
  ✓ Ollama v0.5.1 (http://localhost:11434)
  ○ YARA-X Optional
  ✓ MCP Server (http://localhost:3000)

✓ All required dependencies available
  1 optional dependencies not found
```

---

### sentinel server

Start HTTP API server.

```bash
sentinel server [options]

Options:
  --host <host>    Server host (default: 0.0.0.0)
  --port <port>    Server port (default: 8080)
```

---

## Configuration

### Config File

Create `sentinel.config.json` in project root:

```json
{
  "outputDir": "./outputs",
  "ollamaUrl": "http://localhost:11434",
  "mcpUrl": "http://localhost:3000",
  "verbose": false,
  "logLevel": "info"
}
```

### Environment Variables

| Variable          | Description                       | Default                  |
| ----------------- | --------------------------------- | ------------------------ |
| `OUTPUT_DIR`      | Report output directory           | `./outputs`              |
| `OLLAMA_BASE_URL` | Ollama API URL                    | `http://localhost:11434` |
| `MCP_SERVER_URL`  | MCP Server URL                    | `http://localhost:3000`  |
| `LOG_LEVEL`       | Log level (debug/info/warn/error) | `info`                   |
| `HOST`            | Server host                       | `0.0.0.0`                |
| `PORT`            | Server port                       | `8080`                   |

### Priority Order

1. CLI arguments (highest)
2. Environment variables
3. Config file
4. Defaults (lowest)

---

## Error Codes

| Code                  | Type | Description                  |
| --------------------- | ---- | ---------------------------- |
| `VALIDATION_ERROR`    | 400  | Invalid input parameters     |
| `FILE_NOT_FOUND`      | 404  | Binary file not found        |
| `FILE_ACCESS_ERROR`   | 403  | Permission denied            |
| `PATH_SECURITY_ERROR` | 400  | Path traversal detected      |
| `TIMEOUT_ERROR`       | 408  | Analysis timeout             |
| `SERVICE_ERROR`       | 503  | External service unavailable |
| `INTERNAL_ERROR`      | 500  | Unexpected internal error    |

---

## Rate Limits

The HTTP API has no built-in rate limiting. For production deployments, use a reverse proxy (nginx, Caddy) with rate limiting configured.

---

## Versioning

API versioning is not currently implemented. Breaking changes will be documented in release notes.

---

Last Updated: January 17, 2026
