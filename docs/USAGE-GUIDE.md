# SENTINEL Usage Guide

> **Version:** 1.0.0  
> **Last Updated:** January 22, 2026

This guide walks through common workflows and usage patterns for SENTINEL.

---

## Table of Contents

1. [Editions Overview](#editions-overview)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [Basic Workflows](#basic-workflows)
5. [Advanced Usage](#advanced-usage)
6. [Understanding Reports](#understanding-reports)
7. [Troubleshooting](#troubleshooting)

---

## Editions Overview

SENTINEL is available in three editions:

| Feature              | Community (Free) | Professional | Enterprise |
| -------------------- | :--------------: | :----------: | :--------: |
| Triage (heuristics)  | ✅               | ✅           | ✅         |
| Ghidra integration   | ✅               | ✅           | ✅         |
| Local LLM (Ollama)   | ✅               | ✅           | ✅         |
| AI-powered analysis  | ❌               | ✅           | ✅         |
| Cloud LLMs           | ❌               | ✅           | ✅         |
| Priority support     | ❌               | ❌           | ✅         |

> **Note:** The `analyze` command requires Professional or Enterprise edition for full AI-powered analysis. Community users can use `triage` for heuristic-based assessment.

Premium features are planned for future release. Contact the maintainer for inquiries.

---

## Quick Start

```bash
# 1. Start services
bun run start

# 2. Check dependencies
sentinel check

# 3. Analyze a binary
sentinel analyze ./sample.exe

# 4. View reports in outputs/
cat outputs/sample_2026-01-17/report.md
```

---

## Installation

### Prerequisites

| Component | Required | Notes              |
| --------- | -------- | ------------------ |
| Bun 1.3+  | Yes      | Runtime            |
| Docker    | Yes      | For Ghidra         |
| Ollama    | Yes      | LLM reasoning      |
| YARA-X    | Optional | Signature matching |
| UPX       | Optional | Unpacking          |

### Setup Steps

1. **Clone and install:**

   ```bash
   git clone https://github.com/org/sentinel.git
   cd sentinel
   bun install
   ```

2. **Start Ollama with model:**

   ```bash
   ollama pull qwen3:8b
   ollama serve
   ```

3. **Build Ghidra container:**

   ```bash
   docker compose build ghidra
   ```

4. **Start all services:**

   ```bash
   bun run start
   ```

5. **Verify setup:**

   ```bash
   sentinel check
   ```

---

## Basic Workflows

### Workflow 1: Quick Triage

Use triage for fast risk assessment without deep analysis.

```bash
sentinel triage ./suspicious_file
```

**Output:**

```text
SENTINEL Quick Triage

  File: suspicious_file
  Risk: HIGH (85% confidence)
  Recommendation: ESCALATE

  Type: ELF64 (x86_64)
  SHA256: abc123...
  Entropy: 7.2 (high)
```

**When to use:**

- Initial screening of large sample sets
- Quick decision on whether to escalate
- Resource-constrained environments

---

### Workflow 2: Full Analysis

Use analyze for comprehensive analysis with LLM reasoning.

```bash
sentinel analyze ./malware.exe
```

**Output:**

```text
SENTINEL Analysis Complete

  File: malware.exe
  Status: Complete
  Risk: CRITICAL

  Reports generated:
    outputs/malware_2026-01-17/report.md
    outputs/malware_2026-01-17/report.json
    outputs/malware_2026-01-17/stix-bundle.json
```

**When to use:**

- Confirmed suspicious samples
- Detailed threat intelligence needed
- STIX output for SIEM integration

---

### Workflow 3: Batch Analysis

Analyze multiple samples in a directory.

```bash
sentinel batch ./samples/
```

**Output:**

```text
SENTINEL Batch Analysis

  Samples: 15
  Progress: [████████████████] 100%

  Results:
    CRITICAL: 2
    HIGH: 5
    MEDIUM: 3
    LOW: 5

  Reports: outputs/batch_2026-01-17/
```

---

### Workflow 4: Verbose Analysis

See detailed Phase 2 findings during analysis.

```bash
sentinel analyze ./sample --verbose
```

**Shows:**

- YARA rule matches
- Cryptographic detections
- Assembly patterns (anti-debug, syscalls)
- String analysis categories
- Unpacking results

---

### Workflow 5: JSON Output for Automation

```bash
sentinel analyze ./sample --json > result.json
```

**Process with jq:**

```bash
# Extract risk level
cat result.json | jq '.triage.riskLevel'

# Get all IOCs
cat result.json | jq '.analysis.iocs'

# List YARA matches
cat result.json | jq '.analysis.yaraMatches[].rule'
```

---

## Advanced Usage

### Custom Output Directory

```bash
sentinel analyze ./sample --output-dir /path/to/reports
```

### HTTP API Integration

**Start server:**

```bash
sentinel server --port 8080
```

**Call API:**

```bash
curl -X POST http://localhost:8080/analyze \
  -H "Content-Type: application/json" \
  -d '{"binaryPath": "/absolute/path/to/binary"}'
```

### Environment Configuration

```bash
# Use custom Ollama instance
OLLAMA_BASE_URL=http://remote-host:11434 sentinel analyze ./sample

# Debug logging
LOG_LEVEL=debug sentinel analyze ./sample
```

### Processing STIX Output

SENTINEL generates STIX 2.1 bundles for threat intelligence platforms.

```python
import json

with open('outputs/sample/stix-bundle.json') as f:
    bundle = json.load(f)

# Extract indicators
indicators = [obj for obj in bundle['objects']
              if obj['type'] == 'indicator']

for ind in indicators:
    print(f"Pattern: {ind['pattern']}")
```

---

## Understanding Reports

### Markdown Report Structure

```markdown
# Analysis Report: sample.exe

## Executive Summary

[High-level findings and risk assessment]

## File Information

[Hashes, type, size, timestamps]

## Triage Assessment

[Quick risk indicators and reasoning]

## Technical Analysis

[Deep findings from all analysis phases]

## YARA Matches

[Signature-based detections]

## Crypto Operations

[Cryptographic algorithm detections]

## Assembly Patterns

[Anti-debug, syscalls, suspicious code]

## Strings Analysis

[URLs, IPs, commands, registry keys]

## MITRE ATT&CK Mapping

[Technique classifications]

## Recommendations

[Actionable remediation steps]
```

### JSON Report Fields

| Field              | Description                |
| ------------------ | -------------------------- |
| `timestamp`        | Analysis timestamp         |
| `triage`           | Quick assessment results   |
| `analysis`         | Deep analysis findings     |
| `yaraMatches`      | Matched YARA rules         |
| `cryptoFindings`   | Detected crypto algorithms |
| `assemblyPatterns` | Suspicious code patterns   |
| `enhancedStrings`  | Categorized strings        |
| `mitreTechniques`  | ATT&CK mappings            |
| `iocs`             | Extracted indicators       |

### Risk Levels

| Level    | Description                    | Action                |
| -------- | ------------------------------ | --------------------- |
| CRITICAL | Known malware, high confidence | Immediate response    |
| HIGH     | Strong malicious indicators    | Escalate to analyst   |
| MEDIUM   | Suspicious but unclear         | Further investigation |
| LOW      | Likely benign                  | Monitor               |

---

## Troubleshooting

### Common Issues

#### "MCP Server not responding"

```bash
# Check if running
curl http://localhost:3000/health

# Restart
bun run mcp:server
```

#### "Ollama connection failed"

```bash
# Check Ollama
ollama list

# Verify model
ollama pull qwen3:8b

# Check service
systemctl status ollama
```

#### "Ghidra timeout"

```bash
# Check Docker
docker ps | grep ghidra

# View logs
docker logs sentinel-ghidra

# Restart container
docker compose restart ghidra
```

#### "YARA not found"

YARA-X is optional. Install for signature matching:

```bash
# Install YARA-X
cargo install yara-x

# Verify
yara-x --version
```

#### "Permission denied on binary"

```bash
# Check permissions
ls -la ./sample

# Make readable
chmod +r ./sample
```

### Debug Mode

Enable verbose logging:

```bash
LOG_LEVEL=debug sentinel analyze ./sample 2>&1 | tee debug.log
```

### Getting Help

```bash
# Show help
sentinel help

# Check system
sentinel check

# View logs
cat logs/sentinel.log
```

---

## Best Practices

1. **Use triage first** - Screen samples before full analysis
2. **Set timeouts** - Prevent runaway analyses on complex binaries
3. **Archive reports** - Keep STIX bundles for threat intelligence
4. **Batch overnight** - Queue large sample sets for off-hours processing
5. **Update YARA rules** - Keep signature database current
6. **Monitor resources** - Ghidra can be memory-intensive

---

## Examples Repository

See [/examples](../examples/) for:

- Sample binaries for testing
- Integration scripts
- Custom YARA rules
- Automation workflows

---

Last Updated: January 17, 2026
