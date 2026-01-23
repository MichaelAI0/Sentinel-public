# SENTINEL CLI Reference

> **Version:** 1.0.0  
> **Last Updated:** January 22, 2026

Complete command-line interface reference for SENTINEL.

---

## Table of Contents

1. [Synopsis](#synopsis)
2. [Edition Display](#edition-display)
3. [Global Options](#global-options)
4. [Commands](#commands)
   - [analyze](#analyze)
   - [triage](#triage)
   - [check](#check)
   - [server](#server)
   - [batch](#batch)
5. [Output Formats](#output-formats)
6. [Exit Codes](#exit-codes)
7. [Environment Variables](#environment-variables)
8. [Configuration File](#configuration-file)
9. [Examples](#examples)

---

## Synopsis

```text
sentinel [options] <command> [arguments]
```

---

## Edition Display

When running commands, SENTINEL displays the current edition:

```text
SENTINEL Community Edition (Open Source)
```

```text
SENTINEL Professional Edition
```

```text
SENTINEL Enterprise Edition
```

> **Note:** Some commands require Professional or Enterprise edition. Premium features are planned for future release. Contact the maintainer for inquiries.

---

## Global Options

| Option            | Short | Description                   |
| ----------------- | ----- | ----------------------------- |
| `--help`          | `-h`  | Show help message             |
| `--version`       | `-v`  | Show version                  |
| `--quiet`         | `-q`  | Suppress non-essential output |
| `--verbose`       | `-V`  | Enable verbose logging        |
| `--json`          |       | Output in JSON format         |
| `--config <path>` | `-c`  | Path to configuration file    |
| `--no-color`      |       | Disable colored output        |

---

## Commands

### analyze

Perform comprehensive malware analysis on a binary file.

> ⚠️ **Requires Professional or Enterprise Edition** for full AI-powered analysis. Community Edition users can use the `triage` command for heuristic-based assessment.

```text
sentinel analyze <file> [options]
```

#### Arguments

| Argument | Required | Description                        |
| -------- | -------- | ---------------------------------- |
| `<file>` | Yes      | Path to the binary file to analyze |

#### Options

| Option                | Default     | Description                                      |
| --------------------- | ----------- | ------------------------------------------------ |
| `--output <dir>`      | `./outputs` | Output directory for reports                     |
| `--timeout <seconds>` | `300`       | Analysis timeout in seconds                      |
| `--skip-ghidra`       | `false`     | Skip Ghidra decompilation                        |
| `--skip-yara`         | `false`     | Skip YARA rule matching                          |
| `--format <type>`     | `all`       | Output format: `json`, `markdown`, `stix`, `all` |
| `--model <name>`      | `qwen3:8b`  | Ollama model for analysis                        |
| `--no-update`         | `false`     | Skip signature auto-update                       |

#### Output Files

| File               | Description                         |
| ------------------ | ----------------------------------- |
| `report.json`      | Structured analysis results         |
| `report.md`        | Human-readable Markdown report      |
| `stix-bundle.json` | STIX 2.1 threat intelligence bundle |

#### Example

```bash
# Basic analysis
sentinel analyze suspicious.exe

# Custom output directory
sentinel analyze suspicious.exe --output ./reports

# Skip Ghidra for faster analysis
sentinel analyze suspicious.exe --skip-ghidra

# JSON output only
sentinel analyze suspicious.exe --format json --quiet
```

---

### triage

Quick risk assessment without deep analysis.

```
sentinel triage <file> [options]
```

#### Arguments

| Argument | Required | Description                       |
| -------- | -------- | --------------------------------- |
| `<file>` | Yes      | Path to the binary file to triage |

#### Options

| Option                | Default  | Description                             |
| --------------------- | -------- | --------------------------------------- |
| `--json`              | `false`  | Output in JSON format                   |
| `--threshold <level>` | `medium` | Risk threshold: `low`, `medium`, `high` |

#### Output

Returns a quick risk assessment with:

- File metadata (size, type, hashes)
- Entropy analysis
- Packing detection
- Suspicious indicators count
- Risk level (LOW, MEDIUM, HIGH, CRITICAL)

#### Example

```bash
# Quick triage
sentinel triage unknown.dll

# JSON output for scripting
sentinel triage unknown.dll --json

# Alert only on high-risk files
sentinel triage unknown.dll --threshold high
```

---

### check

Verify SENTINEL installation and dependencies.

```
sentinel check [options]
```

#### Options

| Option   | Default | Description           |
| -------- | ------- | --------------------- |
| `--json` | `false` | Output in JSON format |
| `--fix`  | `false` | Attempt to fix issues |

#### Checks Performed

- Bun runtime version
- Ollama connectivity and model availability
- Docker daemon status
- Ghidra container health
- MCP Server status
- Optional tools (YARA-X, UPX, radare2)

#### Example

```bash
# Run health check
sentinel check

# JSON output for monitoring
sentinel check --json

# Attempt automatic fixes
sentinel check --fix
```

---

### server

Start SENTINEL as an HTTP API server.

```
sentinel server [options]
```

#### Options

| Option          | Default   | Description         |
| --------------- | --------- | ------------------- |
| `--port <port>` | `8080`    | HTTP server port    |
| `--host <host>` | `0.0.0.0` | Server bind address |
| `--cors`        | `false`   | Enable CORS headers |

#### API Endpoints

| Method   | Endpoint            | Description                 |
| -------- | ------------------- | --------------------------- |
| `POST`   | `/api/analyze`      | Submit file for analysis    |
| `GET`    | `/api/analyses/:id` | Get analysis status/results |
| `GET`    | `/api/health`       | Health check endpoint       |
| `DELETE` | `/api/analyses/:id` | Cancel analysis             |

#### Example

```bash
# Start server on default port
sentinel server

# Custom port
sentinel server --port 3000

# With CORS for web clients
sentinel server --port 3000 --cors
```

---

### update-signatures

Update YARA rules and signatures.

```
sentinel update-signatures [options]
```

#### Options

| Option               | Default   | Description                        |
| -------------------- | --------- | ---------------------------------- |
| `--force`            | `false`   | Force update even if recent        |
| `--verify`           | `false`   | Verify rule integrity after update |
| `--rules-dir <path>` | `./rules` | Custom rules directory             |

#### Example

```bash
# Update signatures
sentinel update-signatures

# Force update
sentinel update-signatures --force

# Verify rules after update
sentinel update-signatures --verify
```

---

## Output Formats

### JSON (`report.json`)

```json
{
  "filePath": "/path/to/sample.exe",
  "fileName": "sample.exe",
  "fileSize": 245760,
  "hashes": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb924..."
  },
  "riskLevel": "high",
  "findings": [...],
  "mitreTechniques": [...],
  "behaviorHints": [...],
  "timestamp": "2026-01-17T12:00:00.000Z"
}
```

### Markdown (`report.md`)

Human-readable report with sections:

- Executive Summary
- File Metadata
- Analysis Findings
- MITRE ATT&CK Mapping
- Predicted Behaviors
- Recommendations

### STIX Bundle (`stix-bundle.json`)

STIX 2.1 format for threat intelligence sharing:

- Malware objects
- Indicators
- Attack patterns (MITRE ATT&CK)
- Relationships

---

## Exit Codes

| Code | Meaning             |
| ---- | ------------------- |
| `0`  | Success             |
| `1`  | General error       |
| `2`  | Invalid arguments   |
| `3`  | File not found      |
| `4`  | Analysis timeout    |
| `5`  | Dependency missing  |
| `6`  | Configuration error |

---

## Environment Variables

### Core Configuration

| Variable            | Default                  | Description                                        |
| ------------------- | ------------------------ | -------------------------------------------------- |
| `OLLAMA_BASE_URL`   | `http://localhost:11434` | Ollama API URL                                     |
| `OLLAMA_MODEL`      | `qwen3:8b`               | Default Ollama model                               |
| `MCP_SERVER_URL`    | `http://localhost:3000`  | MCP server URL                                     |
| `GHIDRA_SERVER_URL` | `http://localhost:13100` | Ghidra server URL                                  |
| `OUTPUT_DIR`        | `./outputs`              | Default output directory                           |
| `LOG_LEVEL`         | `info`                   | Logging level: `debug`, `info`, `warning`, `error` |
| `RULES_DIR`         | `./rules`                | YARA rules directory                               |

### Licensing

| Variable              | Default | Description                                    |
| --------------------- | ------- | ---------------------------------------------- |
| `SENTINEL_LICENSE`    | -       | License key (base64-encoded)                   |
| `SENTINEL_LICENSE_FILE` | `~/.sentinel/license.key` | Path to license key file |

### Cloud LLM Providers (Professional/Enterprise)

| Variable              | Default | Description                       |
| --------------------- | ------- | --------------------------------- |
| `OPENAI_API_KEY`      | -       | OpenAI API key                    |
| `ANTHROPIC_API_KEY`   | -       | Anthropic API key                 |

---

## Configuration File

Create `sentinel.config.json` in the project root or specify with `--config`:

```json
{
  "license": "your-license-key-here",
  "ollama": {
    "host": "localhost",
    "port": 11434,
    "model": "qwen3:8b"
  },
  "analysis": {
    "timeout": 300,
    "maxFileSize": 500000000,
    "enableYARA": true,
    "enableGhidra": true
  },
  "output": {
    "directory": "./outputs",
    "formats": ["json", "markdown", "stix"]
  },
  "signatures": {
    "autoUpdate": true,
    "updateIntervalHours": 24,
    "rulesDir": "./rules"
  }
}
```

---

## Examples

### Basic Analysis Workflow

```bash
# 1. Check installation
sentinel check

# 2. Quick triage
sentinel triage suspicious.exe

# 3. Full analysis if needed
sentinel analyze suspicious.exe

# 4. View report
cat outputs/suspicious_*/report.md
```

### Scripted Batch Analysis

```bash
#!/bin/bash

# Analyze all executables in a directory
for file in samples/*.exe; do
  echo "Analyzing: $file"
  sentinel analyze "$file" --quiet --format json
done
```

### Integration with jq

```bash
# Get risk level from JSON output
sentinel triage sample.exe --json | jq -r '.riskLevel'

# List all MITRE techniques
sentinel analyze sample.exe --format json --quiet
cat outputs/sample_*/report.json | jq '.mitreTechniques[].id'
```

### API Usage

```bash
# Start server
sentinel server --port 8080 &

# Submit analysis
curl -X POST http://localhost:8080/api/analyze \
  -F "file=@suspicious.exe"

# Check status
curl http://localhost:8080/api/analyses/abc123

# Get results
curl http://localhost:8080/api/analyses/abc123/report
```

### Docker Usage

```bash
# Run in Docker
docker run -v $(pwd)/samples:/data \
  ghcr.io/michaelai0/sentinel-orchestrator:latest \
  analyze /data/sample.exe
```

---

_For installation help, see [INSTALLATION.md](INSTALLATION.md). For workflow guides, see [USAGE-GUIDE.md](USAGE-GUIDE.md)._
