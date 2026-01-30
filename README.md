# Sentinel - AI-Powered Binary Analysis

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![Bun](https://img.shields.io/badge/Bun-1.0+-f472b6.svg)](https://bun.sh/)

> **Community Edition** - Open source binary analysis framework with heuristic-based threat detection

Sentinel is an AI-powered binary analysis framework that combines Ghidra reverse engineering with LLM intelligence to provide comprehensive malware analysis and threat detection.

## Features

### Community Edition (This Repository)

| Feature                                      | Status |
| -------------------------------------------- | ------ |
| **Static Binary Analysis**                   | Full   |
| **Ghidra Integration**                       | Full   |
| **Hash Calculation** (MD5, SHA256, etc.)     | Full   |
| **String Extraction & Analysis**             | Full   |
| **Import/Export Analysis**                   | Full   |
| **Entropy Calculation**                      | Full   |
| **Local LLM Support** (Ollama, llama-server) | Full   |
| **Heuristic Threat Detection**               | Full   |
| **Text Reports**                             | Full   |
| **Docker Deployment**                        | Full   |

### Premium Features (Coming Soon)

Premium editions with enhanced AI capabilities are planned for future release:

- AI-Powered Deep Analysis with advanced prompts
- MITRE ATT&CK Mapping
- Malware Family Classification
- IOC Extraction & Enrichment
- Cloud LLM Support (OpenAI, Anthropic)
- PDF/HTML Reports
- STIX/TAXII Export

_Contact the maintainer for early access or enterprise inquiries._

## Quick Start

### Prerequisites

- [Bun](https://bun.sh/) 1.0+
- Docker & Docker Compose
- Ghidra 11.0+ (or use Docker image)

### Installation

```bash
# Clone the repository
git clone https://github.com/MichaelAI0/Sentinel-public.git
cd Sentinel-public

# Install dependencies
bun install

# Build packages
bun run build

# Start services (Docker)
docker-compose up -d
```

### Basic Usage

```bash
# Analyze a binary
bun run sentinel analyze ./path/to/binary.exe

# Run with local Ollama
bun run sentinel analyze ./binary.exe --provider ollama --model mistral

# Output to JSON
bun run sentinel analyze ./binary.exe --output json > report.json
```

## Project Structure

```
sentinel/
├── packages/
│   ├── mcp-server/      # Model Context Protocol server
│   ├── orchestrator/    # Analysis orchestration engine
│   └── shared/          # Shared types and utilities
├── docker/
│   ├── ghidra/          # Ghidra headless Docker image
│   └── unipacker/       # Unpacker service
├── docs/                # Documentation
└── scripts/             # Build and deployment scripts
```

## Configuration

Create a `.sentinel/config.json` file in your home directory:

```json
{
  "llm": {
    "provider": "ollama",
    "model": "mistral",
    "baseUrl": "http://localhost:11434"
  },
  "analysis": {
    "timeout": 300,
    "maxFileSize": "100MB"
  }
}
```

## Docker Usage

```bash
# Start all services
docker-compose up -d

# Analyze a binary via MCP
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"path": "/samples/malware.exe"}'
```

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Guide](docs/USAGE-GUIDE.md)
- [API Reference](docs/API-REFERENCE.md)
- [CLI Reference](docs/CLI-REFERENCE.md)
- [Contributing Guide](CONTRIBUTING.md)

## Development

```bash
# Run in development mode
bun run dev

# Run tests
bun test

# Type checking
bun run typecheck

# Linting
bun run lint
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
