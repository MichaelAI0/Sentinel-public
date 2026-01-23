# SENTINEL Installation Guide

> **Version:** 1.0.0  
> **Last Updated:** January 22, 2026

Complete installation instructions for all supported platforms.

---

## Table of Contents

1. [Editions](#editions)
2. [System Requirements](#system-requirements)
3. [Quick Install](#quick-install)
4. [Platform-Specific Instructions](#platform-specific-instructions)
5. [Docker Installation](#docker-installation)
6. [Standalone Executable](#standalone-executable)
7. [License Activation](#license-activation)
8. [Development Setup](#development-setup)
9. [Post-Installation Verification](#post-installation-verification)
10. [Updating](#updating)
11. [Troubleshooting](#troubleshooting)

---

## Editions

SENTINEL uses an Open Core model with three editions:

| Edition          | Price   | Key Features                                      |
| ---------------- | ------- | ------------------------------------------------- |
| **Community**    | Free    | Core analysis, local LLM (Ollama), heuristic triage |
| **Professional** | $49/mo  | AI-powered analysis, cloud LLMs, email support    |
| **Enterprise**   | $299/mo | Team deployment, SSO, priority support            |

The Community Edition is fully functional for binary analysis. Premium editions add AI-powered threat intelligence. Premium features are planned for future release. Contact the maintainer for inquiries.

---

## System Requirements

### Minimum Requirements

| Component | Minimum               | Recommended           |
| --------- | --------------------- | --------------------- |
| CPU       | 4 cores               | 8+ cores              |
| RAM       | 8 GB                  | 16+ GB                |
| Storage   | 10 GB                 | 50+ GB (for samples)  |
| OS        | Linux, macOS, Windows | Linux (Ubuntu 22.04+) |

### Required Dependencies

| Dependency | Version | Required | Purpose                      |
| ---------- | ------- | -------- | ---------------------------- |
| Bun        | 1.3+    | Yes      | JavaScript runtime           |
| Docker     | 20+     | Yes      | Container runtime for Ghidra |
| Ollama     | 0.1+    | Yes      | LLM inference                |
| Git        | 2.0+    | Yes      | Version control              |

### Optional Dependencies

| Dependency | Purpose                   |
| ---------- | ------------------------- |
| YARA-X     | Signature-based detection |
| UPX        | Packed binary unpacking   |
| radare2    | Disassembly fallback      |

---

## Quick Install

### Using Pre-built Executable (Recommended)

```bash
# Linux x64
curl -L https://github.com/MichaelAI0/Sentinel/releases/latest/download/sentinel-linux-x64.tar.gz | tar -xz
chmod +x sentinel
./sentinel --version

# macOS x64
curl -L https://github.com/MichaelAI0/Sentinel/releases/latest/download/sentinel-macos-x64.tar.gz | tar -xz
chmod +x sentinel
./sentinel --version

# macOS ARM64 (Apple Silicon)
curl -L https://github.com/MichaelAI0/Sentinel/releases/latest/download/sentinel-macos-arm64.tar.gz | tar -xz
chmod +x sentinel
./sentinel --version

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/MichaelAI0/Sentinel/releases/latest/download/sentinel-windows-x64.exe.zip -OutFile sentinel.zip
Expand-Archive sentinel.zip -DestinationPath .
.\sentinel.exe --version
```

### Using npm/bun (Requires Bun)

```bash
# Install Bun first (if not installed)
curl -fsSL https://bun.sh/install | bash

# Clone and install
git clone https://github.com/MichaelAI0/Sentinel.git
cd Sentinel
bun install

# Run SENTINEL
bun run sentinel --version
```

---

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y curl git docker.io

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Install Bun
curl -fsSL https://bun.sh/install | bash
source ~/.bashrc

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b
ollama serve &

# Clone and install SENTINEL
git clone https://github.com/MichaelAI0/Sentinel.git
cd Sentinel
bun install

# Verify installation
bun run sentinel check
```

### Linux (Fedora/RHEL)

```bash
# Install system dependencies
sudo dnf install -y curl git podman-docker

# Install Bun
curl -fsSL https://bun.sh/install | bash
source ~/.bashrc

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b
ollama serve &

# Clone and install SENTINEL
git clone https://github.com/MichaelAI0/Sentinel.git
cd Sentinel
bun install

# Verify installation
bun run sentinel check
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install git
brew install --cask docker
brew install oven-sh/bun/bun

# Start Docker Desktop
open -a Docker

# Install Ollama
brew install ollama
ollama pull qwen3:8b
ollama serve &

# Clone and install SENTINEL
git clone https://github.com/MichaelAI0/Sentinel.git
cd Sentinel
bun install

# Verify installation
bun run sentinel check
```

### Windows

1. **Install WSL2 (recommended):**

   ```powershell
   wsl --install -d Ubuntu
   ```

   Then follow Linux instructions inside WSL2.

2. **Native Windows:**
   - Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
   - Install [Bun](https://bun.sh/docs/installation)
   - Install [Git for Windows](https://git-scm.com/download/win)
   - Install [Ollama](https://ollama.com/download)

   ```powershell
   # Clone and install
   git clone https://github.com/MichaelAI0/Sentinel.git
   cd Sentinel
   bun install

   # Start Ollama
   ollama pull qwen3:8b
   ollama serve

   # Verify installation (in new terminal)
   bun run sentinel check
   ```

---

## Docker Installation

Run SENTINEL entirely in Docker containers:

```bash
# Clone repository
git clone https://github.com/MichaelAI0/Sentinel.git
cd Sentinel

# Start all services
docker compose up -d

# Run analysis
docker exec sentinel-orchestrator sentinel analyze /data/sample.exe
```

### Docker Compose Services

| Service      | Port  | Description            |
| ------------ | ----- | ---------------------- |
| mcp-server   | 3000  | Binary analysis tools  |
| orchestrator | 8080  | Analysis orchestration |
| ghidra       | 13100 | Decompilation service  |

---

## Standalone Executable

Download pre-built executables from [GitHub Releases](https://github.com/MichaelAI0/Sentinel/releases).

### Build Your Own

```bash
# Clone repository
git clone https://github.com/MichaelAI0/Sentinel.git
cd Sentinel
bun install

# Build for current platform
bun run build:exec

# Build for specific platform
bun run build:exec:linux
bun run build:exec:macos
bun run build:exec:macos-arm
bun run build:exec:windows

# Build for all platforms
bun run build:exec:all
```

Executables are created in the `dist/` directory.

---

## License Activation

### Community Edition (Default)

No license required. SENTINEL runs in Community mode automatically.

### Professional/Enterprise Edition

After purchasing a license, activate it using one of these methods:

#### Method 1: Environment Variable (Recommended)

```bash
export SENTINEL_LICENSE="your-license-key-here"
```

#### Method 2: License File

```bash
echo "your-license-key" > ~/.sentinel/license.key
```

#### Method 3: Configuration File

Add to `sentinel.config.json`:

```json
{
  "license": "your-license-key"
}
```

### Verify License

```bash
sentinel check
# Output: SENTINEL Professional Edition
```

Premium features are planned for future release. Contact the maintainer for inquiries.

---

## Development Setup

For contributors and developers:

```bash
# Clone repository
git clone https://github.com/MichaelAI0/Sentinel.git
cd Sentinel

# Install dependencies
bun install

# Start development mode
bun run dev

# Run tests
bun test

# Run linting
bun run lint

# Run type checking
bun run typecheck

# Format code
bun run format
```

### Project Structure

```
sentinel/
├── packages/
│   ├── orchestrator/   # Main analysis engine
│   ├── mcp-server/     # Binary analysis tools
│   └── shared/         # Shared types and schemas
├── docker/             # Docker configurations
├── scripts/            # Build and utility scripts
└── docs/               # Documentation
```

---

## Post-Installation Verification

Run the built-in check command to verify all components:

```bash
sentinel check
```

Expected output:

```
╔═══════════════════════════════════════════════════════════╗
║                  SENTINEL Health Check                     ║
╚═══════════════════════════════════════════════════════════╝

✅ Bun runtime: v1.3.4
✅ Ollama: Connected (qwen3:8b available)
✅ Docker: Running
✅ Ghidra container: Ready
✅ MCP Server: Healthy
✅ YARA-X: Installed (optional)
✅ UPX: Installed (optional)

All checks passed! SENTINEL is ready.
```

### Test with Sample File

```bash
# Create a test file
echo "MZ" > test.exe

# Run quick triage
sentinel triage test.exe

# Run full analysis
sentinel analyze test.exe
```

---

## Updating

### Update Executable

```bash
# Download latest release
curl -L https://github.com/MichaelAI0/Sentinel/releases/latest/download/sentinel-linux-x64.tar.gz | tar -xz
chmod +x sentinel
```

### Update from Source

```bash
cd Sentinel
git pull origin main
bun install
```

### Update Signatures

SENTINEL automatically checks for signature updates every 24 hours. To force an update:

```bash
sentinel update-signatures
```

Or disable auto-updates:

```bash
sentinel analyze sample.exe --no-update
```

---

## Troubleshooting

### Common Issues

#### "Cannot connect to Ollama"

```bash
# Check if Ollama is running
ollama list

# Start Ollama
ollama serve

# Check port
curl http://localhost:11434/api/version
```

#### "Docker permission denied"

```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or use sudo
sudo docker compose up
```

#### "Ghidra container not found"

```bash
# Build Ghidra container
docker compose build ghidra

# Or pull from registry
docker pull ghcr.io/michaelai0/sentinel-ghidra:latest
```

#### "Bun command not found"

```bash
# Reinstall Bun
curl -fsSL https://bun.sh/install | bash

# Add to PATH
export PATH="$HOME/.bun/bin:$PATH"
```

### Getting Help

- **Issues:** [GitHub Issues](https://github.com/MichaelAI0/Sentinel/issues)
- **Discussions:** [GitHub Discussions](https://github.com/MichaelAI0/Sentinel/discussions)
- **Documentation:** [Docs](https://github.com/MichaelAI0/Sentinel/tree/main/docs)

---

_For advanced usage, see the [Usage Guide](USAGE-GUIDE.md) and [CLI Reference](CLI-REFERENCE.md)._
