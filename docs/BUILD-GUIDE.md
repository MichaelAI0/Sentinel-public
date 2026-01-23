# SENTINEL Build Guide & Technical Reference

> **Purpose**: Single source of truth for building Project SENTINEL
> **Last Updated**: January 17, 2026

---

## 🎯 Current Status

### Phase Progress

| Phase | Name                            | Status      | Notes                                         |
| ----- | ------------------------------- | ----------- | --------------------------------------------- |
| 1     | Foundation & Infrastructure     | ✅ Complete | Monorepo, configs, shared package             |
| 2     | MCP Server - Binary Utils       | ✅ Complete | 7 tools (hashes, file-type, PE, ELF, Ghidra)  |
| 3     | MCP Server - Ghidra Integration | ✅ Complete | Custom GraalJS extension, 4 Ghidra tools      |
| 4     | MCP Server - Report Tools       | ✅ Complete | Reports generated in orchestrator agents      |
| 5     | Orchestrator - Agent Framework  | ✅ Complete | LangGraph.js + Ollama + 3 agents              |
| 6     | CLI Interface                   | ✅ Complete | Bun native CLI (analyze, triage, server)      |
| 7     | Docker Integration              | 🟡 Partial  | MCP+Ghidra containerized, orchestrator native |

---

## 🔧 Technology Stack (Verified Latest)

### Core Runtime

| Technology     | Version | Purpose                                     |
| -------------- | ------- | ------------------------------------------- |
| **Bun**        | 1.3.6   | Runtime & package manager                   |
| **TypeScript** | 5.9.3   | Type-safe development                       |
| **Biome**      | 2.3.11  | Linter/formatter (replaces ESLint+Prettier) |

### Framework Dependencies

| Package                     | Version | Purpose                                      |
| --------------------------- | ------- | -------------------------------------------- |
| `zod`                       | 4.3.5   | Schema validation (breaking changes from v3) |
| `@modelcontextprotocol/sdk` | 1.25.2  | MCP server implementation                    |
| `@logtape/logtape`          | 2.0.0   | Structured logging                           |
| `lru-cache`                 | 11.2.4  | Result caching                               |
| `langgraph`                 | 1.1.0   | Agent workflow orchestration                 |
| `ollama`                    | 0.6.3   | LLM client                                   |

### Ghidra Integration

| Package       | Version | Purpose                                        |
| ------------- | ------- | ---------------------------------------------- |
| **Ghidra**    | 12.0.1  | Binary analysis engine (Jan 14, 2026 release)  |
| **GraalJS**   | 24.1.1  | JavaScript engine embedded in custom extension |
| `sentinel-js` | 1.0.0   | Custom Ghidra extension for JS script support  |

> **Note**: We replaced Ghidra.js (V8-based) with a custom GraalJS extension for better
> stability and direct Ghidra API access. See [GHIDRA-INTEGRATION-PLAN.md](./GHIDRA-INTEGRATION-PLAN.md).

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     ORCHESTRATOR (Bun/TS) - Port 8080           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                      │
│  │ Triage   │  │ Analyzer │  │ Report   │  LangGraph.js       │
│  │  Agent   │→ │  Agent   │→ │  Agent   │  Workflow Engine    │
│  └──────────┘  └──────────┘  └──────────┘                      │
│       ✅            ✅            ✅       All agents working   │
│                      │                                          │
│               Ollama Client (Qwen 2.5)                         │
└────────────────────────┬────────────────────────────────────────┘
                         │ HTTP API (localhost:3000)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MCP SERVER (Docker) - Port 3000              │
│                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐                      │
│  │  Binary Utils   │  │  Ghidra Tools   │                      │
│  │  (4 tools) ✅   │  │  (3 tools) ✅   │                      │
│  │  - hashes       │  │  - analyze      │                      │
│  │  - file-type    │  │  - functions    │                      │
│  │  - pe-headers   │  │  - strings      │                      │
│  │  - elf-headers  │  │                 │                      │
│  └─────────────────┘  └─────────────────┘                      │
│           │                    │                               │
│           │           ┌────────┴────────┐                      │
│           │           ▼                 │                      │
│           │   Docker Exec Bridge        │                      │
│           │   (ghidra-bridge.ts)        │                      │
└───────────┼─────────────────────────────┼──────────────────────┘
            │                             │
            ▼                             ▼
┌───────────────────────┐    ┌────────────────────────────────────┐
│   Native Analysis     │    │     GHIDRA CONTAINER               │
│   (TypeScript)        │    │                                    │
│   - Hashes            │    │  Ghidra 12.0.1 + GraalJS 24.1.1   │
│   - PE/ELF parsing    │    │                                    │
│   - String extraction │    │  ┌──────────────────────────────┐ │
│   - Entropy calc      │    │  │  sentinel-js Extension       │ │
└───────────────────────┘    │  │  (Custom GraalJS-based)      │ │
                             │  │  - analyze.js                │ │
                             │  │  - extract-functions.js      │ │
                             │  │  - extract-strings.js        │ │
                             │  └──────────────────────────────┘ │
                             │                                    │
                             │  analyzeHeadless -postScript      │
                             └────────────────────────────────────┘
```

---

## 📦 GraalJS Extension (sentinel-js)

> **Note**: We replaced the Ghidra.js (V8-based) approach with a custom GraalJS extension
> for better stability and Ghidra 12.0.1 compatibility.

### What Our Extension Provides

**sentinel-js** is a custom Ghidra Extension that:

1. **Embeds GraalJS 24.1.1** - Modern JavaScript engine from GraalVM
2. **Registers `.js` scripts** - Ghidra's Script Manager recognizes JavaScript files
3. **Exposes Ghidra Java API** - Full access to Ghidra's analysis capabilities
4. **Handles Script Discovery** - ClassSearcher properly finds our ScriptProvider

### Extension Structure

```
docker/ghidra/extension/
├── Module.manifest               # Extension metadata
├── build.gradle                  # Build config (archiveBaseName = 'sentinel-js')
├── extension.properties          # Extension properties
├── lib/                          # GraalJS JARs (17 total)
│   ├── graal-js-24.1.1.jar
│   ├── graal-sdk-24.1.1.jar
│   └── ... (other GraalVM components)
└── src/main/java/.../
    ├── SentinelJSPlugin.java      # Extension plugin registration
    ├── SentinelJSScriptProvider.java  # .js script registration
    └── SentinelJSScript.java      # GraalJS script runner
```

### Key Implementation Details

**JAR Naming**: Must start with module name (`sentinel-js-1.0.0.jar`)
for Ghidra's `ClassSearcher.isModuleDependencyJar()` to recognize it.

**Script Location**: Place `.js` scripts in:

```
/opt/ghidra/Ghidra/Features/sentinel-js/ghidra_scripts/
```

### Ghidra Globals Available in Scripts

```javascript
// Ghidra-provided globals (bound by GraalJS)
currentProgram; // The program being analyzed
currentAddress; // Current cursor address
monitor; // Task monitor for progress/cancellation
state; // Script state

// print() outputs JSON - we parse in ghidra-bridge.ts
print(JSON.stringify(result));
```

### Script Files

```
/opt/ghidra/Ghidra/Features/sentinel-js/ghidra_scripts/
├── analyze.js              # Full binary analysis (imports, exports, sections)
├── extract-functions.js    # Function extraction with decompilation
└── extract-strings.js      # String extraction
```

### Headless Execution Command

```bash
/opt/ghidra/support/analyzeHeadless \
  /tmp/sentinel temp_project \       # Project directory
  -import /binaries/sample.exe \     # Binary to analyze
  -postScript analyze.js \           # Script to run after analysis
  -deleteProject                     # Clean up project after
```

---

## 📂 Project Structure

```
Sentinel/
├── 01-project-sentinel-overview.md   # Vision & scope
├── 02-system-architecture.md         # Architecture design
├── 03-agent-system-design.md         # Agent specifications
├── 04-mcp-server-specifications.md   # Tool specifications
├── 05-tool-service-catalog.md        # Complete catalog
├── BUILD-GUIDE.md                    # This file
├── IMPLEMENTATION.md                 # Session log
│
├── package.json                      # Root monorepo config
├── tsconfig.json                     # Root TypeScript config
├── biome.json                        # Biome 2.x config
├── docker-compose.yml                # Container orchestration
├── .env                              # Environment variables
│
├── binaries/                         # Input samples (gitignored)
├── outputs/                          # Analysis results (gitignored)
├── logs/                             # Log files (gitignored)
├── scripts/                          # Dev helper scripts
│   └── start-dev.sh                  # Development startup
│
├── packages/
│   ├── shared/                       # ✅ Complete
│   │   └── src/
│   │       ├── index.ts              # Central exports
│   │       ├── constants.ts          # Enums, constants
│   │       ├── schemas/
│   │       │   ├── analysis.ts       # Analysis schemas
│   │       │   ├── tools.ts          # Tool I/O schemas
│   │       │   └── agents.ts         # Agent schemas
│   │       └── types/
│   │           └── index.ts          # TypeScript types
│   │
│   ├── mcp-server/                   # ✅ Complete
│   │   └── src/
│   │       ├── index.ts              # MCP server entry
│   │       ├── types.ts              # Local types
│   │       ├── tools/
│   │       │   ├── index.ts          # Tool exports
│   │       │   ├── calculate-hashes.ts      ✅
│   │       │   ├── detect-file-type.ts      ✅
│   │       │   ├── extract-pe-headers.ts    ✅
│   │       │   ├── extract-elf-headers.ts   ✅
│   │       │   ├── ghidra-analyze.ts        ✅
│   │       │   ├── ghidra-functions.ts      ✅
│   │       │   └── ghidra-strings.ts        ✅
│   │       └── utils/
│   │           ├── logger.ts         # LogTape config
│   │           └── ghidra-bridge.ts  # Docker exec wrapper
│   │
│   └── orchestrator/                 # ✅ Complete
│       └── src/
│           ├── index.ts              # HTTP server entry point
│           ├── types.ts              # Analysis state types
│           ├── agents/
│           │   ├── triage-agent.ts   # ✅ Initial triage
│           │   ├── analyzer-agent.ts # ✅ Deep analysis
│           │   └── report-agent.ts   # ✅ Report generation
│           ├── workflow/
│           │   └── index.ts          # LangGraph workflow
│           └── utils/
│               ├── logger.ts         # LogTape config
│               ├── mcp-bridge.ts     # MCP HTTP client
│               └── ollama-client.ts  # Ollama LLM client
│
└── docker/
    └── ghidra/
        ├── Dockerfile                # Ghidra 12.0.1 + GraalJS
        ├── extension/                # Custom sentinel-js extension
        │   ├── Module.manifest
        │   ├── build.gradle
        │   ├── lib/                  # GraalJS JARs
        │   └── src/main/java/...     # Java source
        └── ghidra_scripts/
            ├── analyze.js            # Binary analysis
            ├── extract-functions.js  # Function extraction
            └── extract-strings.js    # String extraction
```

---

## 🔨 Build Commands

### Initial Setup

```bash
# Install dependencies
bun install

# Verify TypeScript
bunx tsc --build --force packages/

# Verify Linting
bunx @biomejs/biome check packages/
```

### Start Services

```bash
# Start Docker services (MCP Server + Ghidra)
DOCKER_GID=$(getent group docker | cut -d: -f3) docker compose up -d

# Start Orchestrator (native, for development)
cd packages/orchestrator && bun run src/index.ts

# Or use dev script
./scripts/start-dev.sh
```

### Run Tests

```bash
# Unit tests (when implemented)
bun test

# Type check only
bunx tsc --noEmit
```

### Docker

```bash
# Build all containers
docker compose build

# Start services
docker compose up -d

# Run analysis
docker compose exec mcp-server bun run analyze /binaries/sample.exe
```

---

## 🎯 Next Steps (Priority Order)

### Phase 7: Docker Full Integration

1. **Containerize Orchestrator**
   - [ ] Dockerfile for orchestrator
   - [ ] Update docker-compose.yml
   - [ ] End-to-end Docker testing

2. **Production Hardening**
   - [ ] Health checks refinement
   - [ ] Graceful shutdown
   - [ ] Resource limits
   - [ ] Logging to files

### Testing & Documentation

3. **Add Tests**
   - [ ] Unit tests for tools
   - [ ] Integration tests for agents
   - [ ] End-to-end workflow tests
   - [ ] More malware sample testing

4. **Enhanced Features**
   - [ ] Batch analysis mode
   - [ ] Config file support
   - [ ] Web UI (optional)

---

## ✅ Completed Milestones

### Phase 1-6 Complete (January 16-17, 2026)

- ✅ Monorepo setup with Bun + TypeScript + Biome
- ✅ Shared package with Zod 4.x schemas
- ✅ MCP Server with 7 tools (4 binary utils + 3 Ghidra)
- ✅ Custom GraalJS Ghidra extension (replaced Ghidra.js)
- ✅ LangGraph.js agent workflow
- ✅ 3 agents: Triage, Analyzer, Report
- ✅ CLI interface: `sentinel analyze`, `sentinel triage`, `sentinel server`
- ✅ Ollama integration (Qwen 2.5:7b-instruct)
- ✅ Report generation (Markdown, JSON, STIX)
- ✅ Full end-to-end pipeline working

---

## ⚠️ Known Issues

1. **Orchestrator Not Containerized**
   - Running native for development
   - Needs Dockerfile for production

2. **Docker Socket Access**
   - MCP container needs docker socket access to spawn Ghidra
   - Set `DOCKER_GID` in `.env` to match host docker group

---

## 📚 References

- **Ghidra API Docs**: https://ghidra.re/ghidra_docs/api/
- **GraalJS**: https://www.graalvm.org/latest/reference-manual/js/
- **MCP Specification**: https://modelcontextprotocol.io/
- **LangGraph.js**: https://langchain-ai.github.io/langgraphjs/
- **Zod v4**: https://zod.dev/ (note: breaking changes from v3)
- **Ollama**: https://ollama.ai/

---

_Last updated: January 17, 2026_
