# Contributing to SENTINEL

Thank you for your interest in contributing to SENTINEL! We welcome contributions from the community.

## Open Core Model

SENTINEL uses an **Open Core** licensing model:

- **Open Source (Apache 2.0)**: `packages/shared/`, `packages/mcp-server/`, `docker/ghidra/`
- **Commercial License**: AI agents, prompts, cloud LLM providers

Contributions to open source components are licensed under Apache 2.0. By submitting code, you agree that your contributions are licensed under the same license as the component you're contributing to.

## Contributor License Agreement

For contributions to commercial components, we require a Contributor License Agreement (CLA). This ensures we can continue to offer both open source and commercial editions. You'll be prompted to sign the CLA when you submit your first PR to a commercial component.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Testing](#testing)

## Code of Conduct

All contributors are expected to be respectful, inclusive, and professional in all interactions.

## Getting Started

### Prerequisites

- [Bun](https://bun.sh) 1.3 or later
- [Docker](https://www.docker.com/) with Docker Compose
- Git

### Fork and Clone

```bash
git clone https://github.com/YOUR_USERNAME/Sentinel.git
cd Sentinel
git remote add upstream https://github.com/MichaelAI0/Sentinel.git
```

## Development Setup

```bash
bun install
bun run check
bun test
bun run typecheck
```

Start development services:

```bash
docker compose up ghidra mcp-server -d
```

## Making Changes

### Branch Naming

Create a feature branch from `development`:

````bash
git checkout development
git pull upstream development
git checkout -b feature/your-feature-name
```text
feature/your-feature-name
````

Prefixes: `feature/`, `fix/`, `docs/`, `refactor/`, `test/`

### Commit Messages

Use conventional commit format:

```text
type(scope): brief description

Closes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:

- `feat(unpacker): add MPRESS native unpacking support`
- `fix(mcp-bridge): handle timeout errors gracefully`
- `docs(readme): update installation instructions`

## Submitting Changes

### Pull Request Process

1. Ensure all tests pass:

```bash
bun test
bun run typecheck
bun run check
```

1. Update documentation if needed

1. Push your branch:

```bash
git push origin feature/your-feature-name
```

1. Create a Pull Request against the `development` branch

1. Fill out the PR template completely

### PR Checklist

- [ ] Tests added/updated for changes
- [ ] Documentation updated
- [ ] All tests passing
- [ ] No linting errors
- [ ] Commits follow conventional format
- [ ] PR description explains the changes

## Code Style

We use [Biome](https://biomejs.dev/) for linting and formatting.

### Auto-fix Issues

```bash
bun run check  # Auto-fix and format
```

### Key Style Guidelines

- Use TypeScript strict mode
- Prefer `const` over `let`
- Use explicit return types on exported functions
- Document public APIs with JSDoc comments
- Keep functions focused and under 50 lines when possible
- Use meaningful variable names

### File Organization

```text
packages/
├── shared/           # Shared types, schemas, utilities
├── mcp-server/       # MCP tool implementations
└── orchestrator/     # Agent logic, LLM integration, CLI
```

## Testing

### Running Tests

```bash
# Run all tests
bun test

# Run specific test file
bun test packages/orchestrator/src/__tests__/unpacker.test.ts

# Run with coverage
bun test --coverage
```

### Writing Tests

- Place tests in `__tests__/` directories or alongside source files with `.test.ts` suffix
- Use descriptive test names
- Test edge cases and error conditions
- Mock external services (LLM, MCP tools) in unit tests

Example:

```typescript
import { describe, expect, test } from "bun:test";
import { myFunction } from "./my-module";

describe("myFunction", () => {
  test("handles valid input", () => {
    const result = myFunction("valid");
    expect(result).toBe("expected");
  });

  test("throws on invalid input", () => {
    expect(() => myFunction("")).toThrow("Invalid input");
  });
});
```

## Documentation

### Where to Document

- **Code comments**: JSDoc for public APIs
- **README.md**: Project overview, quick start
- **docs/**: Detailed guides and references
- **Inline comments**: Complex logic explanation

### Documentation Style

- Use clear, concise language
- Include code examples
- Keep documentation up-to-date with code changes
- Use Markdown formatting consistently

## Questions?

For questions, open a [GitHub Discussion](https://github.com/MichaelAI0/Sentinel/discussions) or check existing issues before creating new ones.
