# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please report it responsibly.

### Reporting Methods

1. **GitHub Security Advisories** (Preferred)
   - Navigate to the [Security tab](../../security/advisories)
   - Click "Report a vulnerability"
   - Complete the vulnerability report form

2. **Email**
   - Contact the repository owner directly
   - Include "[SECURITY]" in the subject line

### Report Contents

Include the following information:

- Vulnerability type and classification
- Affected source files and line numbers
- Steps to reproduce the issue
- Proof-of-concept code (if applicable)
- Potential impact assessment

### Response Timeline

| Phase                     | Timeline        |
| ------------------------- | --------------- |
| Initial acknowledgment    | 48 hours        |
| Status update             | 5 business days |
| Critical issue resolution | 30 days         |

## Security Architecture

### Input Validation

- Zod schema validation at all input boundaries
- Path traversal prevention via `PathSandbox` class
- File size limits to prevent denial of service
- Null byte injection blocking

### Container Isolation

- Binary analysis runs in isolated Docker containers
- Ghidra headless analysis is fully containerized
- File system access restricted to designated directories
- Read-only mounts for binary files

### Dependency Management

- Regular dependency updates via Dependabot
- Security vulnerability scanning in CI/CD pipeline
- Minimal production dependency footprint

### Code Quality

- TypeScript strict mode enabled
- Biome linting with security-focused rules
- Mandatory CI checks on all pull requests

## Security Guidelines for Users

1. **Isolated Environment**: Run SENTINEL in an isolated environment when analyzing untrusted binaries
2. **Regular Updates**: Keep SENTINEL updated to receive security patches
3. **Network Isolation**: When running the server, ensure proper network segmentation
4. **Output Review**: Review analysis outputs before taking action on findings

## Acknowledgments

Security researchers who have responsibly disclosed vulnerabilities will be acknowledged here.

Thank you for helping keep SENTINEL and its users safe!
