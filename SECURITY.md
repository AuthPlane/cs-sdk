# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.x     | :white_check_mark: |

Only the latest minor release of each NuGet package in this repository (`Authplane.Sdk`, `Authplane.Mcp`) receives security patches.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub Private Vulnerability Reporting](https://github.com/AuthPlane/cs-sdk/security/advisories/new) to submit your report. This ensures:

- Your report is confidential and only visible to maintainers
- We can coordinate a fix before public disclosure
- You receive credit for responsible disclosure

### What to Include

- Which package is affected (`Authplane.Sdk`, `Authplane.Mcp`) and installed version
- Description of the vulnerability
- Steps to reproduce (or proof of concept)
- Impact assessment (what an attacker could do)
- Relevant environment details (.NET version, framework, `authserver` version if applicable)

### Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix timeline:** depends on severity (critical: < 7 days, high: < 14 days)

### What We Consider In-Scope

Vulnerabilities in the SDK or its adapters that affect correctness of authentication or authorization decisions, including:

- JWT verification bypass (signature, issuer, audience, expiry, `nbf`, algorithm confusion)
- Algorithm confusion (HMAC, `none`, weak curves)
- DPoP proof verification bypass (binding, replay, `htm` / `htu` / `ath`)
- SSRF in outbound HTTP (metadata discovery, JWKS, introspection, token exchange, revocation)
- Information leaks via error responses, logs, or telemetry
- Cache poisoning of JWKS or AS metadata
- Misconfigured cryptography defaults (e.g. accepting unsafe algorithms by default)

### What We Consider Out-of-Scope

- Issues in upstream dependencies (`System.IdentityModel.Tokens.Jwt`, `Microsoft.IdentityModel.Tokens`) — please report those to their respective maintainers
- Issues that require host-system compromise to exploit
- Theoretical attacks without a working proof of concept

### Coordinated Disclosure

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):

1. Reporter sends vulnerability details privately
2. Maintainers acknowledge and start working on a fix
3. A timeline for public disclosure is agreed (typically 30–90 days from acknowledgment)
4. Fix is released; CVE is requested when applicable; advisory is published

### Recognition

Reporters are credited in the release notes and the GitHub Security Advisory unless they request anonymity.
