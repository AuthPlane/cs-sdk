# Contributing to the Authplane .NET SDK

Thanks for your interest in contributing. This repository is a single-solution monorepo publishing two NuGet packages:

| NuGet package | Project | Directory |
|---|---|---|
| `Authplane.Sdk` | core SDK | `src/Authplane/` |
| `Authplane.Mcp` | MCP adapter | `src/Authplane.Mcp/` |

`Authplane.Mcp` ProjectReferences `Authplane.Sdk`. A single tagged release publishes both.

## Reporting Issues

- **Bugs:** open a [bug report](https://github.com/AuthPlane/cs-sdk/issues/new?template=bug-report.md). Include package name, version, .NET version, and a minimal reproduction.
- **MCP client compatibility:** open an issue with the MCP client name and version.
- **Feature requests:** open a [feature request](https://github.com/AuthPlane/cs-sdk/issues/new?template=feature-request.md). Describe the problem first, then the proposed solution.
- **Security vulnerabilities:** do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Development Setup

### Prerequisites

- .NET 10 SDK (we pin via `global.json`; install matching SDK with [winget](https://learn.microsoft.com/en-us/dotnet/core/install/windows), [apt](https://learn.microsoft.com/en-us/dotnet/core/install/linux), or [the dotnet-install script](https://learn.microsoft.com/en-us/dotnet/core/install/linux-scripted-manual#scripted-install))
- .NET 8 runtime (including ASP.NET Core) — the test projects multi-target
  `net8.0;net10.0`, so `dotnet test` executes the `net8.0` leg and fails with
  `The framework 'Microsoft.NETCore.App', version '8.0.0' was not found`
  without it
- `git`

### Clone and build

```sh
git clone https://github.com/AuthPlane/cs-sdk.git
cd cs-sdk
dotnet restore Authplane.slnx
dotnet build Authplane.slnx --configuration Release
```

### Run tests

```sh
# All tests in the solution.
dotnet test Authplane.slnx --configuration Release

# Just the core SDK tests.
dotnet test tests/Authplane.Tests/Authplane.Tests.csproj

# Just the MCP adapter tests.
dotnet test tests/Authplane.Mcp.Tests/Authplane.Mcp.Tests.csproj
```

### Coverage

```sh
dotnet test Authplane.slnx \
  --configuration Release \
  --collect:"XPlat Code Coverage" \
  --settings coverlet.runsettings
```

The coverage scope is configured in `coverlet.runsettings` to exclude `tests/`, `demo/`, and the conformance shared project. CI fails the build if line coverage drops below 80 % or branch coverage drops below 70 %.

### Format and lint

```sh
# Verify formatting (CI runs the same command).
dotnet format Authplane.slnx --verify-no-changes
```

If the verifier finds drift, run `dotnet format Authplane.slnx` (no flag) and commit the result.

### Conformance suite

The conformance tests load `oauth-sdk-conformance-catalog.yaml` from the shared `AuthPlane/conformance` repository. Two ways to run locally:

```sh
# 1. Set CONFORMANCE_CATALOG_PATH to a local checkout.
git clone https://github.com/AuthPlane/conformance.git ../conformance
CONFORMANCE_CATALOG_PATH=$(pwd)/../conformance/oauth-sdk-conformance-catalog.yaml \
  dotnet test Authplane.slnx --configuration Release

# 2. Or place a copy at ./conformance/oauth-sdk-conformance-catalog.yaml; the test
#    runner walks ancestor directories looking for that file.
```

Add a new test to the conformance suite by:

1. Writing the assertion in the appropriate `tests/*` file.
2. Decorating the method with `[Conformance("rfc-xxxx-...")]`.
3. Running the suite — `ConformanceCatalogAlignmentTests.EveryCatalogCase_HasConformanceMarker` will turn green when every catalog case has a marker.

### Demo (E2E smoke)

```sh
./scripts/manual-e2e-setup.sh   # requires authserver running locally
./scripts/manual-e2e-smoke.sh   # mints a token and pings the demo MCP server
```

See `demo/README.md` for the demo prerequisites.

## Pull Request Guidelines

- **Branching:** branch off `main`. Use `ISSUE-ID-short-description` style; the issue tracker auto-detects the prefix.
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) format. Reference the tracked issue in the commit body or footer (e.g. `(ISSUE-ID)`).
- **PR template:** describe the change, link the issue, list the test plan.
- **CI:** every PR must pass `dotnet build`, `dotnet test`, `dotnet format --verify-no-changes`, and the conformance suite. Coverage thresholds (80 line / 70 branch) are enforced.
- **Changelog:** add an entry under `## [Unreleased]` in `CHANGELOG.md` for any user-visible change. Group under `Added` / `Changed` / `Fixed` / `Deprecated` / `Removed` / `Security`.

## CI / Workflow Expectations

- GitHub Actions are SHA-pinned via [pinact](https://github.com/suzuki-shunsuke/pinact); the manifest is `.pinact.yaml`. To upgrade an action: bump the tag, then `pinact run` to refresh the SHA.
- The workflow file is `.github/workflows/ci.yml`. Changes to it require a PR (no direct pushes to `main`).

## Code of Conduct

We follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be excellent to each other.
