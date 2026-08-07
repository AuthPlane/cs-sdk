## Summary

Brief description of what this PR does and why.

## Linked Issue

<!-- e.g., #123, or leave blank if N/A -->

## Changes

-

## Affected Projects

- [ ] `Authplane.Sdk` (core)
- [ ] `Authplane.Mcp`
- [ ] None (infra / docs / CI only)

## Test Plan

How was this tested? Include relevant test names or manual verification steps.

## Checklist

- [ ] `dotnet build Authplane.slnx --configuration Release` passes
- [ ] `dotnet format Authplane.slnx --verify-no-changes` is clean
- [ ] `dotnet test` passes for affected projects
- [ ] Coverage thresholds met (80 line / 70 branch)
- [ ] Tests added for new functionality
- [ ] Documentation updated (if applicable)
- [ ] `CHANGELOG.md` entry added under `[Unreleased]` (if user-facing)
- [ ] New workflow actions are SHA-pinned (`pinact run` after changes)
- [ ] No token values, secrets, or key material in logs or test fixtures
