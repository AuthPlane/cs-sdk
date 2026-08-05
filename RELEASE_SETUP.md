# Release setup

One-time operator steps required before the release pipeline can publish to NuGet. Both packages (`Authplane.Sdk`, `Authplane.Mcp`) ship via a single API key.

## 1. NuGet API key

Create an API key on [nuget.org](https://www.nuget.org/) with publish rights to both packages:

1. Sign in as the owner (or any user with `Push` rights on the Authplane packages).
2. **Account → API Keys → Create**.
3. **Key Name**: `cs-sdk publish` (or similar — for audit clarity).
4. **Select Scopes**: `Push` (covers both new versions and new packages).
5. **Select Packages**: choose `Authplane.Sdk` and `Authplane.Mcp` (or glob `Authplane.*` if you want one key to cover future adapters).
6. **Expires In**: 365 days (NuGet maximum). Calendar a rotation reminder.
7. Copy the key.

## 2. GitHub Environment

In the `AuthPlane/cs-sdk` repository:

1. **Settings → Environments → New environment → `nuget`**.
2. Add the API key as an environment secret named `NUGET_API_KEY`.
3. **(Recommended)** **Deployment branches and tags → Selected branches and tags → Add deployment branch or tag rule → Tag → `v*.*.*`**. Restricts `publish-nuget.yml` to actual release tags so a misfire on a feature branch can never reach NuGet.
4. **(Optional)** Add **required reviewers** so every NuGet push waits for a human approval. Useful if multiple maintainers can dispatch `release.yml`.

NuGet.org does not yet support OIDC Trusted Publishing, so the API key + tag-policy combination is the strongest binding available today.

## 3. AuthPlane Release Bot App secrets

`release.yml` mints a short-lived installation token from the AuthPlane Release Bot GitHub App to bypass the `v*` tag ruleset (which rejects the default `GITHUB_TOKEN`). Two secrets are required at the **repo** or **org** level:

- `RELEASE_BOT_APP_ID` — numeric App ID of the AuthPlane Release Bot App.
- `RELEASE_BOT_PRIVATE_KEY` — PEM-encoded private key (the full block, including `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----` lines).

These are typically already configured at the org level. Verify the `cs-sdk` repo is in the secret's scope (Org settings → Secrets → `RELEASE_BOT_APP_ID` → Repository access).

If they are missing, `release.yml` fails fast with a clear error before any work is done.

## 4. CHANGELOG

`release.yml` reads `CHANGELOG.md` for release notes. Ensure:

- Every release has a `## [X.Y.Z]` heading on the source branch (`release/v*` or `hotfix/v*`) before running the release workflow.
- The default branch always carries `## [Unreleased]` between releases. `cut-release.yml` enforces this on `release/v*` cuts (refuses to cut if missing); `hotfix/v*` cuts skip the check because they branch off an older tag.

## 5. Dispatching a release

End-to-end happy path:

1. **Cut the release branch** — from the Actions tab, dispatch **Cut release branch** on the default branch with `releaseVersion=X.Y.Z`. The workflow:
   - cuts `release/vX.Y.Z`,
   - bumps `<Version>` in `src/Authplane/Authplane.csproj` and `src/Authplane.Mcp/Authplane.Mcp.csproj` to `X.Y.Z-pre.0`,
   - opens an auto-merge PR bumping the default branch to the next `-pre.N`.
2. **Stabilise on `release/vX.Y.Z`** — rename `## [Unreleased]` to `## [X.Y.Z]` in `CHANGELOG.md`, land last-minute fixes if any.
3. **Dispatch the release** — from the Actions tab, dispatch **Release** on `release/vX.Y.Z`. Use the `dryRun` checkbox the first time on a new repo configuration. On a real run, the workflow:
   - strips the `-pre.N` suffix to `X.Y.Z`,
   - commits + tags `vX.Y.Z`,
   - atomic-pushes branch + tag using the Release Bot token,
   - creates the GitHub Release with notes extracted from CHANGELOG,
   - deletes the source branch.
4. **`publish-nuget.yml` triggers automatically** on the tag push. It builds, packs, and pushes `Authplane.Sdk` then `Authplane.Mcp` to NuGet. The `nuget` environment gates the publish.

## 6. Hotfix flow

For patches to an older minor line (not the current default-branch line):

1. **Cut the hotfix branch** — dispatch **Cut release branch** with `releaseVersion=X.Y.(Z+N)` and `hotfixBase=vX.Y.Z` (the tag the patch is based on). The workflow validates:
   - the hotfix base tag exists,
   - the new version is on the same minor line,
   - the line is strictly older than the default branch's current line.
2. **Land the fix on `hotfix/vX.Y.Z`** — cherry-pick or commit directly. Add a `## [X.Y.Z]` CHANGELOG entry.
3. **Dispatch the release** — same as above, from the `hotfix/v*` branch.
4. **Backport to the default branch** — after publication, port the fix back so the default branch line carries it too. *The dedicated Backport workflow has not been added yet — use the manual cherry-pick fallback below until it lands. Tracked separately.*

   Manual cherry-pick fallback:

   ```bash
   git fetch --tags origin
   git checkout -b backport/<short-desc> origin/develop
   git cherry-pick vX.Y.Z~..vX.Y.Z   # adjust the range to the hotfix commits
   # resolve any conflicts, then:
   git push origin backport/<short-desc>
   gh pr create --base develop --title 'chore(backport): port vX.Y.Z fixes to develop' \
     --body 'Cherry-picked from tag vX.Y.Z. See RELEASE_SETUP.md §6.'
   ```

## 7. Recovery: partial NuGet publish

NuGet does not support atomic multi-package uploads. If `publish-nuget.yml` publishes one package then fails:

1. Inspect the failed workflow run's logs to identify which package was already accepted by NuGet.
2. For each package still missing, manually publish from a developer machine authenticated to NuGet:

   ```bash
   dotnet pack Authplane.slnx --configuration Release --output ./nupkg
   dotnet nuget push ./nupkg/Authplane.Sdk.X.Y.Z.nupkg \
     --source https://api.nuget.org/v3/index.json \
     --api-key $NUGET_API_KEY \
     --skip-duplicate
   dotnet nuget push ./nupkg/Authplane.Mcp.X.Y.Z.nupkg \
     --source https://api.nuget.org/v3/index.json \
     --api-key $NUGET_API_KEY \
     --skip-duplicate
   ```

   `--skip-duplicate` is safe to leave on the package that already published — it will return success without re-uploading.

3. If the GitHub Release was also skipped, create it manually:

   ```bash
   gh release create vX.Y.Z --title vX.Y.Z --notes-file <path-to-notes>
   ```

   No `--target` — the tag already points at the correct commit on the (now deleted) source branch.

4. If any commits on the source branch need to reach the default branch, port them back via the manual cherry-pick fallback documented in §6.4 (the dedicated **Backport fixes** workflow has not been added yet).

The git tag is already live, so re-running `release.yml` is not an option (the tag-exists pre-flight refuses).
