#!/usr/bin/env bash
set -euo pipefail

# Tests for conformance-case-body-drift.sh and conformance-registered-case-ids.sh.
#
# Both scripts run only on the weekly drift schedule, so a break in either
# surfaces late and quietly — and the way it surfaces is a green run, because
# what they guard against is a check that under-reports. Shellcheck cannot see
# that class at all: a loosened id regex that silently drops cases, or a `diff`
# whose exit code stops being read, is valid shell. These tests pin the
# behaviour instead, so such an edit fails at PR time rather than the next time
# the catalog is re-tightened in place.
#
# The headline case is the real one the drift check exists for: the metadata
# jwks_uri rotation case was re-tightened under an unchanged id between two
# catalog revisions. The fixtures carry a trimmed form of both wordings, so the
# suite asserts against the change that actually happened rather than an
# invented one.
#
# Every fixture is a handful of YAML and JSON written to a temp dir. Nothing
# here clones the catalog, runs the conformance suite, or needs the .NET SDK —
# the point is that these controls stay runnable and fast on a PR.
#
# Run: .github/scripts/conformance-case-body-drift.test.sh

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRIFT="$SCRIPTDIR/conformance-case-body-drift.sh"
IDSCRIPT="$SCRIPTDIR/conformance-registered-case-ids.sh"

# conformance-registered-case-ids.sh reads the marker scan with jq and fails
# cleanly when jq is absent — which would turn half this suite into a check that
# the absence message is right, silently dropping the cases it is here to cover.
# Refuse to run instead of passing for that reason.
if ! command -v jq > /dev/null 2>&1; then
  echo "error: these tests need jq; conformance-registered-case-ids.sh reads the marker scan with it" >&2
  exit 1
fi

failures=0

# One root that an EXIT trap removes, so a fixture still gets cleaned up when
# `set -e` kills the shell from inside a helper — the moment a leak is least
# welcome. The per-case RETURN traps below do not fire then.
TESTROOT="$(mktemp -d)"
trap 'rm -rf "$TESTROOT"' EXIT

pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n     %s\n' "$1" "$2"; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Writes a catalog to $1. $2 picks the wording of the jwks_uri rotation case:
# "pinned" for the one the SDK's coverage was written against, "tip" for the
# re-tightening that replaced it under the same id. Trimmed to the keys that
# carry the change — surface, requirement_summary, stimulus, rationale — because
# the point of the fixture is the shape of the edit, not its length.
#
# standards_in_scope is present on purpose. It holds `- id:` entries that are
# not cases, and a fixture without it would not exercise the scoping that keeps
# them out of the comparison.
write_catalog() {
  local out="$1" jwks="$2"

  cat > "$out" <<'YAML'
---
schema_version: "1.0"
catalog_id: "oauth-sdk-conformance-catalog"
catalog_version: "2026-08-04"

standards_in_scope:
  - id: "RFC8414"
    title: "OAuth 2.0 Authorization Server Metadata"
  - id: "RFC7009"
    title: "OAuth 2.0 Token Revocation"

cases:
YAML

  if [[ "$jwks" == "pinned" ]]; then
    cat >> "$out" <<'YAML'
  - id: "rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache"
    title: "Reconfigure JWKS resolution when metadata jwks_uri changes"
    surface: "sdk-client.discovery"
    priority: "medium"
    requirement_summary: "When trusted metadata changes jwks_uri, the SDK SHOULD rebind JWKS fetching to the new URI."
    stimulus:
      operation: "client._on_metadata_changed"
    expected:
      outcome: "accept"
      side_effect:
        - "jwks_uri updated to new metadata value"
    rationale: "Keeps key discovery aligned with metadata rotation without requiring client recreation."
YAML
  else
    cat >> "$out" <<'YAML'
  - id: "rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache"
    title: "Follow a metadata jwks_uri rotation using only ordinary verification traffic"
    surface: "sdk-verifier.jwks"
    priority: "medium"
    requirement_summary: "A verifier SHOULD re-read metadata on its configured refresh interval and rebind JWKS fetching\
      \ to the rotated jwks_uri. Following the rotation MUST require nothing beyond ordinary verification traffic: no\
      \ force-refresh argument, no test-only hook, and no reflective access to internals."
    stimulus:
      operation: "verifier.verify, repeated as ordinary traffic spanning the metadata refresh interval"
    expected:
      outcome: "accept"
      side_effect:
        - "metadata re-fetched after the refresh interval elapses, without an explicit refresh call"
        - "JWKS fetched from new_metadata.jwks_uri"
    rationale: "Keeps key discovery aligned with metadata rotation without requiring client recreation. The mechanism\
      \ restriction is the substance of the case: a verify-only resource server never repeats client-side discovery."
YAML
  fi

  cat >> "$out" <<'YAML'
  - id: "rfc7009-revocation-server-errors-must-surface"
    title: "Surface revocation endpoint server errors as failures"
    surface: "sdk-client.revocation"
    priority: "high"
    requirement_summary: "A 5xx from the revocation endpoint MUST surface as a failure rather than be swallowed."
    expected:
      outcome: "reject"
    rationale: "A revocation the caller believes succeeded is worse than one that visibly failed."
YAML
}

# A pinned/tip pair that differs only in the jwks case, in $1/pinned.yaml and
# $1/tip.yaml, with both case ids registered in $1/ids.txt.
make_pair() {
  local root="$1"
  write_catalog "$root/pinned.yaml" pinned
  write_catalog "$root/tip.yaml" tip
  cat > "$root/ids.txt" <<'IDS'
rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache
rfc7009-revocation-server-errors-must-surface
IDS
}

# Runs the drift script against $1/{pinned,tip}.yaml and $1/ids.txt, capturing
# stdout and stderr together into $out and the exit status into $rc. Both are
# declared `local` by the caller.
run_drift() {
  local root="$1"
  rc=0
  out="$(PINNED_CATALOG="$root/pinned.yaml" \
    TIP_CATALOG="$root/tip.yaml" \
    REGISTERED_IDS="$root/ids.txt" \
    DRIFT_SUMMARY="$root/summary.md" \
    "$DRIFT" 2>&1)" || rc=$?
}

# ---------------------------------------------------------------------------
# conformance-case-body-drift.sh
# ---------------------------------------------------------------------------

# --- the positive control ------------------------------------------------------
# Without this every assertion below could be satisfied by a script that fails
# unconditionally, and the suite would look green while guarding nothing.
t_identical_catalogs_are_clean() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  cp "$root/pinned.yaml" "$root/tip.yaml"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 0 ]]; then
    fail "identical catalogs are clean" "exit $rc, want 0: ${out##*$'\n'}"
  elif ! grep -q "compared 2 registered case(s)" <<<"$out"; then
    fail "identical catalogs are clean" "it did not report comparing both cases: ${out##*$'\n'}"
  else
    pass "identical catalogs report clean, having compared both registered cases"
  fi
}

# --- the case this check exists for --------------------------------------------
# The jwks_uri rotation case was re-tightened in place: same id, new surface, new
# requirement, new mechanism restriction. Every id-level check in the alignment
# machinery sees an unchanged id set and reports clean. This is the one that must
# not, and it must name the case — a red run that does not say which case sends
# the maintainer back into the catalog diff by hand.
t_retightened_case_is_drift() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "a re-tightened case is drift" "exit $rc, want 1"
  elif ! grep -q "rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache" <<<"$out"; then
    fail "a re-tightened case is drift" "it failed without naming the case: ${out##*$'\n'}"
  elif ! grep -q "sdk-verifier.jwks" <<<"$out"; then
    fail "a re-tightened case is drift" "it named the case but printed no diff of the change"
  elif ! grep -q "rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache" "$root/summary.md"; then
    fail "a re-tightened case is drift" "the case is missing from the drift summary"
  else
    pass "a case re-tightened under an unchanged id fails, names the case and diffs it"
  fi
}

# --- scoping to the ids this SDK registers -------------------------------------
# The whole reason the check takes an id list: diffing the entire catalog fires
# on cases this SDK does not cover, and noise is what gets a guard ignored. Same
# drifted catalog as above, with only the untouched case registered.
t_unregistered_drift_is_ignored() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  echo "rfc7009-revocation-server-errors-must-surface" > "$root/ids.txt"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 0 ]]; then
    fail "drift outside the registered ids is ignored" "exit $rc, want 0: ${out##*$'\n'}"
  else
    pass "a case that drifted but is not registered does not fail the check"
  fi
}

# --- standards_in_scope ids are not cases --------------------------------------
# `standards_in_scope` earlier in the catalog carries its own `- id:` entries, and
# they are plain tokens that pass every id check. If the extractor ever reached
# them, "RFC8414" would compare clean against itself and this check would vouch
# for a case that does not exist.
t_standards_in_scope_is_not_a_case() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  cat > "$root/ids.txt" <<'IDS'
RFC8414
rfc7009-revocation-server-errors-must-surface
IDS

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "standards_in_scope ids are not cases" "exit $rc, want 1"
  elif ! grep -q "registers conformance case 'RFC8414', which the PINNED catalog does not contain" <<<"$out"; then
    fail "standards_in_scope ids are not cases" "it did not report RFC8414 as absent: ${out##*$'\n'}"
  else
    pass "an id from standards_in_scope is not found as a case"
  fi
}

# --- a `#` line deep in a scalar is body, not a comment ------------------------
# Inside a block scalar a leading `#` is text. Dropping such lines as comments
# made an edit to one report clean, which is the single normalization in the
# script that erred toward silence. Both fixtures here keep the structural shape
# identical so nothing but the scalar line can account for the result.
t_comment_shaped_scalar_line_is_body() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  cp "$root/pinned.yaml" "$root/tip.yaml"

  cat >> "$root/pinned.yaml" <<'YAML'
  - id: "rfc8414-metadata-refresh-sequence"
    use_case: |
      Rotation sequence, in order:
      # step 2: the AS begins serving new_metadata
    expected:
      outcome: "accept"
YAML
  cat >> "$root/tip.yaml" <<'YAML'
  - id: "rfc8414-metadata-refresh-sequence"
    use_case: |
      Rotation sequence, in order:
      # step 2: the AS withdraws jwks-v1.json entirely
    expected:
      outcome: "accept"
YAML
  echo "rfc8414-metadata-refresh-sequence" > "$root/ids.txt"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "a comment-shaped line inside a scalar is body text" "exit $rc, want 1 — the edit was dropped as a comment"
  elif ! grep -q "withdraws jwks-v1.json" <<<"$out"; then
    fail "a comment-shaped line inside a scalar is body text" "it failed without diffing the edited line"
  else
    pass "an edit to a #-leading line inside a block scalar reports as drift"
  fi
}

# --- a comment at a structural position stays a comment ------------------------
# The other half of that trade-off. Comments around and between the case items
# are YAML comments by construction, and treating a re-worded one as drift would
# be the noise the scoping above exists to avoid.
t_structural_comment_is_not_body() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  cp "$root/pinned.yaml" "$root/tip.yaml"

  # At the case-item indent, and at column 0 inside the cases block.
  cat >> "$root/tip.yaml" <<'YAML'
  # Revisit this grouping once the verifier surfaces settle.
# Catalog maintainers: keep the cases sorted by RFC number.
YAML

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 0 ]]; then
    fail "a structural comment is not body" "exit $rc, want 0: ${out##*$'\n'}"
  else
    pass "comments at and above the case-item indent do not register as drift"
  fi
}

# --- a registered case the pin does not hold -----------------------------------
# Nothing can be said about that case's body either way, so the check says so
# rather than counting it as compared-and-clean.
t_registered_id_absent_from_pin() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  cp "$root/pinned.yaml" "$root/tip.yaml"
  printf 'rfc9999-a-case-the-pin-never-had\n' >> "$root/ids.txt"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "a registered id absent from the pin fails" "exit $rc, want 1"
  elif ! grep -q "rfc9999-a-case-the-pin-never-had" <<<"$out"; then
    fail "a registered id absent from the pin fails" "it did not name the case: ${out##*$'\n'}"
  else
    pass "a registered case the pinned catalog does not hold fails, naming it"
  fi
}

# --- a case removed at the tip is id-level drift, reported elsewhere -----------
# Removal is what the alignment check reports. Counting it here too would put one
# catalog change in two red steps, so it warns and stays out of the exit status —
# but it must still be named, not folded into the compared-and-clean count.
t_case_absent_from_tip_warns() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  cp "$root/pinned.yaml" "$root/tip.yaml"
  # Drop the last case from the tip only — it runs to the end of the file, so
  # deleting from its `- id:` line onward removes the whole item rather than
  # orphaning its keys onto the case before it.
  sed '/- id: "rfc7009-revocation-server-errors-must-surface"/,$d' "$root/tip.yaml" > "$root/tip.trimmed"
  mv "$root/tip.trimmed" "$root/tip.yaml"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 0 ]]; then
    fail "a case absent from the tip warns" "exit $rc, want 0: ${out##*$'\n'}"
  elif ! grep -q "absent from the comparison catalog" <<<"$out"; then
    fail "a case absent from the tip warns" "it passed without mentioning the removal"
  else
    pass "a case removed at the tip warns and leaves the exit status to the alignment check"
  fi
}

# --- an all-blank id list ------------------------------------------------------
# An empty id list makes this check vacuously green, which is the failure it
# exists to prevent. The wording assertion is not decoration: the grep that
# filters blank lines exits 1 when it selects nothing, and under `pipefail` that
# used to end the script right here — the right exit code with nothing printed.
t_blank_id_list() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  printf '\n   \n\t\n\n' > "$root/ids.txt"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "an all-blank id list fails" "exit $rc, want 1"
  elif ! grep -q "holds no case ids" <<<"$out"; then
    fail "an all-blank id list fails" "it failed silently, with no message to act on: ${out:-(empty)}"
  else
    pass "an all-blank id list fails with a message rather than a bare exit 1"
  fi
}

# --- an id list holding something that is not an id ----------------------------
# An entry this check silently drops is a case it silently stops guarding.
t_malformed_id_list() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  echo 'rfc8414-jwks-uri rotation' > "$root/ids.txt"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "a malformed id list fails" "exit $rc, want 1"
  elif ! grep -q "not plain case ids" <<<"$out"; then
    fail "a malformed id list fails" "unexpected message: ${out##*$'\n'}"
  else
    pass "an id list entry that is not a plain case id fails"
  fi
}

# --- no id in common with the catalog ------------------------------------------
# A mismatched pair of inputs, or an id source that produced plausible-looking
# nonsense. Nothing was compared, so nothing is clean.
t_nothing_compared() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  echo 'some-other-catalogs-case-id' > "$root/ids.txt"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "comparing nothing is not a clean run" "exit $rc, want 1"
  elif ! grep -q "not one registered case id could be compared" <<<"$out"; then
    fail "comparing nothing is not a clean run" "unexpected message: ${out##*$'\n'}"
  else
    pass "an id list with nothing in common with the catalog fails"
  fi
}

# --- a missing input -----------------------------------------------------------
# The fetch that produces these files can fail; reading a clean result out of a
# file that is not there is the shape of failure this script refuses.
t_missing_input() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  rm -f "$root/pinned.yaml"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "a missing input fails" "exit $rc, want 1"
  elif ! grep -q "is not a readable regular file" <<<"$out"; then
    fail "a missing input fails" "unexpected message: ${out##*$'\n'}"
  else
    pass "a missing catalog fails rather than reporting a clean result"
  fi
}

# --- an empty input ------------------------------------------------------------
# A truncated clone leaves a file that exists and parses to nothing.
t_empty_input() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  make_pair "$root"
  : > "$root/tip.yaml"

  local out rc
  run_drift "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "an empty input fails" "exit $rc, want 1"
  elif ! grep -q "is empty" <<<"$out"; then
    fail "an empty input fails" "unexpected message: ${out##*$'\n'}"
  else
    pass "an empty catalog file fails rather than reporting a clean result"
  fi
}

# --- catalog shapes the extractor will not guess at -----------------------------
# Each of these would otherwise be mis-attributed to a neighbouring case, which
# is the quiet kind of wrong: the comparison still runs and still reports.
# Driven off one table because the contract is identical for all of them — fail,
# and say which line and why.
t_malformed_catalog_shapes() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN

  local name shape expect
  while IFS='|' read -r name expect shape; do
    [[ -n "$name" ]] || continue
    local dir; dir="$(mktemp -d "$root/XXXXXX")"
    make_pair "$dir"
    # Only the tip is malformed, so a pass here cannot come from both sides
    # being equally unreadable.
    printf '%b' "$shape" >> "$dir/tip.yaml"

    local out rc
    run_drift "$dir"
    if [[ "$rc" -ne 1 ]]; then
      fail "$name" "exit $rc, want 1"
    elif ! grep -q "$expect" <<<"$out"; then
      fail "$name" "unexpected message: ${out##*$'\n'}"
    else
      pass "$name"
    fi
  done <<'SHAPES'
a second top-level cases: key fails|a second top-level cases: key|cases:\n  - id: "rfc7009-a-second-block"\n    title: "x"\n
a non-item line at the case-item indent fails|a non-item line at the case-item indent|  title: "orphaned, and it would land on the previous case"\n
a case item whose first key is not id: fails|does not open with an id: key|  - title: "id further down"\n    id: "rfc7009-id-not-first"\n
a duplicate case id fails|duplicate case id|  - id: "rfc7009-revocation-server-errors-must-surface"\n    title: "the same id again"\n
a case id that is not a plain token fails|not a plain token|  - id: "rfc7009 revocation errors"\n    title: "spaces in the id"\n
SHAPES
}

# ---------------------------------------------------------------------------
# conformance-registered-case-ids.sh
# ---------------------------------------------------------------------------
#
# Registration in this repo is a [Conformance] attribute, read by reflection over
# the compiled attributes and emitted to a scan file per test assembly. These
# fixtures are hand-written JSON rather than a real scan: the point is what the
# reader does with each shape, and producing one for real would make these
# controls depend on the .NET SDK, on the catalog clone, and on the suite
# building.
#
# The scan carries one entry per marker OCCURRENCE and no per-entry registration
# flag — every entry is a marker the scan found. What the reader has to get right
# is therefore different from a run report: deduplicate across tests and across
# assemblies, accept an assembly that legitimately declares nothing, and refuse
# anything that is not the emitter's documented shape.

run_ids() {
  rc=0
  out="$(CONFORMANCE_MARKER_SCAN_DIR="$1" "$IDSCRIPT" 2>&1)" || rc=$?
}

# Writes a scan file for assembly $2 into directory $1. Remaining args are
# `case_id=declared_by` pairs; none means an assembly that declares no markers.
write_scan() {
  local dir="$1" assembly="$2"; shift 2
  mkdir -p "$dir"
  {
    printf '{\n  "assembly": "%s",\n  "cases": [\n' "$assembly"
    local first=1 pair
    for pair in "$@"; do
      [[ "$first" -eq 1 ]] || printf ',\n'
      first=0
      printf '    {"case_id": "%s", "declared_by": "%s"}' "${pair%%=*}" "${pair#*=}"
    done
    [[ "$first" -eq 1 ]] || printf '\n'
    printf '  ]\n}\n'
  } > "$dir/$assembly.json"
}

# --- every marker counts, deduplicated across tests and assemblies --------------
# One entry per marker occurrence, so a case claimed by two tests arrives twice
# and a case claimed in two assemblies arrives from two files. Emitting it twice
# would put a duplicate into the id list, where the generic script would compare
# the same body twice and report a case count that does not match the catalog.
#
# Nothing keys on a test's outcome, and there is nothing in the scan to key on:
# the scan is of the compiled attributes, not of a run. That is the intended
# reading — a registered case whose test failed or was skipped is still
# registered, and still needs its body watched.
t_ids_dedupes_across_tests_and_assemblies() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  write_scan "$root" Authplane.Tests \
    "rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache=Authplane.Tests.JwksTests.Rotates" \
    "rfc7009-revocation-server-errors-must-surface=Authplane.Tests.RevocationTests.Accepts" \
    "rfc7009-revocation-server-errors-must-surface=Authplane.Tests.RevocationTests.Rejects"
  write_scan "$root" Authplane.Mcp.Tests \
    "rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache=Authplane.Mcp.Tests.MiddlewareTests.Rotates"

  local out rc
  run_ids "$root"
  if [[ "$rc" -ne 0 ]]; then
    fail "markers dedupe across tests and assemblies" "exit $rc, want 0: ${out##*$'\n'}"
  elif [[ "$out" != "rfc7009-revocation-server-errors-must-surface
rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache" ]]; then
    fail "markers dedupe across tests and assemblies" "printed: ${out//$'\n'/, }"
  else
    pass "a case claimed by several tests, in several assemblies, is printed once"
  fi
}

# --- an assembly that declares no markers is a legitimate state ------------------
# The MCP adapter test assembly is in it today. It still writes a scan file, so
# the reader can tell a scan that ran and found nothing from a scan that never
# ran — and only one of those is allowed to pass.
t_ids_empty_assembly_is_allowed() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  write_scan "$root" Authplane.Tests \
    "rfc7009-revocation-server-errors-must-surface=Authplane.Tests.RevocationTests.Accepts"
  write_scan "$root" Authplane.Mcp.Tests

  local out rc
  run_ids "$root"
  if [[ "$rc" -ne 0 ]]; then
    fail "an assembly with no markers is allowed" "exit $rc, want 0: ${out##*$'\n'}"
  elif [[ "$out" != "rfc7009-revocation-server-errors-must-surface" ]]; then
    fail "an assembly with no markers is allowed" "printed: ${out//$'\n'/, }"
  else
    pass "an assembly that declares no markers contributes nothing and fails nothing"
  fi
}

# --- but no marker anywhere is not -----------------------------------------------
# Every scan empty: the markers were dropped, or the emitter ran against the wrong
# assemblies. An empty list downstream is a vacuously green drift check, which is
# the failure the whole check exists to prevent.
t_ids_nothing_registered() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN
  write_scan "$root" Authplane.Tests
  write_scan "$root" Authplane.Mcp.Tests

  local out rc
  run_ids "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "a scan with no marker at all fails" "exit $rc, want 1"
  elif ! grep -q "record no \[Conformance\] marker at all" <<<"$out"; then
    fail "a scan with no marker at all fails" "unexpected message: ${out##*$'\n'}"
  else
    pass "scan files that between them hold no marker fail"
  fi
}

# --- a scan directory with no scan file in it ------------------------------------
# The workflow deletes the directory before the run that writes it, so "the tests
# did not run" is a state that really occurs. It must not read as "nothing
# registered, carry on" — and it must not read as "nothing to do" either, which
# is what an empty glob would silently become.
t_ids_no_scan_file() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN

  local out rc
  run_ids "$root"
  if [[ "$rc" -ne 1 ]]; then
    fail "an empty scan directory fails" "exit $rc, want 1"
  elif ! grep -q "holds no scan file" <<<"$out"; then
    fail "an empty scan directory fails" "unexpected message: ${out##*$'\n'}"
  else
    pass "a scan directory holding no scan file fails"
  fi

  run_ids "$root/absent"
  if [[ "$rc" -ne 1 ]] || ! grep -q "is not a directory" <<<"$out"; then
    fail "a missing scan directory fails" "exit $rc: ${out##*$'\n'}"
  else
    pass "a scan directory that does not exist fails, naming the path"
  fi
}

# --- an entry missing a field is the emitter's contract having changed -----------
# Not a case that happens not to be registered. It would drop out of the read
# without a word, so the list would be short by one with nothing to show for it —
# and short is the direction that makes this check quietly stop guarding a case.
t_ids_malformed_entries() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN

  local out rc

  mkdir -p "$root/a"
  cat > "$root/a/Authplane.Tests.json" <<'JSON'
{
  "assembly": "Authplane.Tests",
  "cases": [
    {"case_id": "rfc7009-revocation-server-errors-must-surface", "declared_by": "Authplane.Tests.RevocationTests.Accepts"},
    {"declared_by": "Authplane.Tests.RevocationTests.Rejects"}
  ]
}
JSON
  run_ids "$root/a"
  if [[ "$rc" -ne 1 ]] || ! grep -q "missing or non-string case_id or declared_by" <<<"$out"; then
    fail "an entry with no case_id fails" "exit $rc: ${out##*$'\n'}"
  else
    pass "a scan entry without a case_id fails instead of being dropped"
  fi

  mkdir -p "$root/b"
  cat > "$root/b/Authplane.Tests.json" <<'JSON'
{
  "assembly": "Authplane.Tests",
  "cases": [
    {"case_id": "rfc7009-revocation-server-errors-must-surface", "declared_by": ""}
  ]
}
JSON
  run_ids "$root/b"
  if [[ "$rc" -ne 1 ]] || ! grep -q "missing or non-string case_id or declared_by" <<<"$out"; then
    fail "an entry with no declared_by fails" "exit $rc: ${out##*$'\n'}"
  else
    pass "a scan entry without a declaring method fails"
  fi
}

# --- a file that is not a marker scan ---------------------------------------------
# A stray JSON file in the directory, or the emitter's shape having moved. Reading
# case ids out of it anyway would be guessing, and the guess that finds nothing is
# indistinguishable from an assembly that declares nothing.
t_ids_unusable_scans() {
  local root; root="$(mktemp -d "$TESTROOT/XXXXXX")"; trap 'rm -rf "$root"' RETURN

  local out rc

  mkdir -p "$root/a"
  echo 'not json at all' > "$root/a/Authplane.Tests.json"
  run_ids "$root/a"
  if [[ "$rc" -ne 1 ]] || ! grep -q "not valid JSON" <<<"$out"; then
    fail "an unparseable scan fails" "exit $rc: ${out##*$'\n'}"
  else
    pass "a scan file that is not JSON fails"
  fi

  mkdir -p "$root/b"
  echo '{"cases": [{"case_id": "rfc7009-x", "declared_by": "T.M"}]}' > "$root/b/stray.json"
  run_ids "$root/b"
  if [[ "$rc" -ne 1 ]] || ! grep -q "does not name the assembly it scanned" <<<"$out"; then
    fail "a file that names no assembly fails" "exit $rc: ${out##*$'\n'}"
  else
    pass "a JSON file that does not name the assembly it scanned fails"
  fi

  mkdir -p "$root/c"
  echo '{"assembly": "Authplane.Tests"}' > "$root/c/Authplane.Tests.json"
  run_ids "$root/c"
  if [[ "$rc" -ne 1 ]] || ! grep -q "has no .cases array" <<<"$out"; then
    fail "a scan with no cases array fails" "exit $rc: ${out##*$'\n'}"
  else
    pass "a scan file with no cases array fails"
  fi

  mkdir -p "$root/d"
  : > "$root/d/Authplane.Tests.json"
  run_ids "$root/d"
  if [[ "$rc" -ne 1 ]] || ! grep -q "not a readable, non-empty file" <<<"$out"; then
    fail "an empty scan file fails" "exit $rc: ${out##*$'\n'}"
  else
    pass "an empty scan file fails rather than contributing nothing"
  fi
}

echo "conformance-case-body-drift.sh — case body comparison"
t_identical_catalogs_are_clean
t_retightened_case_is_drift
t_unregistered_drift_is_ignored
t_standards_in_scope_is_not_a_case
t_comment_shaped_scalar_line_is_body
t_structural_comment_is_not_body
t_registered_id_absent_from_pin
t_case_absent_from_tip_warns
t_blank_id_list
t_malformed_id_list
t_nothing_compared
t_missing_input
t_empty_input
t_malformed_catalog_shapes

echo "conformance-registered-case-ids.sh — marker scan reader"
t_ids_dedupes_across_tests_and_assemblies
t_ids_empty_assembly_is_allowed
t_ids_nothing_registered
t_ids_no_scan_file
t_ids_malformed_entries
t_ids_unusable_scans

if [[ "$failures" -gt 0 ]]; then
  echo "$failures failing"
  exit 1
fi
echo "all passing"
