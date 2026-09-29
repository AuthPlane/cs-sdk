#!/usr/bin/env bash
#
# Print the conformance case ids THIS SDK registers, one per line.
#
# This is the repo-specific half of the case-body drift check: the id source depends on how this
# repo records registrations, so it lives here and conformance-case-body-drift.sh stays generic.
#
# Registration here is a [Conformance] attribute on a test method. There is no run-time record to
# read: nothing calls ConformanceTracker or ConformanceCaseRunner, so ConformanceRegistry is empty
# for the whole run and ConformanceReportWriter — which has no callers either — would render every
# catalog case as not_run. So the ids come from the marker scan instead, emitted by
# ConformanceMarkerScanWriter from ConformanceCatalogAlignment.ScanConformanceMarkers.
#
# That scan is reflection over the compiled attributes, not a match over the test sources. It reads
# what the runtime reads, it raises on an assembly whose types will not load rather than returning
# a short list, and — the part that matters — it is the same scan the catalog-alignment assertion
# is written against, asserted in both directions on every PR: every catalog case must carry a
# marker, and every marker must name a catalog case. A marker this extractor missed would surface
# there as an uncovered catalog case and turn the run red. There is no path by which the id list
# silently shortens.
#
# The scan carries one entry per marker OCCURRENCE, so a case claimed by more than one test appears
# more than once and this script deduplicates. `declared_by` is not filtered on: it is checked for
# presence, because an entry without it is not a case that happens not to be registered — it is the
# emitter's contract having changed under this script. Nothing keys on the test's outcome either. A
# registered case whose test failed or was skipped is still registered and still needs its body
# watched.
#
# An assembly that declares no markers emits a scan file with an empty case list. That is a
# legitimate state — the MCP adapter test assembly is in it today — so emptiness is rejected on the
# union rather than per file. The union being empty is a hard failure: an id list with nothing in
# it makes the drift check vacuously green, which is the failure it exists to prevent.
#
# Requires the alignment tests to have run under CONFORMANCE_MARKER_SCAN_DIR, so the scan on disk
# belongs to this commit.
#
# Inputs (environment):
#   CONFORMANCE_MARKER_SCAN_DIR  directory holding one <AssemblyName>.json scan file per test
#                                assembly (default: $GITHUB_WORKSPACE/conformance-marker-scan)
#
# Exit status:
#   0  ids printed on stdout
#   1  the scan is missing, unreadable, malformed, or holds no registered case

set -euo pipefail

SCAN_DIR="${CONFORMANCE_MARKER_SCAN_DIR:-${GITHUB_WORKSPACE:-.}/conformance-marker-scan}"

fail() {
  echo "::error::$1" >&2
  exit 1
}

if ! command -v jq > /dev/null 2>&1; then
  fail "registered case ids: jq is not available, so the marker scan cannot be read."
fi

if [[ ! -d "$SCAN_DIR" ]]; then
  fail "registered case ids: '$SCAN_DIR' is not a directory. The alignment tests write the marker scan there when CONFORMANCE_MARKER_SCAN_DIR is set, so either they did not run or they failed before the scan was written."
fi

shopt -s nullglob
scans=("$SCAN_DIR"/*.json)
shopt -u nullglob

if [[ "${#scans[@]}" -eq 0 ]]; then
  fail "registered case ids: '$SCAN_DIR' holds no scan file. A scan that never ran is not a scan that found nothing — each test assembly writes a file even when it declares no markers."
fi

ids=""

for scan in "${scans[@]}"; do
  if [[ ! -r "$scan" || ! -s "$scan" ]]; then
    fail "registered case ids: '$scan' is not a readable, non-empty file."
  fi

  if ! jq -e . "$scan" > /dev/null 2>&1; then
    fail "registered case ids: '$scan' is not valid JSON."
  fi

  # The emitter names the assembly it scanned. Its absence means the file is not the artifact this
  # script is written against, and reading case ids out of it anyway would be guessing.
  if ! jq -e '(.assembly | type) == "string" and (.assembly | length) > 0' "$scan" > /dev/null 2>&1; then
    fail "registered case ids: '$scan' does not name the assembly it scanned; this is not a marker scan file."
  fi

  if ! jq -e '(.cases | type) == "array"' "$scan" > /dev/null 2>&1; then
    fail "registered case ids: '$scan' has no .cases array."
  fi

  # An entry with a missing or empty field would drop out of the read below without a word, taking
  # a real registration with it.
  if ! jq -e 'all(.cases[];
        (.case_id | type) == "string" and (.case_id | length) > 0 and
        (.declared_by | type) == "string" and (.declared_by | length) > 0)' \
      "$scan" > /dev/null 2>&1; then
    fail "registered case ids: '$scan' holds an entry with a missing or non-string case_id or declared_by."
  fi

  ids+="$(jq -r '.cases[] | .case_id' "$scan")"$'\n'
done

# One entry per marker occurrence upstream, so the same id can arrive from two tests, or from two
# assemblies. Sorting unique here is what the consumer expects.
ids="$(printf '%s' "$ids" | grep -v '^$' | sort -u || true)"

if [[ -z "$ids" ]]; then
  fail "registered case ids: the scan files in '$SCAN_DIR' record no [Conformance] marker at all. Any check restricted to this list would be vacuously green."
fi

printf '%s\n' "$ids"
