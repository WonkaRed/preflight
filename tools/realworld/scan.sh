#!/usr/bin/env bash
# Re-runs the real-world scan behind docs/real-world.md.
#
#   tools/realworld/scan.sh <workdir>
#
# Shallow-fetches each commit pinned in repos.tsv into <workdir> (a repository already there is reused after its
# HEAD is checked), scans it with the built scanner, and prints the findings and the test files skipped per
# repository, the findings per rule and the total. The per-repository table is sorted by findings (most first, then by
# test files skipped) and labelled repo-01, repo-02, ... by that rank, so neither a name nor the order of repos.tsv
# puts a project beside a finding count.
#
# Triage. The per-finding verdicts (repository, file:line, rule, verdict, reason) live in triage.local.tsv, which is
# gitignored because it names third-party files beside verdicts. When it is there, every finding must have exactly
# one row and every row one finding, the verdict counts are regenerated from it, and they must equal the committed
# triage.tsv (rule, verdict, count). Without it only the per-rule totals can be checked, against the sums of the
# committed counts. The cloned code is only read: it is never built or run.
#
# The scanner is $PREFLIGHT, default target/release/preflight (cargo build --release -p preflight).
# Exit status: 0 when every clone and scan worked and the findings agree with the triage, 1 when a clone or scan
# failed or the triage and the scanner disagree.

# Fail mode: closed. Every step that may legitimately fail is handled below with a message that names the cause.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
preflight=${PREFLIGHT:-$root/target/release/preflight}

fail() { echo "scan.sh: $*" >&2; exit 1; }

[ $# -eq 1 ] || fail "usage: tools/realworld/scan.sh <workdir>"
[ -x "$preflight" ] || fail "no scanner at $preflight (run: cargo build --release -p preflight, or set PREFLIGHT)"
command -v git >/dev/null || fail "git is required"
command -v jq >/dev/null || fail "jq is required"
mkdir -p "$1" || fail "cannot create $1"
work=$(cd "$1" && pwd)
mkdir -p "$work/out"

found="$work/out/findings.tsv"
: > "$found"
failed=0
skipped_total=0
per_repo="$work/out/per-repo.tsv"
: > "$per_repo"

echo "scanner: $("$preflight" --version)"

while IFS='	' read -r name url commit sub; do
    case $name in ''|'#'*) continue ;; esac
    dir="$work/$name"
    if [ ! -d "$dir/.git" ]; then
        # One commit, no history: the pin is a full SHA and GitHub serves a fetch by SHA.
        if ! { mkdir -p "$dir" \
            && git -C "$dir" init -q \
            && git -C "$dir" remote add origin "$url" \
            && git -C "$dir" fetch -q --depth 1 origin "$commit" \
            && git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD; }; then
            echo "scan.sh: cannot fetch $name ($url @ $commit)" >&2
            failed=1
            continue
        fi
    fi
    head=$(git -C "$dir" rev-parse HEAD 2>/dev/null) || head=
    [ "$head" = "$commit" ] || { echo "scan.sh: $name is at ${head:-?}, not the pinned $commit" >&2; failed=1; continue; }

    # Exit 1 means findings, which is the normal case here; anything above is a failed scan.
    status=0
    "$preflight" --json "$dir/$sub" > "$work/out/$name.json" 2> "$work/out/$name.err" || status=$?
    if [ $status -ne 0 ] && [ $status -ne 1 ]; then
        echo "scan.sh: the scan of $name failed (exit $status): $(cat "$work/out/$name.err")" >&2
        failed=1
        continue
    fi
    jq -r --arg repo "$name" '.findings[] | [$repo, "\(.file):\(.line)", .rule_id] | @tsv' "$work/out/$name.json" \
        > "$work/out/$name.tsv" || { echo "scan.sh: unreadable report for $name" >&2; failed=1; continue; }
    skipped=$(jq -r '.summary.test_files_skipped' "$work/out/$name.json") || { echo "scan.sh: unreadable report for $name" >&2; failed=1; continue; }
    skipped_total=$((skipped_total + skipped))
    cat "$work/out/$name.tsv" >> "$found"
    printf '%s\t%s\n' "$(wc -l < "$work/out/$name.tsv")" "$skipped" >> "$per_repo"
done < "$here/repos.tsv"

echo
printf '%-16s %-9s %s\n' repository findings test-files-skipped
sort -t'	' -k1,1nr -k2,2nr "$per_repo" | awk -F'\t' '{ printf "%-16s %-9s %s\n", sprintf("repo-%02d", NR), $1, $2 }'
echo
printf '%-16s %s\n' rule findings
cut -f3 "$found" | sort | uniq -c | awk '{ printf "%-16s %s\n", $2, $1 }' || true
echo
echo "total findings: $(wc -l < "$found"), test files skipped: $skipped_total"

sort "$found" > "$work/out/found-keys.tsv"
local_rows="$here/triage.local.tsv"
committed="$here/triage.tsv"
[ -r "$committed" ] || fail "cannot read $committed"
{ grep -v '^#' "$committed" || true; } | sort > "$work/out/committed-counts.tsv"

if [ -r "$local_rows" ]; then
    # The triage must name every finding once and nothing else. Rows are compared as sorted multisets of
    # "repository, file:line, rule", so two findings on one line need two rows.
    { grep -v '^#' "$local_rows" || true; } | cut -f1-3 | sort > "$work/out/triage-keys.tsv"
    bad=$({ grep -v '^#' "$local_rows" || true; } | cut -f4 | grep -vcx 'TRUE\|DEFENSIBLE\|FALSE') || true
    [ "$bad" -eq 0 ] || { echo "scan.sh: triage.local.tsv has $bad rows whose verdict is not TRUE, DEFENSIBLE or FALSE" >&2; failed=1; }
    if [ $failed -eq 0 ]; then
        missing=$(comm -23 "$work/out/found-keys.tsv" "$work/out/triage-keys.tsv") || true
        stale=$(comm -13 "$work/out/found-keys.tsv" "$work/out/triage-keys.tsv") || true
        if [ -n "$missing" ]; then
            echo "scan.sh: findings with no triage row (add a row to tools/realworld/triage.local.tsv):" >&2
            echo "  ${missing//$'\n'/$'\n'  }" >&2
            failed=1
        fi
        if [ -n "$stale" ]; then
            echo "scan.sh: triage rows with no finding (the scanner no longer reports them; delete the row):" >&2
            echo "  ${stale//$'\n'/$'\n'  }" >&2
            failed=1
        fi
    fi
    # The committed counts are regenerated from the rows, never typed.
    { grep -v '^#' "$local_rows" || true; } | cut -f3,4 | sort | uniq -c \
        | awk '{ printf "%s\t%s\t%s\n", $2, $3, $1 }' | sort > "$work/out/generated-counts.tsv"
    if ! diff -u "$work/out/committed-counts.tsv" "$work/out/generated-counts.tsv" > "$work/out/counts.diff"; then
        echo "scan.sh: triage.tsv does not match triage.local.tsv (- committed, + regenerated); copy the data rows from $work/out/generated-counts.tsv" >&2
        cat "$work/out/counts.diff" >&2
        failed=1
    fi
    echo
    echo "triage from triage.local.tsv ($(wc -l < "$work/out/triage-keys.tsv") rows):"
else
    echo
    echo "no triage.local.tsv: only the per-rule totals can be checked, against the committed triage.tsv"
    cut -f3 "$found" | sort | uniq -c | awk '{ printf "%s\t%s\n", $2, $1 }' | sort > "$work/out/found-per-rule.tsv"
    awk -F'\t' '{ sum[$1] += $3 } END { for (rule in sum) printf "%s\t%s\n", rule, sum[rule] }' "$work/out/committed-counts.tsv" \
        | sort > "$work/out/committed-per-rule.tsv"
    if ! diff -u "$work/out/committed-per-rule.tsv" "$work/out/found-per-rule.tsv" > "$work/out/counts.diff"; then
        echo "scan.sh: findings per rule differ from the committed triage.tsv (- committed, + scanner):" >&2
        cat "$work/out/counts.diff" >&2
        failed=1
    fi
    echo "triage from the committed triage.tsv:"
fi
awk -F'\t' '{ count[$2] += $3 } END { for (verdict in count) printf "  %-12s %s\n", verdict, count[verdict] }' \
    "$work/out/committed-counts.tsv" | sort

if [ $failed -ne 0 ]; then
    echo "scan.sh: FAILED" >&2
elif [ -r "$local_rows" ]; then
    echo "every finding has exactly one triage row, and the committed triage.tsv matches those rows"
else
    echo "per-rule finding totals match the committed triage.tsv (per-finding triage not checked: triage.local.tsv is absent)"
fi
exit $failed
