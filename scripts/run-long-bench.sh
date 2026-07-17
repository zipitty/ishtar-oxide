#!/usr/bin/env bash
set -u
set -o pipefail

BASE_URL="http://127.0.0.1:3301"
OUTPUT_DIR="reports/long-run"
ROUNDS=5
START_SEED=1
PROFILES_CSV="attacker-favorable,realistic,sub-ms-overlap,many-sessions"
RETRIES=3
RETRY_DELAY_SECONDS=10
BUILD=1
BENCH_BINARY="target/release/ishtar-bench-client"

usage() {
  printf '%s\n' \
    "Usage: scripts/run-long-bench.sh [options]" \
    "" \
    "Runs matched signal/control pairs and preserves every raw report." \
    "Completed reports are skipped, so rerunning the command resumes a campaign." \
    "" \
    "Options:" \
    "  --base-url URL          Verified proxy URL (default: $BASE_URL)" \
    "  --output-dir DIR        Campaign directory (default: $OUTPUT_DIR)" \
    "  --rounds N              Seeds to run; 0 runs until interrupted (default: $ROUNDS)" \
    "  --start-seed N          First seed (default: $START_SEED)" \
    "  --profiles CSV          Profile IDs (default: $PROFILES_CSV)" \
    "  --retries N             Attempts per failed run (default: $RETRIES)" \
    "  --retry-delay SECONDS   Delay between attempts (default: $RETRY_DELAY_SECONDS)" \
    "  --binary PATH           Benchmark client path (default: $BENCH_BINARY)" \
    "  --no-build              Do not build the release client first" \
    "  -h, --help              Show this help"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_uint() {
  case "$2" in
    ''|*[!0-9]*) die "$1 must be a non-negative integer" ;;
  esac
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --base-url) [ "$#" -ge 2 ] || die "--base-url requires a value"; BASE_URL=$2; shift 2 ;;
    --output-dir) [ "$#" -ge 2 ] || die "--output-dir requires a value"; OUTPUT_DIR=$2; shift 2 ;;
    --rounds) [ "$#" -ge 2 ] || die "--rounds requires a value"; require_uint "$1" "$2"; ROUNDS=$2; shift 2 ;;
    --start-seed) [ "$#" -ge 2 ] || die "--start-seed requires a value"; require_uint "$1" "$2"; START_SEED=$2; shift 2 ;;
    --profiles) [ "$#" -ge 2 ] || die "--profiles requires a value"; PROFILES_CSV=$2; shift 2 ;;
    --retries) [ "$#" -ge 2 ] || die "--retries requires a value"; require_uint "$1" "$2"; RETRIES=$2; shift 2 ;;
    --retry-delay) [ "$#" -ge 2 ] || die "--retry-delay requires a value"; require_uint "$1" "$2"; RETRY_DELAY_SECONDS=$2; shift 2 ;;
    --binary) [ "$#" -ge 2 ] || die "--binary requires a value"; BENCH_BINARY=$2; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[ -n "${LAB_ADMIN_TOKEN:-}" ] || die "LAB_ADMIN_TOKEN must be exported"
[ "$RETRIES" -ge 1 ] || die "--retries must be at least 1"
command -v jq >/dev/null 2>&1 || die "jq is required to validate and summarize reports"

if [ "$BUILD" -eq 1 ]; then
  cargo build --release -p ishtar-bench-client || die "release client build failed"
fi
[ -x "$BENCH_BINARY" ] || die "benchmark client is not executable: $BENCH_BINARY"

REPORT_DIR="$OUTPUT_DIR/reports"
SUMMARY_PATH="$OUTPUT_DIR/summary.json"
mkdir -p "$REPORT_DIR" || die "cannot create output directory"

summarize() {
  set -- "$REPORT_DIR"/*.json
  if [ ! -e "$1" ]; then
    return
  fi
  summary_tmp="$SUMMARY_PATH.tmp"
  if jq -c -f scripts/compact-long-bench.jq "$@" \
    | jq -s -f scripts/summarize-long-bench.jq > "$summary_tmp"; then
    mv "$summary_tmp" "$SUMMARY_PATH"
    printf 'updated %s\n' "$SUMMARY_PATH"
  else
    printf 'warning: could not update %s\n' "$SUMMARY_PATH" >&2
  fi
}

interrupted=0
on_interrupt() {
  interrupted=1
  printf '\ninterrupted; preserving completed reports\n' >&2
}
trap on_interrupt INT TERM

run_one() {
  profile=$1
  seed=$2
  mode=$3
  final_path="$REPORT_DIR/${profile}-${mode}-seed-${seed}.json"
  temp_path="$final_path.tmp"

  if [ -f "$final_path" ]; then
    if jq -e --arg profile "$profile" --arg mode "$mode" --argjson seed "$seed" '
      .profile_id == $profile
      and .seed == $seed
      and .control == ($mode == "control")
      and .run_info.completed == true
      and .run_info.records_dropped == 0
    ' "$final_path" >/dev/null; then
      printf 'skip completed %s %s seed %s\n' "$profile" "$mode" "$seed"
      return 0
    fi
    die "existing report is invalid or mismatched: $final_path"
  fi

  attempt=1
  while [ "$attempt" -le "$RETRIES" ]; do
    printf 'run %s %s seed %s (attempt %s/%s)\n' \
      "$profile" "$mode" "$seed" "$attempt" "$RETRIES"
    if [ "$mode" = "control" ]; then
      "$BENCH_BINARY" run \
        --base-url "$BASE_URL" \
        --profile "$profile" \
        --seed "$seed" \
        --control \
        --output "$temp_path"
    else
      "$BENCH_BINARY" run \
        --base-url "$BASE_URL" \
        --profile "$profile" \
        --seed "$seed" \
        --output "$temp_path"
    fi
    status=$?

    if [ "$status" -eq 0 ] && jq -e --arg profile "$profile" --arg mode "$mode" --argjson seed "$seed" '
      .profile_id == $profile
      and .seed == $seed
      and .control == ($mode == "control")
      and .run_info.completed == true
      and .run_info.records_dropped == 0
    ' "$temp_path" >/dev/null; then
      mv "$temp_path" "$final_path"
      summarize
      return 0
    fi

    printf 'warning: %s %s seed %s failed\n' "$profile" "$mode" "$seed" >&2
    if [ "$interrupted" -ne 0 ]; then
      return 130
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -le "$RETRIES" ]; then
      sleep "$RETRY_DELAY_SECONDS"
    fi
  done
  return 1
}

OLD_IFS=$IFS
IFS=','
set -- $PROFILES_CSV
IFS=$OLD_IFS
[ "$#" -gt 0 ] || die "at least one profile is required"
PROFILES=("$@")

round=0
failures=0
while [ "$ROUNDS" -eq 0 ] || [ "$round" -lt "$ROUNDS" ]; do
  seed=$((START_SEED + round))
  for profile in "${PROFILES[@]}"; do
    [ "$interrupted" -eq 0 ] || break 2
    if [ $((seed % 2)) -eq 0 ]; then
      modes=(control signal)
    else
      modes=(signal control)
    fi
    for mode in "${modes[@]}"; do
      [ "$interrupted" -eq 0 ] || break 3
      if ! run_one "$profile" "$seed" "$mode"; then
        failures=$((failures + 1))
      fi
    done
  done
  round=$((round + 1))
done

summarize
if [ "$interrupted" -ne 0 ]; then
  exit 130
fi
if [ "$failures" -ne 0 ]; then
  die "$failures benchmark run(s) exhausted all retries"
fi
printf 'campaign complete: %s\n' "$OUTPUT_DIR"
