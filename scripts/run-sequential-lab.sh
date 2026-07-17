#!/usr/bin/env bash
set -eu

BASE_URL=${BASE_URL:-http://127.0.0.1:8081}
OUTPUT_DIR=${OUTPUT_DIR:-reports/sequential}
ROUNDS=${ROUNDS:-5}
TRIALS=${TRIALS:-1200}
START_SEED=${START_SEED:-1}
BINARY=${BINARY:-target/release/ishtar-sequential-lab}

if [ -z "${LAB_ADMIN_TOKEN:-}" ]; then
  printf '%s\n' 'LAB_ADMIN_TOKEN must be set' >&2
  exit 1
fi

cargo build --release -p ishtar-sequential-lab
mkdir -p "$OUTPUT_DIR"

round=0
while [ "$round" -lt "$ROUNDS" ]; do
  seed=$((START_SEED + round))
  if [ $((seed % 2)) -eq 0 ]; then
    modes='control signal'
  else
    modes='signal control'
  fi
  for mode in $modes; do
    output="$OUTPUT_DIR/$mode-seed-$seed.json"
    if [ -f "$output" ]; then
      printf 'skip existing %s\n' "$output"
      continue
    fi
    if [ "$mode" = control ]; then
      "$BINARY" bench --base-url "$BASE_URL" --trials "$TRIALS" \
        --seed "$seed" --control --output "$output"
    else
      "$BINARY" bench --base-url "$BASE_URL" --trials "$TRIALS" \
        --seed "$seed" --output "$output"
    fi
  done
  round=$((round + 1))
done

printf 'completed matched reports in %s\n' "$OUTPUT_DIR"
