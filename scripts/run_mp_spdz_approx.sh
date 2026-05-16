#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MP_SPDZ_DIR="${MP_SPDZ_DIR:-"$PROJECT_DIR/../MP-SPDZ"}"
DISK_MEMORY_DIR="${MP_SPDZ_DISK_MEMORY_DIR:-"$MP_SPDZ_DIR/Player-Data/disk-memory"}"
MP_BATCH_SIZE="${MP_SPDZ_BATCH_SIZE:-1}"
CANDIDATES_PER_BATCH="${MPC_CANDIDATES_PER_BATCH:-10000}"
START_BATCH="${MPC_START_BATCH:-0}"
STOP_AFTER_BATCH="${MPC_STOP_AFTER_BATCH:-}"

CONFIG_SRC="$PROJECT_DIR/output/mp_spdz/approx_psi_config.mpc"
INPUT0_SRC="$PROJECT_DIR/output/mp_spdz/Player-Data/Input-P0-0"
INPUT1_SRC="$PROJECT_DIR/output/mp_spdz/Player-Data/Input-P1-0"
RUN_LOG_DIR="$PROJECT_DIR/output/mp_spdz/logs"
MATCH_ID_FILE="$PROJECT_DIR/output/mp_spdz/matched_candidate_ids.txt"

read_config_value() {
  local key="$1"
  awk -F '=' -v key="$key" '$1 ~ "^[[:space:]]*" key "[[:space:]]*$" { gsub(/[[:space:]]/, "", $2); print $2 }' "$CONFIG_SRC"
}

TOTAL_CANDIDATES="$(read_config_value MAX_CANDIDATES)"
PAYLOAD_BITS="$(read_config_value PAYLOAD_BITS)"
CHUNK_BITS="$(read_config_value CHUNK_BITS)"
PAYLOAD_CHUNKS="$(read_config_value PAYLOAD_CHUNKS)"
HAMMING_D="$(read_config_value HAMMING_D)"
LINES_PER_CANDIDATE=$((PAYLOAD_CHUNKS + 1))
TOTAL_BATCHES=$(((TOTAL_CANDIDATES + CANDIDATES_PER_BATCH - 1) / CANDIDATES_PER_BATCH))

mkdir -p "$MP_SPDZ_DIR/Programs/Source"
mkdir -p "$MP_SPDZ_DIR/Player-Data"
mkdir -p "$DISK_MEMORY_DIR"
mkdir -p "$RUN_LOG_DIR"

cp "$PROJECT_DIR/approx_psi.mpc" \
   "$MP_SPDZ_DIR/Programs/Source/approx_psi.mpc"

if [[ "$START_BATCH" == "0" ]]; then
  : > "$MATCH_ID_FILE"
fi

echo "Total candidates: $TOTAL_CANDIDATES"
echo "Candidates per batch: $CANDIDATES_PER_BATCH"
echo "Total batches: $TOTAL_BATCHES"
echo "MP-SPDZ dir: $MP_SPDZ_DIR"

for ((batch = START_BATCH; batch < TOTAL_BATCHES; ++batch)); do
  if [[ -n "$STOP_AFTER_BATCH" && "$batch" -gt "$STOP_AFTER_BATCH" ]]; then
    break
  fi

  offset=$((batch * CANDIDATES_PER_BATCH))
  remaining=$((TOTAL_CANDIDATES - offset))
  batch_candidates=$CANDIDATES_PER_BATCH
  if (( remaining < batch_candidates )); then
    batch_candidates=$remaining
  fi

  start_line=$((offset * LINES_PER_CANDIDATE + 1))
  line_count=$((batch_candidates * LINES_PER_CANDIDATE))

  echo "Batch $batch/$((TOTAL_BATCHES - 1)): offset=$offset candidates=$batch_candidates"

  sed -n "${start_line},$((start_line + line_count - 1))p" "$INPUT0_SRC" \
    > "$MP_SPDZ_DIR/Player-Data/Input-P0-0"
  sed -n "${start_line},$((start_line + line_count - 1))p" "$INPUT1_SRC" \
    > "$MP_SPDZ_DIR/Player-Data/Input-P1-0"

  cat > "$MP_SPDZ_DIR/Programs/Source/approx_psi_config.mpc" <<EOF_CONFIG
PAYLOAD_BITS = $PAYLOAD_BITS
CHUNK_BITS = $CHUNK_BITS
PAYLOAD_CHUNKS = $PAYLOAD_CHUNKS
HAMMING_D = $HAMMING_D
CANDIDATE_OFFSET = $offset
MAX_CANDIDATES = $batch_candidates
EOF_CONFIG

  (
    cd "$MP_SPDZ_DIR"
    ./compile.py approx_psi
    Scripts/mascot.sh approx_psi \
      --disk-memory "$DISK_MEMORY_DIR" \
      --batch-size "$MP_BATCH_SIZE"
  ) 2>&1 | tee "$RUN_LOG_DIR/approx_psi_batch_${batch}.log"

  grep -hEo 'MATCH candidate_id=[0-9]+' "$RUN_LOG_DIR/approx_psi_batch_${batch}.log" \
    | sed 's/[^0-9]//g' >> "$MATCH_ID_FILE" || true
done

sort -n -u "$MATCH_ID_FILE" -o "$MATCH_ID_FILE"
python3 "$PROJECT_DIR/scripts/mp_spdz_matches_to_csv.py"

echo "Matched candidate ids: $MATCH_ID_FILE"
echo "Final MPC match CSV: $PROJECT_DIR/output/mpc_fuzzy_matches_from_mpc.csv"
