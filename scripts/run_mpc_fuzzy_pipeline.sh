#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADDRESS="${MPC_FUZZY_ADDRESS:-127.0.0.1:1212}"
N_RECORDS="${MPC_EVAL_N:-2000}"
MAX_TOKEN_EDIT="${MPC_EVAL_MAX_TOKEN_EDIT:-1}"

cd "$PROJECT_DIR"

echo "== Build local_compute and mpc_fuzzy_psi =="
cmake --build build --target local_compute mpc_fuzzy_psi

echo "== Generate projected round files =="
./build/local_compute

echo "== Run MPC candidate generation =="
./build/mpc_fuzzy_psi 0 "$ADDRESS" > party0.log 2>&1 &
party0_pid=$!

cleanup() {
  if kill -0 "$party0_pid" >/dev/null 2>&1; then
    kill "$party0_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

sleep 1
./build/mpc_fuzzy_psi 1 "$ADDRESS" > party1.log 2>&1
wait "$party0_pid"
trap - EXIT

echo "== Candidate-generation summary =="
cat output/mpc_fuzzy_summary.txt
wc -l output/mpc_fuzzy_mpc_candidates.csv
wc -l output/mp_spdz/Player-Data/Input-P0-0 output/mp_spdz/Player-Data/Input-P1-0

echo "== Run MP-SPDZ secure Hamming filter =="
./scripts/run_mp_spdz_approx.sh 2>&1 | tee mp_spdz_approx.log

echo "== Evaluate final MPC output =="
python3 evaluate_ss_psi.py \
  --matches output/mpc_fuzzy_matches_from_mpc.csv \
  --n "$N_RECORDS" \
  --max-token-edit "$MAX_TOKEN_EDIT" \
  --summary-out output/mpc_fuzzy_eval_summary.csv \
  --true-positive-out output/mpc_fuzzy_true_positives.csv \
  --duplicate-out output/mpc_fuzzy_equivalent_duplicate_matches.csv \
  --false-positive-out output/mpc_fuzzy_false_positives.csv \
  --missed-out output/mpc_fuzzy_missed_true_matches.csv

echo "== Final MPC evaluation summary =="
cat output/mpc_fuzzy_eval_summary.csv
