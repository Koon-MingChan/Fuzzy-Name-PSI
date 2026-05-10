#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract false positives and missed true matches from ss_psi_opened_matches.csv."
    )
    parser.add_argument(
        "--matches",
        default="output/ss_psi_opened_matches.csv",
        type=Path,
        help="Opened matches CSV produced by ss_psi.",
    )
    parser.add_argument(
        "--fuzzy",
        default="output/fuzzy_names.csv",
        type=Path,
        help="Fuzzy names CSV used as party1 / noisy records.",
    )
    parser.add_argument(
        "--clean",
        default="output/clean_names.csv",
        type=Path,
        help="Clean names CSV used as party0 / original records.",
    )
    parser.add_argument(
        "--n",
        default=None,
        type=int,
        help="Number of records evaluated. Defaults to max opened index + 1.",
    )
    parser.add_argument(
        "--false-positive-out",
        default="output/ss_psi_false_positives.csv",
        type=Path,
        help="Where to write opened rows whose party indices differ.",
    )
    parser.add_argument(
        "--missed-out",
        default="output/ss_psi_missed_true_matches.csv",
        type=Path,
        help="Where to write true same-index pairs that were not opened.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    matches = read_csv(args.matches)
    clean_rows = read_csv(args.clean)
    fuzzy_rows = read_csv(args.fuzzy)

    for row in matches:
        row["party0_index"] = int(row["party0_index"])
        row["party1_index"] = int(row["party1_index"])

    if args.n is None:
        max_index = max(
            max(row["party0_index"], row["party1_index"]) for row in matches
        )
        n_records = max_index + 1
    else:
        n_records = args.n

    false_positives = [
        row for row in matches if row["party0_index"] != row["party1_index"]
    ]
    true_opened_indices = {
        row["party0_index"]
        for row in matches
        if row["party0_index"] == row["party1_index"]
    }

    missed = []
    for index in range(n_records):
        if index in true_opened_indices:
            continue

        clean = clean_rows[index] if index < len(clean_rows) else {}
        fuzzy = fuzzy_rows[index] if index < len(fuzzy_rows) else {}
        missed.append(
            {
                "index": index,
                "record_id": fuzzy.get("record_id", clean.get("record_id", "")),
                "clean_name": clean.get("full_name_romanised", ""),
                "fuzzy_name": fuzzy.get("fuzzy_name", ""),
                "original_name": fuzzy.get("original_name", ""),
                "error_type": fuzzy.get("error_type", ""),
                "is_noisy": fuzzy.get("is_noisy", ""),
            }
        )

    write_csv(args.false_positive_out, false_positives, matches[0].keys())
    write_csv(
        args.missed_out,
        missed,
        [
            "index",
            "record_id",
            "clean_name",
            "fuzzy_name",
            "original_name",
            "error_type",
            "is_noisy",
        ],
    )

    true_positive_count = len([row for row in matches if row["party0_index"] == row["party1_index"]])
    precision = true_positive_count / len(matches) if matches else 0.0
    recall = len(true_opened_indices) / n_records if n_records else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    print(f"Evaluated records: {n_records}")
    print(f"Opened candidate pairs: {len(matches)}")
    print(f"True positives: {true_positive_count}")
    print(f"False positives: {len(false_positives)}")
    print(f"Missed true matches: {len(missed)}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1: {f1:.4f}")
    print(f"Wrote false positives: {args.false_positive_out}")
    print(f"Wrote missed true matches: {args.missed_out}")


if __name__ == "__main__":
    main()
