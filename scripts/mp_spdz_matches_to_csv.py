#!/usr/bin/env python3
import csv
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
MANIFEST = PROJECT_DIR / "output" / "mpc_fuzzy_mpc_candidates.csv"
MATCH_IDS = PROJECT_DIR / "output" / "mp_spdz" / "matched_candidate_ids.txt"
OUTPUT = PROJECT_DIR / "output" / "mpc_fuzzy_matches_from_mpc.csv"


def load_match_ids(path: Path) -> set[int]:
    if not path.exists():
        return set()

    out: set[int] = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        out.add(int(line))
    return out


def main() -> None:
    match_ids = load_match_ids(MATCH_IDS)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with MANIFEST.open(newline="") as fin, OUTPUT.open("w", newline="") as fout:
        reader = csv.DictReader(fin)
        fieldnames = [
            "round",
            "party0_index",
            "party0_name",
            "party1_index",
            "party1_name",
            "proj_dist",
            "payload_dist",
        ]
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            candidate_id = int(row["candidate_id"])
            if candidate_id not in match_ids:
                continue

            writer.writerow({
                "round": row["round"],
                "party0_index": row["party0_index"],
                "party0_name": row["party0_name"],
                "party1_index": row["party1_index"],
                "party1_name": row["party1_name"],
                "proj_dist": row["proj_dist"],
                # The MPC stage reveals only the match bit. It intentionally
                # does not reveal the Hamming distance.
                "payload_dist": -1,
            })

    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
