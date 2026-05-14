#!/usr/bin/env python3
import argparse
import csv
import re
import unicodedata
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


def normalize_name_for_eval(name):
    """
    Normalise names for evaluation only.
    This does not affect the C++ matching result.
    """
    if name is None:
        return ""

    name = str(name)

    # Remove diacritics where possible
    name = unicodedata.normalize("NFKD", name)
    name = "".join(c for c in name if not unicodedata.combining(c))

    # Uppercase
    name = name.upper()

    # Convert punctuation/symbols to spaces
    name = re.sub(r"[^A-Z0-9]+", " ", name)

    # Collapse spaces
    name = re.sub(r"\s+", " ", name).strip()

    return name


def sorted_token_key(name):
    """
    Token-order-insensitive key.
    Useful for cases such as:
    JULEN ANE GUTIERREZ vs GUTIERREZ JULEN ANE
    """
    norm = normalize_name_for_eval(name)
    tokens = norm.split()
    tokens.sort()
    return " ".join(tokens)

def sorted_unique_token_key(name):
    """
    Token-order-insensitive and duplicate-token-insensitive key.
    Useful for cases such as:
    THOMAS THOMAS BROWN vs THOMAS BROWN
    EMINE EMINE DEMIR vs EMINE DEMIR
    """
    norm = normalize_name_for_eval(name)
    tokens = norm.split()
    tokens = sorted(set(tokens))
    return " ".join(tokens)


def fix_mojibake(s):
    """
    Fix common UTF-8 text decoded as Latin-1, e.g.
    LÃ©na -> Léna.
    If fixing fails, return original string.
    """
    if s is None:
        return ""
    s = str(s)
    try:
        fixed = s.encode("latin1").decode("utf-8")
        # Only use fixed version if it looks better
        if "Ã" in s or "Â" in s:
            return fixed
    except Exception:
        pass
    return s

def is_blank_name(name):
    return name is None or str(name).strip() == ""


def normalize_name_for_eval(name):
    """
    Normalise names for evaluation only.
    This does not affect the C++ matching result.
    """
    if name is None:
        return ""

    name = fix_mojibake(str(name))

    # Remove diacritics where possible
    name = unicodedata.normalize("NFKD", name)
    name = "".join(c for c in name if not unicodedata.combining(c))

    # Uppercase
    name = name.upper()

    # Convert punctuation/symbols to spaces
    name = re.sub(r"[^A-Z0-9]+", " ", name)

    # Collapse spaces
    name = re.sub(r"\s+", " ", name).strip()

    return name


def tokens_for_eval(name):
    return normalize_name_for_eval(name).split()


def sorted_token_key(name):
    tokens = tokens_for_eval(name)
    tokens.sort()
    return " ".join(tokens)


def sorted_unique_token_key(name):
    tokens = sorted(set(tokens_for_eval(name)))
    return " ".join(tokens)


def levenshtein_distance(a, b, max_dist=None):
    """
    Small edit-distance function with optional early stopping.
    """
    if a == b:
        return 0

    if max_dist is not None and abs(len(a) - len(b)) > max_dist:
        return max_dist + 1

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        row_min = curr[0]

        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(
                min(
                    prev[j] + 1,      # deletion
                    curr[j - 1] + 1,  # insertion
                    prev[j - 1] + cost,
                )
            )
            row_min = min(row_min, curr[-1])

        if max_dist is not None and row_min > max_dist:
            return max_dist + 1

        prev = curr

    return prev[-1]


def token_sets_have_subset_relation(tokens0, tokens1, min_shared=2):
    """
    Handles missing/extra middle-token cases:
    EMINE AZRA DEMIR vs EMINE DEMIR
    THOMAS THOMAS BROWN vs THOMAS BROWN after unique-token reduction.
    """
    set0 = set(tokens0)
    set1 = set(tokens1)

    if len(set0) < min_shared or len(set1) < min_shared:
        return False

    if set0.issubset(set1) or set1.issubset(set0):
        return True

    return False


def near_token_multiset_match(tokens0, tokens1, max_token_edit=1, min_token_len=4):
    """
    Token-order-insensitive near-token matching.

    Example with max_token_edit=1:
    JORI MOSHE vs JORI NOSHE

    Example with max_token_edit=2:
    BARBARA OLIVIA THOMAS vs THOMAS BARBARA OLIVER
    """
    if len(tokens0) != len(tokens1):
        return False

    # Work on sorted tokens to remove order dependence
    remaining = list(tokens1)
    used_near_match = False

    for t0 in tokens0:
        # Prefer exact match first
        if t0 in remaining:
            remaining.remove(t0)
            continue

        # Otherwise try one near-token match
        matched_idx = None
        for i, t1 in enumerate(remaining):
            if min(len(t0), len(t1)) < min_token_len:
                continue

            dist = levenshtein_distance(t0, t1, max_dist=max_token_edit)
            if dist <= max_token_edit:
                matched_idx = i
                used_near_match = True
                break

        if matched_idx is None:
            return False

        remaining.pop(matched_idx)

    return used_near_match and len(remaining) == 0


def is_equivalent_name(name0, name1, max_token_edit=1):
    """
    Decide whether a non-index match should be separated from real false positives.

    Returns:
        (True/False, reason)
    """
    norm0 = normalize_name_for_eval(name0)
    norm1 = normalize_name_for_eval(name1)

    if norm0 == norm1:
        return True, "exact_normalised_name"

    if sorted_token_key(name0) == sorted_token_key(name1):
        return True, "token_order_equivalent"

    if sorted_unique_token_key(name0) == sorted_unique_token_key(name1):
        return True, "duplicate_token_equivalent"

    tokens0 = tokens_for_eval(name0)
    tokens1 = tokens_for_eval(name1)

    if token_sets_have_subset_relation(tokens0, tokens1, min_shared=2):
        return True, "missing_or_extra_token"

    if near_token_multiset_match(
        tokens0,
        tokens1,
        max_token_edit=max_token_edit,
        min_token_len=4,
    ):
        return True, f"near_token_edit_distance_le_{max_token_edit}"

    return False, "possible_false_positive"


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Extract true positives, duplicate/equivalent-name matches, "
            "possible false positives, and missed true matches from ss_psi_opened_matches.csv."
        )
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
        "--true-positive-out",
        default="output/ss_psi_true_positives.csv",
        type=Path,
        help="Where to write opened rows whose party indices are the same.",
    )
    parser.add_argument(
        "--duplicate-out",
        default="output/ss_psi_equivalent_duplicate_matches.csv",
        type=Path,
        help="Where to write non-index matches that are equivalent after name normalisation.",
    )
    parser.add_argument(
        "--false-positive-out",
        default="output/ss_psi_false_positives.csv",
        type=Path,
        help="Where to write non-index matches that are not equivalent after name normalisation.",
    )
    parser.add_argument(
        "--missed-out",
        default="output/ss_psi_missed_true_matches.csv",
        type=Path,
        help="Where to write true same-index pairs that were not opened.",
    )
    parser.add_argument(
        "--summary-out",
        default="output/ss_psi_eval_summary.csv",
        type=Path,
        help="Where to write evaluation summary.",
    )
    parser.add_argument(
    "--max-token-edit",
    default=1,
    type=int,
    help=(
        "Maximum edit distance allowed for one token-level typo in equivalent-name classification. "
        "Use 1 for strict one-character typo; use 2 to include cases such as OLIVIA vs OLIVER."
    ),
    )
    return parser.parse_args()


def enrich_match_row(row):
    party0_name = row.get("party0_name", "")
    party1_name = row.get("party1_name", "")

    row = dict(row)
    row["party0_norm_eval"] = normalize_name_for_eval(party0_name)
    row["party1_norm_eval"] = normalize_name_for_eval(party1_name)
    row["party0_sorted_key_eval"] = sorted_token_key(party0_name)
    row["party1_sorted_key_eval"] = sorted_token_key(party1_name)
    row["party0_unique_token_key_eval"] = sorted_unique_token_key(party0_name)
    row["party1_unique_token_key_eval"] = sorted_unique_token_key(party1_name)
    return row


def main():
    args = parse_args()

    matches = read_csv(args.matches)
    clean_rows = read_csv(args.clean)
    fuzzy_rows = read_csv(args.fuzzy)

    if not matches:
        print("No opened matches found.")
        return

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

    true_positives = []
    equivalent_duplicates = []
    possible_false_positives = []

    for row in matches:
        if row["party0_index"] == row["party1_index"]:
            enriched = enrich_match_row(row)
            enriched["equivalence_reason"] = "index_match"
            true_positives.append(enriched)
            continue

        enriched = enrich_match_row(row)

        is_equiv, reason = is_equivalent_name(
            row.get("party0_name", ""),
            row.get("party1_name", ""),
            max_token_edit=args.max_token_edit,
        )

        enriched["equivalence_reason"] = reason

        if is_equiv:
            equivalent_duplicates.append(enriched)
        else:
            possible_false_positives.append(enriched)

    true_opened_indices = {row["party0_index"] for row in true_positives}

    # -------------------------------------------------
    # Build the set of valid expected records.
    # Empty-name records are intentionally excluded from matching,
    # so they should not be counted as missed true matches.
    # -------------------------------------------------
    valid_expected_indices = set()

    for index in range(n_records):
        clean = clean_rows[index] if index < len(clean_rows) else {}
        fuzzy = fuzzy_rows[index] if index < len(fuzzy_rows) else {}

        clean_name = clean.get("full_name_romanised", "")
        fuzzy_name = fuzzy.get("fuzzy_name", "")

        if is_blank_name(clean_name) or is_blank_name(fuzzy_name):
            continue

        valid_expected_indices.add(index)

    missed = []
    for index in sorted(valid_expected_indices):
        if index in true_opened_indices:
            continue

        clean = clean_rows[index] if index < len(clean_rows) else {}
        fuzzy = fuzzy_rows[index] if index < len(fuzzy_rows) else {}

        clean_name = clean.get("full_name_romanised", "")
        fuzzy_name = fuzzy.get("fuzzy_name", "")

        # Empty records are excluded from matching, so do not count them as missed.
        if is_blank_name(clean_name) or is_blank_name(fuzzy_name):
            continue

        if index in true_opened_indices:
            continue

        missed.append(
            {
                "index": index,
                "record_id": fuzzy.get("record_id", clean.get("record_id", "")),
                "clean_name": clean_name,
                "fuzzy_name": fuzzy_name,
                "original_name": fuzzy.get("original_name", ""),
                "error_type": fuzzy.get("error_type", ""),
                "is_noisy": fuzzy.get("is_noisy", ""),
                "clean_norm_eval": normalize_name_for_eval(clean_name),
                "fuzzy_norm_eval": normalize_name_for_eval(fuzzy_name),
                "clean_sorted_key_eval": sorted_token_key(clean_name),
                "fuzzy_sorted_key_eval": sorted_token_key(fuzzy_name),
            }
        )

    # Fieldnames for opened-match outputs
    # Fieldnames for opened-match outputs
    base_fieldnames = list(enrich_match_row(matches[0]).keys())

    extra_fields = ["equivalence_reason"]   

    match_fieldnames = base_fieldnames.copy()
    for field in extra_fields:
        if field not in match_fieldnames:
            match_fieldnames.append(field)

    # Make sure all rows contain all fields
    for rows in [true_positives, equivalent_duplicates, possible_false_positives]:
        for row in rows:
            for field in match_fieldnames:
                row.setdefault(field, "")

    write_csv(args.true_positive_out, true_positives, match_fieldnames)
    write_csv(args.duplicate_out, equivalent_duplicates, match_fieldnames)
    write_csv(args.false_positive_out, possible_false_positives, match_fieldnames)

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
            "clean_norm_eval",
            "fuzzy_norm_eval",
            "clean_sorted_key_eval",
            "fuzzy_sorted_key_eval",
        ],
    )

    opened_total = len(matches)
    tp = len(true_positives)
    dup = len(equivalent_duplicates)
    fp = len(possible_false_positives)
    missed_count = len(missed)

    strict_precision = tp / opened_total if opened_total else 0.0
    valid_expected_count = len(valid_expected_indices)
    strict_recall = tp / valid_expected_count if valid_expected_count else 0.0
    strict_f1 = (
        2 * strict_precision * strict_recall / (strict_precision + strict_recall)
        if strict_precision + strict_recall
        else 0.0
    )

    adjusted_precision = (tp + dup) / opened_total if opened_total else 0.0
    adjusted_f1 = (
        2 * adjusted_precision * strict_recall / (adjusted_precision + strict_recall)
        if adjusted_precision + strict_recall
        else 0.0
    )

    summary = [
        {
            "evaluated_records": n_records,
            "opened_candidate_pairs": opened_total,
            "true_positives_index_match": tp,
            "equivalent_duplicate_name_matches": dup,
            "possible_false_positives": fp,
            "missed_true_matches": missed_count,
            "strict_precision": f"{strict_precision:.6f}",
            "strict_recall": f"{strict_recall:.6f}",
            "strict_f1": f"{strict_f1:.6f}",
            "adjusted_precision_including_equivalent_duplicates": f"{adjusted_precision:.6f}",
            "adjusted_f1_including_equivalent_duplicates": f"{adjusted_f1:.6f}",
            "strict_false_discovery_rate": f"{(fp + dup) / opened_total:.6f}" if opened_total else "0.000000",
            "possible_false_discovery_rate": f"{fp / opened_total:.6f}" if opened_total else "0.000000",
            "valid_expected_records": valid_expected_count,
            "false_negative_rate": f"{missed_count / valid_expected_count:.6f}" if valid_expected_count else "0.000000",
        }
    ]

    write_csv(
        args.summary_out,
        summary,
        [
            "evaluated_records",
            "opened_candidate_pairs",
            "true_positives_index_match",
            "equivalent_duplicate_name_matches",
            "possible_false_positives",
            "missed_true_matches",
            "strict_precision",
            "strict_recall",
            "strict_f1",
            "adjusted_precision_including_equivalent_duplicates",
            "adjusted_f1_including_equivalent_duplicates",
            "strict_false_discovery_rate",
            "possible_false_discovery_rate",
            "valid_expected_records",
            "false_negative_rate",
        ],
    )

    print(f"Evaluated records: {n_records}")
    print(f"Opened candidate pairs: {opened_total}")
    print(f"True positives/index matches: {tp}")
    print(f"Equivalent duplicate-name matches: {dup}")
    print(f"Possible false positives: {fp}")
    print(f"Missed true matches: {missed_count}")
    print(f"Strict precision: {strict_precision:.4f}")
    print(f"Strict recall: {strict_recall:.4f}")
    print(f"Strict F1: {strict_f1:.4f}")
    print(f"Adjusted precision including equivalent duplicates: {adjusted_precision:.4f}")
    print(f"Adjusted F1 including equivalent duplicates: {adjusted_f1:.4f}")
    print()
    print(f"Wrote true positives: {args.true_positive_out}")
    print(f"Wrote equivalent duplicate matches: {args.duplicate_out}")
    print(f"Wrote possible false positives: {args.false_positive_out}")
    print(f"Wrote missed true matches: {args.missed_out}")
    print(f"Wrote summary: {args.summary_out}")


if __name__ == "__main__":
    main()