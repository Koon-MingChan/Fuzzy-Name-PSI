#include <cassert>
#include <cmath>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <vector>

#include "name_encoding.h"
#include "rlc.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>

using namespace std;
using namespace approx_psi;
using BitVector = approx_psi::BitVector;

// Global Constants for the Approx-PSI Pipeline
const int L_BIT_LENGTH = 8192;
const int GRAM_SIZE = 3;
const int HAMMING_D = 5;
const int GAP_T = 10;
const int N_ELEMENTS = 100;
const int K_ROUNDS = 40;

using BinaryVector = vector<int>;

struct PlainRecord {
    size_t index;
    string name;
    BitVector encoded;
};

string to_binary_string(const BinaryVector& v) {
    string s;
    s.reserve(v.size());
    for (int bit : v) s.push_back(bit ? '1' : '0');
    return s;
}

BinaryVector from_determined_bitvector(const BitVector& bv, size_t out_len) {
    BinaryVector out(out_len);
    for (size_t i = 0; i < out_len; ++i) {
        out[i] = (i < bv.size() && bv[i]) ? 1 : 0;
    }
    return out;
}

size_t compute_hash_commitment(uint64_t seed) {
    hash<uint64_t> hasher;
    return hasher(seed);
}

uint64_t execute_coin_toss() {
    cout << "\n--- Executing Secure Coin Tossing for Joint Randomness ---\n";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint64_t> seed_dist(1, UINT64_MAX);

    uint64_t s_A = seed_dist(gen);
    size_t commitment_A = compute_hash_commitment(s_A);
    cout << "Party A: Generated Secret Seed s_A.\n";
    cout << "Party A -> Party B: Hash Commitment (H(s_A)) = " << hex << commitment_A << dec << "\n";

    uint64_t s_B = seed_dist(gen);
    cout << "Party B: Generated Secret Seed s_B = " << hex << s_B << dec << "\n";
    cout << "Party B -> Party A: s_B\n";

    cout << "Party A -> Party B: Reveals s_A = " << hex << s_A << dec << "\n";

    assert(compute_hash_commitment(s_A) == commitment_A && "Commitment failure! Party A cheated.");
    cout << "Party B: Verified Hash Commitment.\n";

    uint64_t joint_seed = s_A ^ s_B;
    cout << "Both Parties: Derived Shared Joint Seed = " << hex << joint_seed << dec << "\n\n";

    return joint_seed;
}

vector<vector<size_t>> generate_projections_from_seed(uint64_t joint_seed, int L_size, int d, int t, int n, int k_rounds) {
    double base = n * t;
    double exponent = 1.0 / (d * (t - 1.0));
    double p = 1.0 - (1.0 / pow(base, exponent));

    mt19937_64 synchronized_prg(joint_seed);
    uniform_real_distribution<> dis(0.0, 1.0);

    vector<vector<size_t>> projections;
    while (projections.size() < static_cast<size_t>(k_rounds)) {
        vector<size_t> current_proj;
        for (int j = 0; j < L_size; ++j) {
            if (dis(synchronized_prg) <= p) {
                current_proj.push_back(static_cast<size_t>(j));
            }
        }
        if (current_proj.size() > static_cast<size_t>(L_size * p * 0.5)) {
            projections.push_back(current_proj);
        }
    }
    return projections;
}

vector<PlainRecord> build_records(const vector<string>& names, const NameEncoding& encoder) {
    vector<PlainRecord> records;
    records.reserve(names.size());
    for (size_t i = 0; i < names.size(); ++i) {
        records.push_back(PlainRecord{
            i,
            names[i],
            //encoder.encode_name_tail_token(names[i])
            encoder.encode_name_token_or(names[i])
        });
    }
    return records;
}

void write_party_section(ofstream& fout,
                         const char* header,
                         const vector<PlainRecord>& records,
                         const vector<size_t>& mask,
                         const ProjectionConsistencyCheck& rlc_checker) {
    fout << header << "\n";
    for (const auto& record : records) {
        BitVector projected;
        projected.resize(mask.size());

        for (size_t i = 0; i < mask.size(); ++i) {
            projected[i] = record.encoded[mask[i]];
        }

        if (!rlc_checker.verify_projection(record.encoded, projected, mask)) {
            throw runtime_error(string("RLC Verification Failed for ") + header + ", record " + to_string(record.index));
        }

        fout << record.index
             << "\t" << quoted(record.name)
             << "\t" << projected
             << "\t" << record.encoded
             << "\n";
    }
}

int main() {
    cout << "--- Starting Full Name-to-PSI Pipeline Simulation ---\n";

    NameEncodingConfig enc_cfg{L_BIT_LENGTH, GRAM_SIZE};
    NameEncoding encoder(enc_cfg);

    uint64_t shared_seed = execute_coin_toss();
    ProjectionConsistencyCheck rlc_checker(shared_seed);

    // Two independent party datasets to better simulate bank-to-bank fuzzy PSI.
    vector<string> party0_names = {
        "ALEXANDER-SMITH JONATHAN",
        "LEE CHING-WAI",
        "GARCIA-LORENZ MARIA ELENA",
        "ABDUL RAHMAN BIN AZIZ",
        "CATHERINE ZETA-JONES",
        "MUHAMMAD AL-FARISI",
        "ELIZABETH HIGGINS",
        "NICHOLAS BROOKS",
        "WILLIAM ROBERT THORNTON",
        "CHRISTOPHER P. LOWE",
        "SOPHIA ISABELLA RODRIGUEZ",
        "LIAN WEI",
        "O'CONNOR SHAUN",
        "JONATHAN SMITH",
        "LI WEI MING",
        "BENJAMIN FRANKLIN",
        "DAISY MILLER",
        "PETER PARKER"
    };

    vector<string> party1_names = {
        "JONATHAN ALEXANDER SMITH",
        "CHING WAI LEE",
        "MARIA ELENA GARCIA LORENZ",
        "AZIZ ABDUL RAHMAN",
        "KATHERINE ZETA JONES",
        "MOHAMMAD AL FARISI",
        "ELISABETH HIGGINS",
        "NICKOLAS BROOKS",
        "WM ROBERT THORNTON",
        "CHRISTOPHER PAUL LOWE",
        "SOPHIA I. RODRIGUEZ",
        "LIAN  WEI",
        "OCONNOR SHAUN",
        "JENNIFER SMITH",
        "LI WEI KANG",
        "BEN F",
        "THOMAS ANDERSON",
        "BRUCE WAYNE"
    };

    auto party0_records = build_records(party0_names, encoder);
    auto party1_records = build_records(party1_names, encoder);

    auto masks = generate_projections_from_seed(
        shared_seed,
        L_BIT_LENGTH,
        HAMMING_D,
        GAP_T,
        static_cast<int>(max(party0_records.size(), party1_records.size())),
        K_ROUNDS);

    for (int k = 0; k < K_ROUNDS; ++k) {
        ofstream fout("sspsi_round_" + to_string(k) + ".txt");
        if (!fout) {
            throw runtime_error("Unable to create round file for round " + to_string(k));
        }

        write_party_section(fout, "#A", party0_records, masks[k], rlc_checker);
        write_party_section(fout, "#B", party1_records, masks[k], rlc_checker);
    }

    cout << "Generated " << K_ROUNDS << " rounds of projected records for:\n";
    cout << "  Party 0 dataset size: " << party0_records.size() << "\n";
    cout << "  Party 1 dataset size: " << party1_records.size() << "\n";
    cout << "Pipeline Setup Complete. Data ready for ss_psi execution.\n";
    return 0;
}
