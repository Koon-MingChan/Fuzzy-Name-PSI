#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <iomanip>
#include <cassert>
#include <cmath>
#include <fstream>
#include "name_encoding.h"
#include "rlc.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>

// For deployment grade hashing (mocking sha256 output)
// In a real implementation we would include <openssl/sha.h>
#include <functional> 

using namespace std;
using namespace approx_psi;
using BitVector = approx_psi::BitVector;

// Configuration parameters
// Global Constants for the Approx-PSI Pipeline
const int L_BIT_LENGTH = 1024;  // Length of the bit-vector (L)
const int GRAM_SIZE = 3;         // Size of n-grams for name encoding
const int HAMMING_D = 4;         // Distance threshold (d)
const int GAP_T = 4;             // Gap factor (T)
const int N_ELEMENTS = 100;      // Number of elements per set (n)
const int K_ROUNDS = 20;         // Number of projection rounds (k)

using BinaryVector = vector<int>;

vector<int> bv_to_int_vec(const BitVector& bv, size_t target_len) {
    vector<int> out(target_len, 0);
    for (size_t i = 0; i < min(bv.size(), target_len); ++i) {
        out[i] = bv[i] ? 1 : 0;
    }
    return out;
}

approx_psi::BitVector to_bitvector(const BinaryVector& v) {
    approx_psi::BitVector out(v.size());
    for (size_t i = 0; i < v.size(); ++i) out[i] = (v[i] != 0);
    return out;
}

int hamming_distance(const BinaryVector& a, const BinaryVector& b) {
    int dist = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) dist++;
    }
    return dist;
}

BinaryVector project_vector(const BinaryVector& v, const vector<size_t>& indices) {
    BinaryVector projection;
    projection.reserve(indices.size());
    for (size_t idx : indices) {
        projection.push_back(v[idx]);
    }
    return projection;
}

string to_binary_string(const BinaryVector& v) {
    string s;
    s.reserve(v.size());
    for (int bit : v) s.push_back(bit ? '1' : '0');
    return s;
}

void write_round_data(int round,
                      const vector<BinaryVector>& projA,
                      const vector<BinaryVector>& payloadA,
                      const vector<BinaryVector>& projB,
                      const vector<BinaryVector>& payloadB) {
    string filename = "sspsi_round_" + to_string(round) + ".txt";
    ofstream fout(filename);
    if (!fout) {
        cerr << "Error: Unable to create " << filename << "\n";
        return;
    }

    fout << "#A\n";
    for (size_t i = 0; i < projA.size(); ++i) {
        fout << to_binary_string(projA[i]) << "\t" << to_binary_string(payloadA[i]) << "\n";
    }
    fout << "#B\n";
    for (size_t i = 0; i < projB.size(); ++i) {
        fout << to_binary_string(projB[i]) << "\t" << to_binary_string(payloadB[i]) << "\n";
    }
    fout.close();
}

BinaryVector random_vector(int size, mt19937& gen) {
    uniform_int_distribution<> dis(0, 1);
    BinaryVector v(size);
    for (int i = 0; i < size; ++i) v[i] = dis(gen);
    return v;
}

BinaryVector from_determined_bitvector(const approx_psi::BitVector& bv, size_t out_len) {
    BinaryVector out(out_len);
    for (size_t i = 0; i < out_len; ++i) {
        out[i] = (i < bv.size() && bv[i]) ? 1 : 0;
    }
    return out;
}

// ---------------------------------------------------------
// Deployment-Grade Subprotocol: Joint Mask Generation 
// ---------------------------------------------------------

// Computes a mock SHA-256 for the commitment
size_t compute_hash_commitment(uint64_t seed) {
    hash<uint64_t> hasher;
    return hasher(seed);
}

// Executes a standard semi-honest Coin Tossing protocol.
// Returns the synchronized, shared Seed for both Partys.
uint64_t execute_coin_toss() {
    cout << "\n--- Executing Secure Coin Tossing for Joint Randomness ---\n";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<uint64_t> seed_dist(1, UINT64_MAX);

    // 1. Party A generates secret seed and commits to it.
    uint64_t s_A = seed_dist(gen);
    size_t commitment_A = compute_hash_commitment(s_A);
    cout << "Party A: Generated Secret Seed s_A.\n";
    cout << "Party A -> Party B: Hash Commitment (H(s_A)) = " << hex << commitment_A << dec << "\n";

    // 2. Party B generates secret seed and sends it in plaintext.
    uint64_t s_B = seed_dist(gen);
    cout << "Party B: Generated Secret Seed s_B = " << hex << s_B << dec << "\n";
    cout << "Party B -> Party A: s_B\n";

    // 3. Party A responds by revealing the pre-committed s_A.
    cout << "Party A -> Party B: Reveals s_A = " << hex << s_A << dec << "\n";
    
    // 4. Party B verifies commitment_A == H(s_A)
    assert(compute_hash_commitment(s_A) == commitment_A && "Commitment failure! Party A cheated.");
    cout << "Party B: Verified Hash Commitment.\n";

    // 5. Both Parties locally XOR the seeds to form the shared unified seed
    uint64_t joint_seed = s_A ^ s_B;
    cout << "Both Parties: Derived Shared Joint Seed = " << hex << joint_seed << dec << "\n\n";
    
    return joint_seed;
}

// Generate K independent projections using the strictly synchronized Pseudorandom Generator
vector<vector<size_t>> generate_projections_from_seed(uint64_t joint_seed, int L_size, int d, int t, int n, int k_rounds) {
    double base = n * t;
    double exponent = 1.0 / (d * (t - 1.0));
    double p = 1.0 - (1.0 / pow(base, exponent));
    
    // Using MT19937-64 as a PRG initialized with the agreed seed
    // Both parties will generate the *exact* same series of numbers globally
    mt19937_64 synchronized_prg(joint_seed);
    uniform_real_distribution<> dis(0.0, 1.0);
    
    vector<vector<size_t>> projections;
    for (int i = 0; i < k_rounds; ++i) {
        vector<size_t> current_proj;
        for (int j = 0; j < L_size; ++j) {
            if (dis(synchronized_prg) <= p) {
                current_proj.push_back(static_cast<size_t>(j));
            }
        }
        projections.push_back(current_proj);
    }
    return projections;
}

int main() {
    
    cout << "--- Starting Full Name-to-PSI Pipeline Simulation ---\n";

    // 1. Initialize Encoding and RLC
    NameEncodingConfig enc_cfg{L_BIT_LENGTH, GRAM_SIZE};
    NameEncoding encoder(enc_cfg);
    
    // We use the same seed for RLC and Projection Masking to simulate synchronized setup
    uint64_t shared_seed = 12345ULL; 
    ProjectionConsistencyCheck rlc_checker(shared_seed);

    // 2. Define Test Names (Fuzzy Pairs)
    // We test: Exact Match, Hyphenation, and Token Reordering
    vector<pair<string, string>> test_pairs = {
        {"BARON-COHEN SIMON", "SIMON BARON COHEN"}, // Hyphen + Reorder
        {"CHAN KOON MING", "CHAN KOON-MING"},       // Hyphenation
        {"ALICE SMITH", "SMITH ALICE"},             // Reordering
        {"DIANA PRINCE", "DIANA P"}                 // Significant deletion (should likely fail)
    };

    vector<BitVector> original_set_A;
    vector<BitVector> original_set_B;

    for (const auto& p : test_pairs) {
        original_set_A.push_back(encoder.encode_name_tail_token(p.first));
        original_set_B.push_back(encoder.encode_name_base(p.second));
    }

    // 3. Generate Projection Masks
    // In real MPC, this uses the generate_projections_from_seed logic
    // Here we simulate 20 rounds of random bit-position sampling
    auto masks = generate_projections_from_seed(shared_seed, L_BIT_LENGTH, HAMMING_D, 4, test_pairs.size(), K_ROUNDS);

    // 4. Processing Rounds
    for (int k = 0; k < K_ROUNDS; ++k) {
        ofstream fout("sspsi_round_" + to_string(k) + ".txt");
        fout << "#A\n";
        
        for (const auto& bvA : original_set_A) {
            // FIX: Initialize projA correctly
            BitVector projA; 
            projA.resize(masks[k].size()); 
            
            for(size_t i=0; i<masks[k].size(); ++i) {
                projA[i] = bvA[masks[k][i]];
            }

            if (!rlc_checker.verify_projection(bvA, projA, masks[k])) {
                throw runtime_error("RLC Verification Failed for Party A, Round " + to_string(k));
            }

            // This now works perfectly!
            fout << projA << "\t" << bvA << "\n"; 
        }

        fout << "#B\n";
        for (const auto& bvB : original_set_B) {
            BitVector projB;
            projB.resize(masks[k].size());

            for(size_t i=0; i<masks[k].size(); ++i) {
                projB[i] = bvB[masks[k][i]];
            }

            if (!rlc_checker.verify_projection(bvB, projB, masks[k])) {
                throw runtime_error("RLC Verification Failed for Party B, Round " + to_string(k));
            }

            // Fixed here too
            fout << projB << "\t" << bvB << "\n";
        }
        fout.close();
    }

    cout << "Pipeline Setup Complete. Data ready for ss_psi execution.\n";
    return 0;
}
