#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <random>
#include <stdexcept>
#include <bitset>
#include "ass.h" // Integrated ASS header

#ifdef USE_VOLEPSI
#include "volePSI/RsCpsi.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#endif

using namespace std;

// --- Global Constants (Synchronized with local_compute.cpp) ---
const int L_BIT_LENGTH = 1024;  // Length of the bit-vector (L)
const int GRAM_SIZE = 3;         // Size of n-grams for name encoding
const int HAMMING_D = 4;         // Distance threshold (d)
const int GAP_T = 4;             // Gap factor (T)
const int N_ELEMENTS = 100;      // Number of elements per set (n)
const int K_ROUNDS = 20;         // Number of projection rounds (k)

// Initialize the ASS Engine with a master key
approx_psi::AuthenticatedSecretSharing ass_engine(98765ULL); 

using BinaryVector = vector<int>;

// --- Helper Functions ---
string to_binary_string(const BinaryVector& v) {
    string s;
    s.reserve(v.size());
    for (int bit : v) s.push_back(bit ? '1' : '0');
    return s;
}

BinaryVector from_binary_string(const string& s) {
    BinaryVector v;
    v.reserve(s.size());
    for (char c : s) {
        if (c == '0') v.push_back(0);
        else if (c == '1') v.push_back(1);
        else throw runtime_error("Invalid bit character: " + string(1, c));
    }
    return v;
}

int hamming_distance(const BinaryVector& a, const BinaryVector& b) {
    if (a.size() != b.size()) throw runtime_error("Hamming distance mismatch");
    int dist = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) dist++;
    }
    return dist;
}

BinaryVector xor_vector(const BinaryVector& a, const BinaryVector& b) {
    if (a.size() != b.size()) throw runtime_error("XOR mismatch");
    BinaryVector c(a.size());
    for (size_t i = 0; i < a.size(); ++i) c[i] = a[i] ^ b[i];
    return c;
}

// --- Data Loading ---
void read_round_data(int round,
                     vector<pair<BinaryVector, BinaryVector>>& outA,
                     vector<pair<BinaryVector, BinaryVector>>& outB) {
    string filename = "sspsi_round_" + to_string(round) + ".txt";
    ifstream fin(filename);
    if (!fin) throw runtime_error("Cannot open " + filename);

    string line;
    bool readingA = false, readingB = false;

    while (getline(fin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        if (line[0] == '#') {
            if (line.find("#A") != string::npos) { readingA = true; readingB = false; }
            else if (line.find("#B") != string::npos) { readingA = false; readingB = true; }
            continue;
        }

        stringstream ss(line);
        string proj_str, payload_str;
        if (!(ss >> proj_str >> payload_str)) throw runtime_error("Invalid line format");

        if (readingA) outA.emplace_back(from_binary_string(proj_str), from_binary_string(payload_str));
        else if (readingB) outB.emplace_back(from_binary_string(proj_str), from_binary_string(payload_str));
    }
}

// --- The Matching Engine ---
void simulate_f_sspsi(int party_id) {
    cout << "Party " << party_id << " initializing pipeline check (F_ssPSI + ASS)\n";

    long total_matches = 0;

    // Use the global K_ROUNDS constant for the loop
    for (int k = 0; k < K_ROUNDS; k++) {
        vector<pair<BinaryVector, BinaryVector>> dataA;
        vector<pair<BinaryVector, BinaryVector>> dataB;

        read_round_data(k, dataA, dataB);

        string outFile = "ss_psi_shares_party" + to_string(party_id) + "_round" + to_string(k) + ".txt";
        ofstream fout(outFile);

        int matches_this_round = 0;
        for (auto& [projB, payloadB] : dataB) {
            for (auto& [projA, payloadA] : dataA) {
                
                // 1. Perform Matching based on Hamming Distance
                if (hamming_distance(projA, projB) <= HAMMING_D) {
                    
                    // 2. Generate the XOR result (The shared secret)
                    BinaryVector z = xor_vector(payloadA, payloadB);
                    
                    // 3. INTEGRATION: Apply ASS to protect the result
                    // For each bit in the result, we create an authenticated share
                    for (size_t i = 0; i < z.size(); ++i) {
                        auto [share0, share1] = ass_engine.share(z[i], k);
                        
                        // Select share based on current party
                        approx_psi::Share my_share = (party_id == 0 ? share0 : share1);

                        // 4. INTEGRATION: Verify the share before saving
                        // This simulates the "Abort" mechanism if data is corrupted
                        if (!ass_engine.verify(my_share, k)) {
                            throw runtime_error("ASS Verification Failed in Round " + to_string(k));
                        }

                        // Save the bit value of the verified share
                        fout << my_share.value;
                    }
                    fout << "\n";
                    matches_this_round++;
                }
            }
        }
        fout.close();
        total_matches += matches_this_round;
        cout << "Round " << k << ": " << matches_this_round << " matches verified with ASS. Output: " << outFile << "\n";
    }

    cout << "\n--- Pipeline Simulation Summary ---\n";
    cout << "Total matched pairs across " << K_ROUNDS << " rounds: " << total_matches << "\n";
}

int main(int argc, char** argv) {
    int party = 0;
    if (argc > 1) party = stoi(argv[1]);
    
    try {
        simulate_f_sspsi(party);
    } catch (const exception& e) {
        cerr << "CRITICAL ERROR: " << e.what() << endl;
        return 1;
    }

    return 0;
}