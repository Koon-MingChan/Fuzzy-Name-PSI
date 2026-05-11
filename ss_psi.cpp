#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#include "ass.h"

#ifdef USE_VOLEPSI
#include "volePSI/RsCpsi.h"
#include "cryptoTools/Network/IOService.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Crypto/PRNG.h"
#endif

using namespace std;

const int L_BIT_LENGTH = 8192;
const int GRAM_SIZE = 2;
const int HAMMING_D = 4;
const int GAP_T = 9;
const int N_ELEMENTS = 500;
const int K_ROUNDS = 50;
const size_t TERMINAL_PREVIEW_LIMIT = 10;
const char* MATCH_OUTPUT_CSV = "output/ss_psi_opened_matches.csv";
const char* SUMMARY_OUTPUT_TXT = "output/ss_psi_summary.txt";

approx_psi::AuthenticatedSecretSharing ass_engine(98765ULL);

using BinaryVector = vector<int>;

struct EncodedRecord {
    size_t index;
    string name;
    BinaryVector projection;
    BinaryVector payload;
};

struct OpenMatch {
    int round;
    size_t party0_index;
    string party0_name;
    size_t party1_index;
    string party1_name;
    int projection_distance;
    int payload_distance;
};

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

string resolve_output_path(const string& path) {
    namespace fs = std::filesystem;
    fs::path out = path;
    if (!fs::exists(out.parent_path())) {
        fs::path alt = fs::path("..") / out;
        fs::create_directories(alt.parent_path());
        return alt.string();
    }

    fs::create_directories(out.parent_path());
    return out.string();
}

void read_round_data(int round,
                     vector<EncodedRecord>& outA,
                     vector<EncodedRecord>& outB) {
    string filename = "sspsi_round_" + to_string(round) + ".txt";
    ifstream fin(filename);
    if (!fin) throw runtime_error("Cannot open " + filename);

    string line;
    bool readingA = false;
    bool readingB = false;

    while (getline(fin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        if (line[0] == '#') {
            if (line.find("#A") != string::npos) {
                readingA = true;
                readingB = false;
            } else if (line.find("#B") != string::npos) {
                readingA = false;
                readingB = true;
            }
            continue;
        }

        stringstream ss(line);
        size_t idx = 0;
        string name;
        string proj_str;
        string payload_str;
        if (!(ss >> idx >> quoted(name) >> proj_str >> payload_str)) {
            throw runtime_error("Invalid round data line in " + filename);
        }

        EncodedRecord record{idx, name, from_binary_string(proj_str), from_binary_string(payload_str)};
        if (readingA) outA.push_back(record);
        else if (readingB) outB.push_back(record);
    }
}

void print_opened_matches(const vector<OpenMatch>& opened_matches) {
    cout << "\n--- Open Phase: Revealed Fuzzy Matches ---\n";
    if (opened_matches.empty()) {
        cout << "No fuzzy matches satisfied the final Hamming threshold.\n";
        return;
    }

    const size_t preview_count = min(opened_matches.size(), TERMINAL_PREVIEW_LIMIT);
    for (size_t i = 0; i < preview_count; ++i) {
        const auto& match = opened_matches[i];
        cout << "Round " << match.round
             << ": Party0[" << match.party0_index << "] " << quoted(match.party0_name)
             << " <-> Party1[" << match.party1_index << "] " << quoted(match.party1_name)
             << " | proj_dist=" << match.projection_distance
             << ", payload_dist=" << match.payload_distance
             << "\n";
    }

    if (opened_matches.size() > preview_count) {
        cout << "... " << (opened_matches.size() - preview_count)
             << " more matches written to " << MATCH_OUTPUT_CSV << "\n";
    }
}

void write_opened_matches_csv(const vector<OpenMatch>& opened_matches) {
    const string output_path = resolve_output_path(MATCH_OUTPUT_CSV);
    ofstream fout(output_path);
    if (!fout) {
        throw runtime_error("Cannot create " + output_path);
    }

    fout << "round,party0_index,party0_name,party1_index,party1_name,proj_dist,payload_dist\n";
    for (const auto& match : opened_matches) {
        fout << match.round << ','
             << match.party0_index << ','
             << quoted(match.party0_name) << ','
             << match.party1_index << ','
             << quoted(match.party1_name) << ','
             << match.projection_distance << ','
             << match.payload_distance << '\n';
    }
}

void write_summary_file(long total_matches, const vector<OpenMatch>& opened_matches) {
    const string output_path = resolve_output_path(SUMMARY_OUTPUT_TXT);
    ofstream fout(output_path);
    if (!fout) {
        throw runtime_error("Cannot create " + output_path);
    }

    fout << "Technique: simulation_ss_psi\n";
    fout << "K_ROUNDS: " << K_ROUNDS << "\n";
    fout << "HAMMING_D: " << HAMMING_D << "\n";
    fout << "Total matched pairs across rounds: " << total_matches << "\n";
    fout << "Unique fuzzy-matched record pairs opened: " << opened_matches.size() << "\n";
    fout << "Detailed CSV: " << MATCH_OUTPUT_CSV << "\n";
}

void simulate_f_sspsi(int party_id) {
    cout << "Party " << party_id << " initializing pipeline check (F_ssPSI + ASS + Open)\n";

    long total_matches = 0;
    vector<OpenMatch> opened_matches;
    set<pair<size_t, size_t>> seen_pairs;

    for (int k = 0; k < K_ROUNDS; ++k) {
        vector<EncodedRecord> dataA;
        vector<EncodedRecord> dataB;

        read_round_data(k, dataA, dataB);

        string outFile = "ss_psi_shares_party" + to_string(party_id) + "_round" + to_string(k) + ".txt";
        ofstream fout(outFile);
        if (!fout) {
            throw runtime_error("Cannot create " + outFile);
        }

        int matches_this_round = 0;
        for (const auto& recB : dataB) {
            for (const auto& recA : dataA) {
                int proj_dist = hamming_distance(recA.projection, recB.projection);
                if (proj_dist > 0) continue;

                int payload_dist = hamming_distance(recA.payload, recB.payload);
                if (payload_dist > HAMMING_D) continue;

                BinaryVector z = xor_vector(recA.payload, recB.payload);
                size_t verified_share_count = 0;

                for (size_t i = 0; i < z.size(); ++i) {
                    auto [share0, share1] = ass_engine.share(z[i], k);
                    approx_psi::Share my_share = (party_id == 0 ? share0 : share1);

                    if (!ass_engine.verify(my_share, k)) {
                        throw runtime_error("ASS Verification Failed in Round " + to_string(k));
                    }
                    ++verified_share_count;
                }

                fout << recA.index
                     << "\t" << recB.index
                     << "\t" << quoted(recA.name)
                     << "\t" << quoted(recB.name)
                     << "\t" << proj_dist
                     << "\t" << payload_dist
                     << "\t" << verified_share_count
                     << "\n";

                if (seen_pairs.insert({recA.index, recB.index}).second) {
                    opened_matches.push_back(OpenMatch{
                        k,
                        recA.index,
                        recA.name,
                        recB.index,
                        recB.name,
                        proj_dist,
                        payload_dist
                    });
                }

                ++matches_this_round;
            }
        }

        total_matches += matches_this_round;
        cout << "Round " << k << ": " << matches_this_round
             << " candidate matches written to " << outFile << "\n";
    }

    cout << "\n--- Pipeline Simulation Summary ---\n";
    cout << "Total matched pairs across " << K_ROUNDS << " rounds: " << total_matches << "\n";
    cout << "Unique fuzzy-matched record pairs opened: " << opened_matches.size() << "\n";
    write_opened_matches_csv(opened_matches);
    write_summary_file(total_matches, opened_matches);
    cout << "Detailed matches written to " << MATCH_OUTPUT_CSV << "\n";
    cout << "Summary written to " << SUMMARY_OUTPUT_TXT << "\n";
    print_opened_matches(opened_matches);
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
