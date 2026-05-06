#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "coproto/Socket/AsioSocket.h"
#include "volePSI/RsCpsi.h"
#include "macoro/sync_wait.h"

using namespace std;
using namespace osuCrypto;
using namespace volePSI;

const int HAMMING_D = 7;
const int K_ROUNDS = 45;
const u64 STAT_SEC_PARAM = 40;
const u64 NUM_THREADS = 1;
const size_t MAX_NAME_BYTES = 128;
const size_t TERMINAL_PREVIEW_LIMIT = 10;
const char* RECEIVER_MATCH_OUTPUT_CSV = "output/mpc_fuzzy_matches.csv";
const char* RECEIVER_SUMMARY_OUTPUT_TXT = "output/mpc_fuzzy_summary.txt";

using BinaryVector = vector<int>;

struct EncodedRecord {
    size_t index;
    string name;
    BinaryVector projection;
    BinaryVector payload;
};

struct SenderValue {
    size_t index = 0;
    string name;
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
        if (a[i] != b[i]) ++dist;
    }
    return dist;
}

void read_round_party_data(int round, int party_id, vector<EncodedRecord>& out) {
    string filename = "sspsi_round_" + to_string(round) + ".txt";
    ifstream fin(filename);
    if (!fin) throw runtime_error("Cannot open " + filename);

    const string target_header = (party_id == 0 ? "#A" : "#B");
    string line;
    bool reading_target = false;

    while (getline(fin, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        if (line[0] == '#') {
            reading_target = (line.find(target_header) != string::npos);
            continue;
        }

        if (!reading_target) continue;

        stringstream ss(line);
        size_t idx = 0;
        string name;
        string proj_str;
        string payload_str;
        if (!(ss >> idx >> quoted(name) >> proj_str >> payload_str)) {
            throw runtime_error("Invalid round data line in " + filename);
        }

        out.push_back(EncodedRecord{
            idx,
            name,
            from_binary_string(proj_str),
            from_binary_string(payload_str)
        });
    }
}

string projection_string(const BinaryVector& projection) {
    string key;
    key.reserve(projection.size());
    for (int bit : projection) key.push_back(bit ? '1' : '0');
    return key;
}

block projection_key_from_string(const string& key) {
    array<u8, RandomOracle::HashSize> digest{};
    RandomOracle ro;
    ro.Update(reinterpret_cast<const u8*>(key.data()), key.size());
    ro.Final(digest.data());

    block out;
    static_assert(sizeof(out) <= RandomOracle::HashSize, "Digest too small for block");
    memcpy(&out, digest.data(), sizeof(out));
    return out;
}

block projection_key(const BinaryVector& projection) {
    return projection_key_from_string(projection_string(projection));
}

vector<u8> pack_bits(const BinaryVector& bits) {
    vector<u8> bytes((bits.size() + 7) / 8, 0);
    for (size_t i = 0; i < bits.size(); ++i) {
        if (bits[i]) {
            bytes[i / 8] |= static_cast<u8>(1u << (i % 8));
        }
    }
    return bytes;
}

BinaryVector unpack_bits(std::span<const u8> bytes, size_t bit_count) {
    BinaryVector bits(bit_count, 0);
    for (size_t i = 0; i < bit_count; ++i) {
        bits[i] = (bytes[i / 8] >> (i % 8)) & 1u;
    }
    return bits;
}

u32 read_u32(const u8* src) {
    u32 out = 0;
    memcpy(&out, src, sizeof(out));
    return out;
}

void write_u32(u8* dest, u32 value) {
    memcpy(dest, &value, sizeof(value));
}

size_t value_byte_length(size_t payload_bits) {
    const size_t payload_bytes = (payload_bits + 7) / 8;
    return sizeof(u32) + sizeof(u32) + MAX_NAME_BYTES + sizeof(u32) + payload_bytes;
}

vector<u8> serialize_sender_value(const EncodedRecord& rec) {
    const auto packed_payload = pack_bits(rec.payload);
    vector<u8> out(value_byte_length(rec.payload.size()), 0);

    size_t offset = 0;
    write_u32(out.data() + offset, static_cast<u32>(rec.index));
    offset += sizeof(u32);

    const auto clamped_name_len = static_cast<u32>(min(rec.name.size(), MAX_NAME_BYTES));
    write_u32(out.data() + offset, clamped_name_len);
    offset += sizeof(u32);

    memcpy(out.data() + offset, rec.name.data(), clamped_name_len);
    offset += MAX_NAME_BYTES;

    write_u32(out.data() + offset, static_cast<u32>(rec.payload.size()));
    offset += sizeof(u32);

    memcpy(out.data() + offset, packed_payload.data(), packed_payload.size());
    return out;
}

SenderValue deserialize_sender_value(std::span<const u8> data) {
    size_t offset = 0;
    SenderValue out;

    out.index = read_u32(data.data() + offset);
    offset += sizeof(u32);

    const auto name_len = read_u32(data.data() + offset);
    offset += sizeof(u32);

    if (name_len > MAX_NAME_BYTES) {
        throw runtime_error("Serialized sender value has invalid name length");
    }

    out.name.assign(reinterpret_cast<const char*>(data.data() + offset), name_len);
    offset += MAX_NAME_BYTES;

    const auto payload_bits = read_u32(data.data() + offset);
    offset += sizeof(u32);

    const size_t payload_bytes = (payload_bits + 7) / 8;
    if (offset + payload_bytes > data.size()) {
        throw runtime_error("Serialized sender value truncated");
    }

    out.payload = unpack_bits(data.subspan(offset, payload_bytes), payload_bits);
    return out;
}

vector<u8> xor_rows(std::span<const u8> a, std::span<const u8> b) {
    if (a.size() != b.size()) throw runtime_error("Share row length mismatch");
    vector<u8> out(a.size());
    for (size_t i = 0; i < a.size(); ++i) out[i] = a[i] ^ b[i];
    return out;
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
             << " more matches written to " << RECEIVER_MATCH_OUTPUT_CSV << "\n";
    }
}

void write_opened_matches_csv(const vector<OpenMatch>& opened_matches) {
    const string output_path = resolve_output_path(RECEIVER_MATCH_OUTPUT_CSV);
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

void write_summary_file(long total_candidates, const vector<OpenMatch>& opened_matches) {
    const string output_path = resolve_output_path(RECEIVER_SUMMARY_OUTPUT_TXT);
    ofstream fout(output_path);
    if (!fout) {
        throw runtime_error("Cannot create " + output_path);
    }

    fout << "Technique: mpc_fuzzy_psi_exact_projection\n";
    fout << "K_ROUNDS: " << K_ROUNDS << "\n";
    fout << "HAMMING_D: " << HAMMING_D << "\n";
    fout << "Total exact projected candidates across rounds: " << total_candidates << "\n";
    fout << "Unique fuzzy-matched record pairs opened: " << opened_matches.size() << "\n";
    fout << "Detailed CSV: " << RECEIVER_MATCH_OUTPUT_CSV << "\n";
}

template <typename T>
void send_vec(coproto::Socket& sock, const vector<T>& data) {
    const u64 size = static_cast<u64>(data.size());
    macoro::sync_wait(sock.send(size));
    if (size) {
        macoro::sync_wait(sock.send(data));
    }
}

template <typename T>
vector<T> recv_vec(coproto::Socket& sock) {
    u64 size = 0;
    macoro::sync_wait(sock.recv(size));
    vector<T> data(size);
    if (size) {
        macoro::sync_wait(sock.recv(data));
    }
    return data;
}

void run_sender(coproto::Socket& sock) {
    cout << "Party 0 starting MPC fuzzy PSI sender on exact projected keys.\n";

    long total_candidates = 0;
    for (int round = 0; round < K_ROUNDS; ++round) {
        vector<EncodedRecord> dataA;
        read_round_party_data(round, 0, dataA);

        vector<size_t> sender_rows;
        map<string, size_t> sender_projection_rows;
        for (size_t i = 0; i < dataA.size(); ++i) {
            auto key = projection_string(dataA[i].projection);
            if (sender_projection_rows.emplace(key, sender_rows.size()).second) {
                sender_rows.push_back(i);
            }
        }

        const u64 sender_size = static_cast<u64>(sender_rows.size());
        macoro::sync_wait(sock.send(sender_size));

        u64 receiver_size = 0;
        macoro::sync_wait(sock.recv(receiver_size));

        vector<block> keys;
        keys.reserve(sender_rows.size());
        const size_t packed_len = value_byte_length(dataA.front().payload.size());
        osuCrypto::Matrix<u8> values(sender_rows.size(), packed_len);

        for (size_t row = 0; row < sender_rows.size(); ++row) {
            const auto& rec = dataA[sender_rows[row]];
            keys.push_back(projection_key(rec.projection));
            auto serialized = serialize_sender_value(rec);
            memcpy(&values(row, 0), serialized.data(), serialized.size());
        }

        PRNG prng(toBlock(static_cast<u64>(round + 1), 0xABCDEF));
        RsCpsiSender sender;
        sender.init(sender_size, receiver_size, packed_len, STAT_SEC_PARAM, prng.get(), NUM_THREADS);

        RsCpsiSender::Sharing share;
        macoro::sync_wait(sender.send(keys, values, share, sock));

        vector<u8> flag_bytes(share.mFlagBits.sizeBytes());
        if (!flag_bytes.empty()) {
            memcpy(flag_bytes.data(), share.mFlagBits.data(), flag_bytes.size());
        }

        vector<u8> share_bytes(share.mValues.rows() * share.mValues.cols());
        if (!share_bytes.empty()) {
            memcpy(share_bytes.data(), share.mValues.data(), share_bytes.size());
        }

        send_vec(sock, flag_bytes);
        send_vec(sock, share_bytes);

        u64 receiver_candidates = 0;
        macoro::sync_wait(sock.recv(receiver_candidates));
        total_candidates += static_cast<long>(receiver_candidates);

        cout << "Round " << round << ": sender processed " << dataA.size()
             << " unique projection keys, receiver reported " << receiver_candidates
             << " exact projected candidates.\n";
    }

    cout << "\n--- MPC Sender Summary ---\n";
    cout << "Receiver reported " << total_candidates
         << " exact projected candidates across " << K_ROUNDS << " rounds.\n";
}

void run_receiver(coproto::Socket& sock) {
    cout << "Party 1 starting MPC fuzzy PSI receiver on exact projected keys.\n";

    long total_candidates = 0;
    vector<OpenMatch> opened_matches;
    set<pair<size_t, size_t>> seen_pairs;

    for (int round = 0; round < K_ROUNDS; ++round) {
        vector<EncodedRecord> dataB;
        read_round_party_data(round, 1, dataB);

        u64 sender_size = 0;
        macoro::sync_wait(sock.recv(sender_size));

        vector<block> keys;
        vector<vector<size_t>> receiver_row_records;
        map<string, size_t> receiver_projection_rows;

        for (size_t i = 0; i < dataB.size(); ++i) {
            auto key = projection_string(dataB[i].projection);
            auto [it, inserted] = receiver_projection_rows.emplace(key, keys.size());
            if (inserted) {
                keys.push_back(projection_key_from_string(key));
                receiver_row_records.push_back({});
            }
            receiver_row_records[it->second].push_back(i);
        }

        const u64 receiver_size = static_cast<u64>(keys.size());
        macoro::sync_wait(sock.send(receiver_size));

        const size_t packed_len = value_byte_length(dataB.front().payload.size());
        PRNG prng(toBlock(static_cast<u64>(round + 1), 0xABCDEF));
        RsCpsiReceiver receiver;
        receiver.init(sender_size, receiver_size, packed_len, STAT_SEC_PARAM, prng.get(), NUM_THREADS);

        RsCpsiReceiver::Sharing share;
        macoro::sync_wait(receiver.receive(keys, share, sock));

        auto sender_flag_bytes = recv_vec<u8>(sock);
        auto sender_share_bytes = recv_vec<u8>(sock);

        if (share.mValues.cols() != packed_len) {
            throw runtime_error("Unexpected receiver share width");
        }

        if (sender_share_bytes.size() != share.mValues.rows() * share.mValues.cols()) {
            throw runtime_error("Sender share matrix size mismatch");
        }

        u64 matches_this_round = 0;
        for (size_t i = 0; i < keys.size(); ++i) {
            const auto output_row = share.mMapping[i];
            if (output_row == ~u64(0)) continue;
            if (output_row >= share.mValues.rows()) continue;
            if (output_row / 8 >= sender_flag_bytes.size()) continue;

            const bool sender_flag = (sender_flag_bytes[output_row / 8] >> (output_row % 8)) & 1u;
            const bool receiver_flag = share.mFlagBits[output_row];
            if (!(sender_flag ^ receiver_flag)) continue;

            ++matches_this_round;

            const u8* receiver_row = &share.mValues(output_row, 0);
            const u8* sender_row = sender_share_bytes.data() + (output_row * share.mValues.cols());
            auto opened_value = xor_rows(
                std::span<const u8>(receiver_row, share.mValues.cols()),
                std::span<const u8>(sender_row, share.mValues.cols()));

            auto sender_value = deserialize_sender_value(opened_value);

            for (size_t rec_index : receiver_row_records[i]) {
                const auto& recB = dataB[rec_index];
                const int payload_dist = hamming_distance(sender_value.payload, recB.payload);
                if (payload_dist > HAMMING_D) continue;

                if (seen_pairs.insert({sender_value.index, recB.index}).second) {
                    opened_matches.push_back(OpenMatch{
                        round,
                        sender_value.index,
                        sender_value.name,
                        recB.index,
                        recB.name,
                        0,
                        payload_dist
                    });
                }
            }
        }

        total_candidates += static_cast<long>(matches_this_round);
        macoro::sync_wait(sock.send(matches_this_round));

        cout << "Round " << round << ": receiver found " << matches_this_round
             << " exact projected candidates.\n";
    }

    cout << "\n--- MPC Fuzzy PSI Summary ---\n";
    cout << "Total exact projected candidates across " << K_ROUNDS << " rounds: "
         << total_candidates << "\n";
    cout << "Unique fuzzy-matched record pairs opened: " << opened_matches.size() << "\n";
    write_opened_matches_csv(opened_matches);
    write_summary_file(total_candidates, opened_matches);
    cout << "Detailed matches written to " << RECEIVER_MATCH_OUTPUT_CSV << "\n";
    cout << "Summary written to " << RECEIVER_SUMMARY_OUTPUT_TXT << "\n";
    print_opened_matches(opened_matches);
}

int main(int argc, char** argv) {
    int party = 0;
    if (argc > 1) party = stoi(argv[1]);
    string address = "localhost:1212";
    if (argc > 2) address = argv[2];

    try {
        const bool is_server = (party == 0);
        coproto::Socket sock = coproto::asioConnect(address, is_server);

        if (party == 0) run_sender(sock);
        else run_receiver(sock);

        macoro::sync_wait(sock.flush());
    } catch (const exception& e) {
        cerr << "CRITICAL ERROR: " << e.what() << endl;
        return 1;
    }

    return 0;
}
