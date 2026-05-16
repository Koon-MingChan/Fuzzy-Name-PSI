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
#include <utility>

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Crypto/RandomOracle.h"
#include "coproto/Socket/AsioSocket.h"
#include "volePSI/RsCpsi.h"
#include "macoro/sync_wait.h"

// Stage 2 prototype:
// This version realises PSI-style candidate generation and writes aligned
// split-party private input files for a secret-shared MPC Hamming/masking
// stage. Party 0 payloads are written by Party 0, Party 1 payloads are written
// by Party 1, and the receiver no longer opens Party 0 payloads.

using namespace std;
using namespace osuCrypto;
using namespace volePSI;

const int HAMMING_D = 5;
const int K_ROUNDS = 50;
const u64 STAT_SEC_PARAM = 40;
const u64 NUM_THREADS = 1;
const size_t MAX_NAME_BYTES = 128;
const size_t MAX_BUCKET_RECORDS = 512;
const size_t TERMINAL_PREVIEW_LIMIT = 10;
const size_t MPC_PAYLOAD_BITS = 8192;
const size_t MPC_CHUNK_BITS = 64;
const size_t MPC_PAYLOAD_CHUNKS = MPC_PAYLOAD_BITS / MPC_CHUNK_BITS;
const char* RECEIVER_MATCH_OUTPUT_CSV = "output/mpc_fuzzy_matches.csv";
const char* RECEIVER_SUMMARY_OUTPUT_TXT = "output/mpc_fuzzy_summary.txt";
const char* MPC_HANDOFF_MANIFEST_CSV = "output/mpc_fuzzy_mpc_candidates.csv";
const char* MPC_PARTY0_INPUT_TXT = "output/mpc_fuzzy_party0_payloads.txt";
const char* MPC_PARTY1_INPUT_TXT = "output/mpc_fuzzy_party1_payloads.txt";
const char* MPC_CONFIG_MPC = "output/mp_spdz/approx_psi_config.mpc";
const char* MPC_SPDZ_PARTY0_INPUT_TXT = "output/mp_spdz/Player-Data/Input-P0-0";
const char* MPC_SPDZ_PARTY1_INPUT_TXT = "output/mp_spdz/Player-Data/Input-P1-0";

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

struct MpcCandidate {
    u64 candidate_id;
    int round;
    size_t party0_index;
    string party0_name;
    size_t party1_index;
    string party1_name;
};

struct MpcInputRecord {
    u64 candidate_id;
    BinaryVector payload;
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

string to_binary_string(const BinaryVector& v) {
    string s;
    s.reserve(v.size());
    for (int bit : v) s.push_back(bit ? '1' : '0');
    return s;
}

vector<u64> binary_vector_to_u64_chunks(const BinaryVector& v) {
    if (v.size() != MPC_PAYLOAD_BITS) {
        throw runtime_error("MPC payload bit length must be " + to_string(MPC_PAYLOAD_BITS));
    }

    vector<u64> chunks(MPC_PAYLOAD_CHUNKS, 0);
    for (size_t i = 0; i < v.size(); ++i) {
        if (v[i]) {
            chunks[i / MPC_CHUNK_BITS] |= (u64{1} << (i % MPC_CHUNK_BITS));
        }
    }
    return chunks;
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

size_t single_sender_value_byte_length(size_t payload_bits) {
    (void)payload_bits;
    return sizeof(u32) + sizeof(u32) + MAX_NAME_BYTES;
}

size_t bucket_value_byte_length(size_t payload_bits) {
    return sizeof(u32) + (MAX_BUCKET_RECORDS * single_sender_value_byte_length(payload_bits));
}

vector<u8> serialize_sender_value(const EncodedRecord& rec) {
    vector<u8> out(single_sender_value_byte_length(rec.payload.size()), 0);

    size_t offset = 0;
    write_u32(out.data() + offset, static_cast<u32>(rec.index));
    offset += sizeof(u32);

    const auto clamped_name_len = static_cast<u32>(min(rec.name.size(), MAX_NAME_BYTES));
    write_u32(out.data() + offset, clamped_name_len);
    offset += sizeof(u32);

    memcpy(out.data() + offset, rec.name.data(), clamped_name_len);
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
    return out;
}

vector<u8> serialize_sender_bucket(const vector<size_t>& bucket_records,
                                   const vector<EncodedRecord>& dataA,
                                   size_t payload_bits) {
    if (bucket_records.size() > MAX_BUCKET_RECORDS) {
        throw runtime_error("Sender projection bucket exceeds MAX_BUCKET_RECORDS");
    }

    vector<u8> out(bucket_value_byte_length(payload_bits), 0);
    write_u32(out.data(), static_cast<u32>(bucket_records.size()));

    const size_t single_len = single_sender_value_byte_length(payload_bits);
    size_t offset = sizeof(u32);
    for (size_t rec_index : bucket_records) {
        const auto& rec = dataA[rec_index];

        auto serialized = serialize_sender_value(rec);
        if (serialized.size() != single_len) {
            throw runtime_error("Unexpected serialized sender value width");
        }
        memcpy(out.data() + offset, serialized.data(), serialized.size());
        offset += single_len;
    }

    return out;
}

vector<SenderValue> deserialize_sender_bucket(std::span<const u8> data,
                                              size_t payload_bits) {
    const size_t expected_len = bucket_value_byte_length(payload_bits);
    if (data.size() != expected_len) {
        throw runtime_error("Serialized sender bucket has unexpected length");
    }

    const auto bucket_count = read_u32(data.data());
    if (bucket_count > MAX_BUCKET_RECORDS) {
        throw runtime_error("Serialized sender bucket count exceeds MAX_BUCKET_RECORDS");
    }

    vector<SenderValue> out;
    out.reserve(bucket_count);

    const size_t single_len = single_sender_value_byte_length(payload_bits);
    size_t offset = sizeof(u32);
    for (u32 i = 0; i < bucket_count; ++i) {
        auto sender_value = deserialize_sender_value(data.subspan(offset, single_len));
        out.push_back(std::move(sender_value));
        offset += single_len;
    }

    return out;
}

size_t validate_payload_bit_length(const vector<EncodedRecord>& records,
                                   const string& party_label,
                                   int round) {
    if (records.empty()) return 0;

    const size_t payload_bits = records.front().payload.size();
    for (const auto& rec : records) {
        if (rec.payload.size() != payload_bits) {
            throw runtime_error(party_label + " payload length mismatch in round " + to_string(round));
        }
    }
    return payload_bits;
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
    fout << "Filtering: split_party_mpc_handoff_secret_shared_hamming\n";
    fout << "K_ROUNDS: " << K_ROUNDS << "\n";
    fout << "HAMMING_D: " << HAMMING_D << "\n";
    fout << "Total expanded exact-projection candidate pairs across rounds: " << total_candidates << "\n";
    fout << "Unique fuzzy-matched record pairs opened: " << opened_matches.size() << "\n";
    fout << "MPC handoff manifest: " << MPC_HANDOFF_MANIFEST_CSV << "\n";
    fout << "MPC Party 0 input: " << MPC_PARTY0_INPUT_TXT << "\n";
    fout << "MPC Party 1 input: " << MPC_PARTY1_INPUT_TXT << "\n";
    fout << "MP-SPDZ Party 0 input: " << MPC_SPDZ_PARTY0_INPUT_TXT << "\n";
    fout << "MP-SPDZ Party 1 input: " << MPC_SPDZ_PARTY1_INPUT_TXT << "\n";
    fout << "MP-SPDZ config: " << MPC_CONFIG_MPC << "\n";
    fout << "MP-SPDZ payload chunks: " << MPC_PAYLOAD_CHUNKS << "\n";
    fout << "Detailed CSV: " << RECEIVER_MATCH_OUTPUT_CSV << "\n";
}

void write_mpc_config(size_t candidate_count) {
    if (MPC_PAYLOAD_BITS % MPC_CHUNK_BITS != 0) {
        throw runtime_error("MPC_PAYLOAD_BITS must be divisible by MPC_CHUNK_BITS");
    }

    const string config_path = resolve_output_path(MPC_CONFIG_MPC);

    ofstream config(config_path);
    if (!config) throw runtime_error("Cannot create " + config_path);

    config << "PAYLOAD_BITS = " << MPC_PAYLOAD_BITS << "\n";
    config << "CHUNK_BITS = " << MPC_CHUNK_BITS << "\n";
    config << "PAYLOAD_CHUNKS = " << MPC_PAYLOAD_CHUNKS << "\n";
    config << "HAMMING_D = " << HAMMING_D << "\n";
    config << "CANDIDATE_OFFSET = 0\n";
    config << "MAX_CANDIDATES = " << candidate_count << "\n";
}

void write_mpc_manifest_file(const vector<MpcCandidate>& candidates) {
    const string manifest_path = resolve_output_path(MPC_HANDOFF_MANIFEST_CSV);
    ofstream manifest(manifest_path);
    if (!manifest) throw runtime_error("Cannot create " + manifest_path);

    // Public bookkeeping for candidate-id to record-id mapping. Payloads are
    // not written here.
    manifest << "candidate_id,round,party0_index,party0_name,party1_index,party1_name,proj_dist\n";
    for (const auto& candidate : candidates) {
        manifest << candidate.candidate_id << ','
                 << candidate.round << ','
                 << candidate.party0_index << ','
                 << quoted(candidate.party0_name) << ','
                 << candidate.party1_index << ','
                 << quoted(candidate.party1_name) << ','
                 << 0 << '\n';
    }
}

void write_mpc_party_input_files(const string& readable_path,
                                 const string& spdz_path,
                                 vector<MpcInputRecord> inputs) {
    sort(inputs.begin(), inputs.end(), [](const auto& a, const auto& b) {
        return a.candidate_id < b.candidate_id;
    });

    const string resolved_readable_path = resolve_output_path(readable_path);
    const string resolved_spdz_path = resolve_output_path(spdz_path);

    ofstream readable(resolved_readable_path);
    ofstream spdz_input(resolved_spdz_path);
    if (!readable) throw runtime_error("Cannot create " + resolved_readable_path);
    if (!spdz_input) throw runtime_error("Cannot create " + resolved_spdz_path);

    readable << "# candidate_id payload_bits\n";
    for (const auto& input : inputs) {
        readable << input.candidate_id << ' '
                 << to_binary_string(input.payload) << '\n';

        const auto chunks = binary_vector_to_u64_chunks(input.payload);

        // MP-SPDZ player input format is whitespace-separated decimal values.
        // For each candidate each party writes: active_flag, then payload
        // chunks. The generated approx_psi_config.mpc records exactly how many
        // candidate slots were emitted.
        spdz_input << 1 << '\n';
        for (u64 chunk : chunks) spdz_input << chunk << '\n';
    }
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
    cout << "Party 0 starting PSI-style candidate generation sender on exact projected keys.\n";

    long total_candidates = 0;
    vector<MpcInputRecord> party0_inputs;
    for (int round = 0; round < K_ROUNDS; ++round) {
        vector<EncodedRecord> dataA;
        read_round_party_data(round, 0, dataA);
        const size_t payload_bits = validate_payload_bit_length(dataA, "Party 0", round);

        map<size_t, const EncodedRecord*> records_by_index;
        for (const auto& rec : dataA) {
            records_by_index[rec.index] = &rec;
        }

        map<string, vector<size_t>> sender_projection_buckets;
        for (size_t i = 0; i < dataA.size(); ++i) {
            auto key = projection_string(dataA[i].projection);
            sender_projection_buckets[key].push_back(i);
        }

        size_t max_sender_bucket_size = 0;
        for (const auto& [key, bucket_records] : sender_projection_buckets) {
            max_sender_bucket_size = max(max_sender_bucket_size, bucket_records.size());
            if (bucket_records.size() > MAX_BUCKET_RECORDS) {
                throw runtime_error("Sender projection bucket for round " + to_string(round)
                                    + " exceeds MAX_BUCKET_RECORDS");
            }
        }

        const u64 sender_size = static_cast<u64>(sender_projection_buckets.size());
        macoro::sync_wait(sock.send(sender_size));
        macoro::sync_wait(sock.send(static_cast<u64>(payload_bits)));
        macoro::sync_wait(sock.send(static_cast<u64>(dataA.size())));
        macoro::sync_wait(sock.send(static_cast<u64>(max_sender_bucket_size)));

        u64 receiver_size = 0;
        macoro::sync_wait(sock.recv(receiver_size));
        u64 receiver_payload_bits = 0;
        macoro::sync_wait(sock.recv(receiver_payload_bits));

        if (sender_size && receiver_size && payload_bits != receiver_payload_bits) {
            throw runtime_error("Sender/receiver payload bit length mismatch in round " + to_string(round));
        }

        const size_t packed_len = bucket_value_byte_length(payload_bits);
        if (sender_size == 0 || receiver_size == 0) {
            send_vec(sock, vector<u8>{});
            send_vec(sock, vector<u8>{});

            auto assignment_words = recv_vec<u64>(sock);
            if (!assignment_words.empty()) {
                throw runtime_error("Expected no candidate assignments for empty PSI round");
            }

            u64 receiver_candidates = 0;
            macoro::sync_wait(sock.recv(receiver_candidates));
            total_candidates += static_cast<long>(receiver_candidates);

            cout << "Round " << round
                 << ": party0_records=" << dataA.size()
                 << ", sender_projection_buckets=" << sender_projection_buckets.size()
                 << ", max_sender_bucket_size=" << max_sender_bucket_size
                 << ", receiver reported " << receiver_candidates
                 << " expanded candidate pairs.\n";
            continue;
        }

        vector<block> keys;
        keys.reserve(sender_projection_buckets.size());
        osuCrypto::Matrix<u8> values(sender_projection_buckets.size(), packed_len);

        size_t row = 0;
        for (const auto& [key, bucket_records] : sender_projection_buckets) {
            keys.push_back(projection_key_from_string(key));
            auto serialized = serialize_sender_bucket(bucket_records, dataA, payload_bits);
            memcpy(&values(row, 0), serialized.data(), serialized.size());
            ++row;
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

        auto assignment_words = recv_vec<u64>(sock);
        if (assignment_words.size() % 2 != 0) {
            throw runtime_error("Candidate assignment message has odd length");
        }

        for (size_t i = 0; i < assignment_words.size(); i += 2) {
            const u64 candidate_id = assignment_words[i];
            const size_t party0_index = static_cast<size_t>(assignment_words[i + 1]);
            const auto rec_it = records_by_index.find(party0_index);
            if (rec_it == records_by_index.end()) {
                throw runtime_error("Candidate assignment references unknown Party 0 index");
            }

            party0_inputs.push_back(MpcInputRecord{
                candidate_id,
                rec_it->second->payload
            });
        }

        u64 receiver_candidates = 0;
        macoro::sync_wait(sock.recv(receiver_candidates));
        total_candidates += static_cast<long>(receiver_candidates);

        cout << "Round " << round
             << ": party0_records=" << dataA.size()
             << ", sender_projection_buckets=" << sender_projection_buckets.size()
             << ", max_sender_bucket_size=" << max_sender_bucket_size
             << ", receiver reported " << receiver_candidates
             << " expanded candidate pairs.\n";
    }

    cout << "\n--- MPC Sender Summary ---\n";
    cout << "Receiver reported " << total_candidates
         << " expanded exact-projection candidate pairs across " << K_ROUNDS << " rounds.\n";
    cout << "Party 0 private MPC inputs written: " << party0_inputs.size() << "\n";
    write_mpc_party_input_files(MPC_PARTY0_INPUT_TXT, MPC_SPDZ_PARTY0_INPUT_TXT, party0_inputs);
    cout << "Party 0 MPC inputs written to " << MPC_PARTY0_INPUT_TXT << "\n";
    cout << "MP-SPDZ Party 0 input written to " << MPC_SPDZ_PARTY0_INPUT_TXT << "\n";
}

void run_receiver(coproto::Socket& sock) {
    cout << "Party 1 starting PSI-style candidate generation receiver on exact projected keys.\n";

    long total_candidates = 0;
    vector<OpenMatch> opened_matches;
    vector<MpcCandidate> mpc_candidates;
    vector<MpcInputRecord> party1_inputs;
    u64 next_candidate_id = 0;

    for (int round = 0; round < K_ROUNDS; ++round) {
        vector<EncodedRecord> dataB;
        read_round_party_data(round, 1, dataB);
        const size_t payload_bits = validate_payload_bit_length(dataB, "Party 1", round);

        u64 sender_size = 0;
        macoro::sync_wait(sock.recv(sender_size));
        u64 sender_payload_bits = 0;
        macoro::sync_wait(sock.recv(sender_payload_bits));
        u64 sender_record_count = 0;
        macoro::sync_wait(sock.recv(sender_record_count));
        u64 max_sender_bucket_size = 0;
        macoro::sync_wait(sock.recv(max_sender_bucket_size));

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
        macoro::sync_wait(sock.send(static_cast<u64>(payload_bits)));

        if (sender_size && receiver_size && payload_bits != sender_payload_bits) {
            throw runtime_error("Sender/receiver payload bit length mismatch in round " + to_string(round));
        }

        size_t max_receiver_bucket_size = 0;
        for (const auto& bucket_records : receiver_row_records) {
            max_receiver_bucket_size = max(max_receiver_bucket_size, bucket_records.size());
        }

        u64 bucket_intersections_this_round = 0;
        u64 candidate_pairs_this_round = 0;
        const size_t packed_len = bucket_value_byte_length(payload_bits);

        if (sender_size == 0 || receiver_size == 0) {
            auto sender_flag_bytes = recv_vec<u8>(sock);
            auto sender_share_bytes = recv_vec<u8>(sock);
            if (!sender_flag_bytes.empty() || !sender_share_bytes.empty()) {
                throw runtime_error("Expected empty sender shares for empty PSI round");
            }

            total_candidates += static_cast<long>(candidate_pairs_this_round);
            send_vec(sock, vector<u64>{});
            macoro::sync_wait(sock.send(candidate_pairs_this_round));

            cout << "Round " << round
                 << ": party0_records=" << sender_record_count
                 << ", sender_projection_buckets=" << sender_size
                 << ", max_sender_bucket_size=" << max_sender_bucket_size
                 << ", party1_records=" << dataB.size()
                 << ", receiver_projection_buckets=" << receiver_projection_rows.size()
                 << ", max_receiver_bucket_size=" << max_receiver_bucket_size
                 << ", bucket_intersections=" << bucket_intersections_this_round
                 << ", expanded_candidate_pairs=" << candidate_pairs_this_round
                 << ", mpc_candidate_pairs=" << candidate_pairs_this_round
                 << ".\n";
            continue;
        }

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

        if (sender_flag_bytes.size() != share.mFlagBits.sizeBytes()) {
            throw runtime_error("Sender flag share size mismatch");
        }

        // Stage 2 handoff: PSI gives exact projection-bucket candidates. Each
        // expanded record pair receives a public candidate id. Party 1 writes
        // only Party 1 payloads locally, and sends candidate id + Party 0
        // record id back to Party 0 so Party 0 can write its own private input.
        vector<u64> assignment_words;
        for (size_t i = 0; i < keys.size(); ++i) {
            const auto output_row = share.mMapping[i];
            if (output_row == ~u64(0)) continue;
            if (output_row >= share.mValues.rows()) continue;
            if (output_row / 8 >= sender_flag_bytes.size()) continue;

            const bool sender_flag = (sender_flag_bytes[output_row / 8] >> (output_row % 8)) & 1u;
            const bool receiver_flag = share.mFlagBits[output_row];
            if (!(sender_flag ^ receiver_flag)) continue;

            ++bucket_intersections_this_round;

            const u8* receiver_row = &share.mValues(output_row, 0);
            const u8* sender_row = sender_share_bytes.data() + (output_row * share.mValues.cols());
            auto opened_value = xor_rows(
                std::span<const u8>(receiver_row, share.mValues.cols()),
                std::span<const u8>(sender_row, share.mValues.cols()));

            auto sender_values = deserialize_sender_bucket(opened_value, payload_bits);
            candidate_pairs_this_round +=
                static_cast<u64>(sender_values.size() * receiver_row_records[i].size());

            for (const auto& sender_value : sender_values) {
                for (size_t rec_index : receiver_row_records[i]) {
                    const auto& recB = dataB[rec_index];
                    const u64 candidate_id = next_candidate_id++;
                    mpc_candidates.push_back(MpcCandidate{
                        candidate_id,
                        round,
                        sender_value.index,
                        sender_value.name,
                        recB.index,
                        recB.name
                    });

                    party1_inputs.push_back(MpcInputRecord{
                        candidate_id,
                        recB.payload
                    });
                    assignment_words.push_back(candidate_id);
                    assignment_words.push_back(static_cast<u64>(sender_value.index));
                }
            }
        }

        total_candidates += static_cast<long>(candidate_pairs_this_round);
        send_vec(sock, assignment_words);
        macoro::sync_wait(sock.send(candidate_pairs_this_round));

        cout << "Round " << round
             << ": party0_records=" << sender_record_count
             << ", sender_projection_buckets=" << sender_size
             << ", max_sender_bucket_size=" << max_sender_bucket_size
             << ", party1_records=" << dataB.size()
             << ", receiver_projection_buckets=" << receiver_projection_rows.size()
             << ", max_receiver_bucket_size=" << max_receiver_bucket_size
             << ", bucket_intersections=" << bucket_intersections_this_round
             << ", expanded_candidate_pairs=" << candidate_pairs_this_round
             << ", mpc_candidate_pairs=" << candidate_pairs_this_round
             << ".\n";
    }

    cout << "\n--- MPC Fuzzy PSI Summary ---\n";
    cout << "Filtering mode: split-party MPC handoff for secret-shared Hamming threshold.\n";
    cout << "Total expanded exact-projection candidate pairs across " << K_ROUNDS << " rounds: "
         << total_candidates << "\n";
    cout << "MPC candidate inputs written: " << mpc_candidates.size() << "\n";
    cout << "Plaintext fuzzy pairs opened before MPC: " << opened_matches.size() << "\n";
    write_mpc_config(mpc_candidates.size());
    write_mpc_manifest_file(mpc_candidates);
    write_mpc_party_input_files(MPC_PARTY1_INPUT_TXT, MPC_SPDZ_PARTY1_INPUT_TXT, party1_inputs);
    write_opened_matches_csv(opened_matches);
    write_summary_file(total_candidates, opened_matches);
    cout << "MPC handoff manifest written to " << MPC_HANDOFF_MANIFEST_CSV << "\n";
    cout << "Party 0 MPC inputs written to " << MPC_PARTY0_INPUT_TXT << "\n";
    cout << "Party 1 MPC inputs written to " << MPC_PARTY1_INPUT_TXT << "\n";
    cout << "MP-SPDZ config written to " << MPC_CONFIG_MPC << "\n";
    cout << "MP-SPDZ Party 0 input written to " << MPC_SPDZ_PARTY0_INPUT_TXT << "\n";
    cout << "MP-SPDZ Party 1 input written to " << MPC_SPDZ_PARTY1_INPUT_TXT << "\n";
    cout << "Plaintext reference matches written to " << RECEIVER_MATCH_OUTPUT_CSV << "\n";
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
