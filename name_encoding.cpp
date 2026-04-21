#include "name_encoding.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <functional>
#include <cryptoTools/Common/BitVector.h>

namespace approx_psi {
NameEncoding::NameEncoding(NameEncodingConfig cfg) : cfg_(std::move(cfg)) {
    std::cout << "[DEBUG] Encoder Init: BV_LEN=" << cfg_.BITVECTOR_LENGTH 
              << ", GRAM=" << cfg_.GRAM_SIZE << std::endl;
    if (cfg_.BITVECTOR_LENGTH == 0) {
        throw std::invalid_argument("BITVECTOR_LENGTH must be >0");
    }
    if (cfg_.GRAM_SIZE == 0) {
        throw std::invalid_argument("GRAM_SIZE must be >0");
    }
}

std::string NameEncoding::normalize(const std::string& name, bool keep_hyphen) const {
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            out.push_back(' ');
            continue;
        }
        if (std::isalnum(static_cast<unsigned char>(c))) {
            out.push_back(std::toupper(static_cast<unsigned char>(c)));
        } else if (c == '-') {
            // Smart Fix: Keep it as a trigger for Tail Token, 
            // otherwise convert to space for standard tokenization.
            if (keep_hyphen) {
                out.push_back('-');
            } else {
                out.push_back(' '); 
            }
        }
    }
    return out;
}

std::vector<std::string> NameEncoding::tokenize(const std::string& clean) const {
    std::istringstream iss(clean);
    std::vector<std::string> tokens;
    std::string tok;
    while (iss >> tok) {
        if (!tok.empty()) tokens.push_back(tok);
    }
    return tokens;
}

void NameEncoding::apply_tail_token(std::vector<std::string>& tokens) const {
    std::vector<std::string> extra;
    for (auto& t : tokens) {
        size_t p = t.find('-');
        if (p != std::string::npos && p + 1 < t.size()) {
            std::string head = t.substr(0, p);
            std::string tail = t.substr(p + 1);
            std::string full = head + tail;
            extra.push_back(full);
            extra.push_back(tail);
        }
    }
    for (auto& e : extra) tokens.push_back(e);
}

uint64_t NameEncoding::hash_gram(const std::string& gram) const {
    std::hash<std::string> hasher;
    return static_cast<uint64_t>(hasher(gram));
}

BitVector NameEncoding::encode_tokens_base(const std::vector<std::string>& tokens) const {
    // 1. SAFETY CHECK: Ensure length is valid
    if (cfg_.BITVECTOR_LENGTH == 0) {
        throw std::runtime_error("BitVector length is 0. Check NameEncodingConfig initialization.");
    }

    BitVector bv;
    bv.reset(cfg_.BITVECTOR_LENGTH); // This allocates AND zeros out the memory safely

    std::vector<std::string> sorted_tok = tokens;
    std::sort(sorted_tok.begin(), sorted_tok.end());
    
    std::string concat;
    for (const auto& t : sorted_tok) {
        concat += t;
    }

    if (concat.size() < cfg_.GRAM_SIZE) return bv;

    for (size_t i = 0; i + cfg_.GRAM_SIZE <= concat.size(); ++i) {
        std::string gram = concat.substr(i, cfg_.GRAM_SIZE);
        uint64_t h = hash_gram(gram);
        
        // 2. MODULO: Double check the size at runtime
        size_t idx = static_cast<size_t>(h % bv.size()); 
        
        bv[idx] = 1; // Use 1 instead of true for osuCrypto types
    }
    
    return bv;
}

BitVector NameEncoding::encode_name_base(const std::string& name) const {
    auto cleaned = normalize(name, false);
    auto tokens = tokenize(cleaned);
    return encode_tokens_base(tokens);
}

BitVector NameEncoding::encode_name_tail_token(const std::string& name) const {
    auto cleaned = normalize(name, true);
    auto tokens = tokenize(cleaned);
    apply_tail_token(tokens);
    return encode_tokens_base(tokens);
}

BitVector NameEncoding::encode_name_token_or(const std::string& name) const {
    auto cleaned = normalize(name, false);
    auto tokens = tokenize(cleaned);
    BitVector combined;
    combined.reset(cfg_.BITVECTOR_LENGTH);
    for (auto& token : tokens) {
        std::vector<std::string> single{token};
        auto token_bv = encode_tokens_base(single);
        for (size_t i = 0; i < cfg_.BITVECTOR_LENGTH; ++i) {
            combined[i] = combined[i] || token_bv[i];
        }
    }
    return combined;
}

} // namespace approx_psi
