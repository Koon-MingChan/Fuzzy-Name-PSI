#include "name_encoding.h"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <functional>
#include <unordered_map>
#include <cryptoTools/Common/BitVector.h>

namespace approx_psi {
namespace {

const std::unordered_map<std::string, std::string>& diacritic_map() {
    static const std::unordered_map<std::string, std::string> table = {
        {"À", "A"}, {"Á", "A"}, {"Â", "A"}, {"Ã", "A"}, {"Ä", "A"}, {"Å", "A"},
        {"à", "A"}, {"á", "A"}, {"â", "A"}, {"ã", "A"}, {"ä", "A"}, {"å", "A"},
        {"Ā", "A"}, {"ā", "A"}, {"Ă", "A"}, {"ă", "A"}, {"Ą", "A"}, {"ą", "A"},
        {"Ǎ", "A"}, {"ǎ", "A"},
        {"Ç", "C"}, {"ç", "C"}, {"Ć", "C"}, {"ć", "C"}, {"Č", "C"}, {"č", "C"},
        {"Đ", "D"}, {"đ", "D"}, {"Ð", "D"}, {"ð", "D"},
        {"È", "E"}, {"É", "E"}, {"Ê", "E"}, {"Ë", "E"},
        {"è", "E"}, {"é", "E"}, {"ê", "E"}, {"ë", "E"},
        {"Ē", "E"}, {"ē", "E"}, {"Ė", "E"}, {"ė", "E"}, {"Ě", "E"}, {"ě", "E"},
        {"Ğ", "G"}, {"ğ", "G"},
        {"Ì", "I"}, {"Í", "I"}, {"Î", "I"}, {"Ï", "I"},
        {"ì", "I"}, {"í", "I"}, {"î", "I"}, {"ï", "I"},
        {"Ī", "I"}, {"ī", "I"}, {"İ", "I"}, {"ı", "I"}, {"Ǐ", "I"}, {"ǐ", "I"},
        {"Ļ", "L"}, {"ļ", "L"}, {"Ł", "L"}, {"ł", "L"},
        {"Ñ", "N"}, {"ñ", "N"}, {"Ń", "N"}, {"ń", "N"}, {"Ņ", "N"}, {"ņ", "N"},
        {"Ò", "O"}, {"Ó", "O"}, {"Ô", "O"}, {"Õ", "O"}, {"Ö", "O"}, {"Ø", "O"},
        {"ò", "O"}, {"ó", "O"}, {"ô", "O"}, {"õ", "O"}, {"ö", "O"}, {"ø", "O"},
        {"Ō", "O"}, {"ō", "O"},
        {"Ř", "R"}, {"ř", "R"},
        {"Ś", "S"}, {"ś", "S"}, {"Ş", "S"}, {"ş", "S"}, {"Š", "S"}, {"š", "S"},
        {"Ț", "T"}, {"ț", "T"}, {"Þ", "TH"}, {"þ", "TH"},
        {"Ù", "U"}, {"Ú", "U"}, {"Û", "U"}, {"Ü", "U"},
        {"ù", "U"}, {"ú", "U"}, {"û", "U"}, {"ü", "U"},
        {"Ū", "U"}, {"ū", "U"}, {"Ŭ", "U"}, {"ŭ", "U"}, {"Ǔ", "U"}, {"ǔ", "U"},
        {"Ý", "Y"}, {"ý", "Y"},
        {"Ź", "Z"}, {"ź", "Z"}, {"Ž", "Z"}, {"ž", "Z"},
        {"С", "S"}, {"с", "S"}, {"е", "E"}, {"Е", "E"}, {"р", "R"}, {"Р", "R"},
        {"и", "I"}, {"И", "I"}, {"к", "K"}, {"К", "K"}, {"а", "A"}, {"А", "A"},
        {"б", "B"}, {"Б", "B"}, {"й", "Y"}, {"Й", "Y"}
    };
    return table;
}

size_t utf8_char_length(unsigned char c) {
    if ((c & 0x80) == 0) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

} // namespace

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
    for (size_t i = 0; i < name.size();) {
        unsigned char c = static_cast<unsigned char>(name[i]);
        if (c >= 0x80) {
            const size_t char_len = std::min(utf8_char_length(c), name.size() - i);
            const std::string utf8_char = name.substr(i, char_len);
            const auto mapped = diacritic_map().find(utf8_char);
            if (mapped != diacritic_map().end()) {
                out += mapped->second;
            }
            i += char_len;
            continue;
        }

        if (std::isspace(static_cast<unsigned char>(c))) {
            out.push_back(' ');
            ++i;
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
        ++i;
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
            extra.push_back(head);
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

void NameEncoding::add_token_grams(BitVector& bv, const std::string& token) const {
    if (token.empty()) return;

    std::string source = token;

    // Boundary-aware q-grams:
    // Example for q=2:
    // JULEN -> ^J, JU, UL, LE, EN, N$
    // E     -> ^E, E$
    if (cfg_.USE_BOUNDARY_GRAMS) {
        source = "^" + token + "$";
    }

    if (source.size() < cfg_.GRAM_SIZE) return;

    for (size_t i = 0; i + cfg_.GRAM_SIZE <= source.size(); ++i) {
        std::string gram = source.substr(i, cfg_.GRAM_SIZE);
        uint64_t h = hash_gram(gram);
        size_t idx = static_cast<size_t>(h % bv.size());
        bv[idx] = 1;
    }
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
    
    if (cfg_.USE_BOUNDARY_GRAMS) {
        // Boundary-aware mode:
        // Encode each sorted token independently with boundary markers.
        // This avoids cross-token grams and preserves token start/end evidence.
        sorted_tok.erase(std::unique(sorted_tok.begin(), sorted_tok.end()), sorted_tok.end());

        for (const auto& token : sorted_tok) {
            add_token_grams(bv, token);
        }
    
        return bv;
    }

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

BitVector NameEncoding::encode_tokens_individually(const std::vector<std::string>& tokens) const {
    if (cfg_.BITVECTOR_LENGTH == 0) {
        throw std::runtime_error("BitVector length is 0. Check NameEncodingConfig initialization.");
    }

    BitVector bv;
    bv.reset(cfg_.BITVECTOR_LENGTH);

    std::vector<std::string> sorted_tok = tokens;
    std::sort(sorted_tok.begin(), sorted_tok.end());
    sorted_tok.erase(std::unique(sorted_tok.begin(), sorted_tok.end()), sorted_tok.end());

    for (const auto& token : sorted_tok) {
        add_token_grams(bv, token);
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

    for (auto& token : tokens) {
        token.erase(std::remove(token.begin(), token.end(), '-'), token.end());
    }

    return encode_tokens_individually(tokens);
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
