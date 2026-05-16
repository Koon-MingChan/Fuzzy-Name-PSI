#ifndef NAME_ENCODING_H
#define NAME_ENCODING_H

#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cryptoTools/Common/BitVector.h>

namespace approx_psi {

using BitVector = osuCrypto::BitVector;

struct NameEncodingConfig {
    size_t BITVECTOR_LENGTH;
    size_t GRAM_SIZE;
    bool USE_BOUNDARY_GRAMS = false;
    bool CANONICALIZE_BIGRAMS_FOR_TRANSPOSITION = false;
};

class NameEncoding {
public:
    explicit NameEncoding(NameEncodingConfig cfg = {});

    BitVector encode_name_base(const std::string& name) const;
    BitVector encode_name_tail_token(const std::string& name) const;
    BitVector encode_name_token_or(const std::string& name) const;

private:
    NameEncodingConfig cfg_;
    std::string normalize(const std::string& name, bool keep_hyphen) const;
    std::vector<std::string> tokenize(const std::string& clean) const;
    void apply_tail_token(std::vector<std::string>& tokens) const;
    uint64_t hash_gram(const std::string& gram) const;
    std::string feature_gram(const std::string& gram) const;
    BitVector encode_tokens_base(const std::vector<std::string>& tokens) const;
    void add_token_grams(BitVector& bv, const std::string& token) const;
    BitVector encode_tokens_individually(const std::vector<std::string>& tokens) const;
};

} // namespace approx_psi
#endif // NAME_ENCODING_H
