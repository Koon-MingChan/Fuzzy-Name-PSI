#pragma once
#include <cstdint>
#include <utility>

namespace approx_psi {

struct Share {
    uint64_t value;
    uint64_t mac;
    uint32_t key_id;
};

class AuthenticatedSecretSharing {
public:
    explicit AuthenticatedSecretSharing(uint64_t master_key = 0xDEADBEEFCAFEBABEULL);
    std::pair<Share, Share> share(uint64_t value, uint32_t round_id);
    Share add(const Share& a, const Share& b, uint32_t round_id);
    Share multiply_bit_vector(const Share& a, const Share& b, uint32_t round_id);
    bool verify(const Share& s, uint32_t round_id) const;

private:
    uint64_t master_key_;
    uint64_t compute_mac(uint64_t value, uint32_t round_id, uint32_t share_idx) const;
};

} // namespace approx_psi
