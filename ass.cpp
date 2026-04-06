#include "ass.h"
#include <stdexcept>

namespace approx_psi {

static uint64_t simple_mac_hash(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    uint64_t x = a ^ b ^ c ^ d;
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

AuthenticatedSecretSharing::AuthenticatedSecretSharing(uint64_t master_key)
    : master_key_(master_key) { }

uint64_t AuthenticatedSecretSharing::compute_mac(uint64_t value, uint32_t round_id, uint32_t share_idx) const {
    return simple_mac_hash(value, master_key_, round_id, share_idx);
}

std::pair<Share, Share> AuthenticatedSecretSharing::share(uint64_t value, uint32_t round_id) {
    uint64_t r = (static_cast<uint64_t>(round_id) << 32) ^ 0xCAFEBABEDEADBEEFULL;
    Share a{r, compute_mac(r, round_id, 0), 0};
    Share b{value - r, compute_mac(value - r, round_id, 1), 1};
    return {a, b};
}

bool AuthenticatedSecretSharing::verify(const Share& s, uint32_t round_id) const {
    if (s.key_id > 1) return false;
    uint64_t expected = compute_mac(s.value, round_id, s.key_id);
    return expected == s.mac;
}

Share AuthenticatedSecretSharing::add(const Share& a, const Share& b, uint32_t round_id) {
    if (!verify(a, round_id) || !verify(b, round_id)) {
        throw std::runtime_error("ASS verification failed in add");
    }
    Share out;
    out.value = a.value + b.value;
    out.key_id = a.key_id;
    out.mac = compute_mac(out.value, round_id, out.key_id);
    return out;
}

Share AuthenticatedSecretSharing::multiply_bit_vector(const Share& a, const Share& b, uint32_t round_id) {
    if (!verify(a, round_id) || !verify(b, round_id)) {
        throw std::runtime_error("ASS verification failed in multiply_bit_vector");
    }
    if ((a.value != 0 && a.value != 1) || (b.value != 0 && b.value != 1)) {
        throw std::runtime_error("multiply_bit_vector requires bit shares");
    }
    Share out;
    out.value = a.value & b.value;
    out.key_id = a.key_id;
    out.mac = compute_mac(out.value, round_id, out.key_id);
    return out;
}

} // namespace approx_psi
