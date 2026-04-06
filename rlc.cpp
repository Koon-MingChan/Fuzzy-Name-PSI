#include "rlc.h"

namespace approx_psi {

ProjectionConsistencyCheck::ProjectionConsistencyCheck(uint64_t seed) : seed_(seed) {}

bool ProjectionConsistencyCheck::verify_projection(
    const BitVector& original_vector,
    const BitVector& projected_vector,
    const std::vector<size_t>& mask) const {
    if (mask.size() != projected_vector.size()) return false;
    uint64_t state = seed_;
    uint64_t L1 = 0;
    uint64_t L2 = 0;
    for (size_t i = 0; i < mask.size(); ++i) {
        size_t idx = mask[i];
        if (idx >= original_vector.size()) return false;
        state = (state ^ (state << 13)) ^ (state >> 7) ^ (state << 17);
        uint64_t r = state | 1ULL;
        uint64_t ai = projected_vector[i] ? 1ULL : 0ULL;
        uint64_t aj = original_vector[idx] ? 1ULL : 0ULL;
        L1 += r * ai;
        L2 += r * aj;
    }
    return L1 == L2;
}

} // namespace approx_psi
