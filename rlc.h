#pragma once
#include "name_encoding.h"
#include <cstdint>
#include <vector>

namespace approx_psi {

class ProjectionConsistencyCheck {
public:
    explicit ProjectionConsistencyCheck(uint64_t seed = 0xFACEFEED12345678ULL);
    bool verify_projection(
        const BitVector& original_vector,
        const BitVector& projected_vector,
        const std::vector<size_t>& mask) const;

private:
    uint64_t seed_;
};

} // namespace approx_psi
