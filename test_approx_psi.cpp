#include "name_encoding.h"
#include "ass.h"
#include "rlc.h"
#include <cassert>
#include <iostream>

using namespace approx_psi;

int main() {
    // Name encoding test
    NameEncoding encoder({1024, 3});
    auto v = encoder.encode_name_tail_token("Alice Smith");
    assert(v.size() <= 1024);
    auto v2 = encoder.encode_name_tail_token("Alice Smith");
    assert(v == v2);

    // ASS test
    AuthenticatedSecretSharing ass(0x1234567890ABCDEFULL);
    auto [a0, a1] = ass.share(42ULL, 7);
    assert(ass.verify(a0, 7));
    assert(ass.verify(a1, 7));
    auto sum0 = ass.add(a0, a0, 7);
    assert(ass.verify(sum0, 7));
    {
        Share bad = a0; bad.mac = 0;
        assert(!ass.verify(bad, 7) && "tampered share should fail");
    }

    // RLC test
    ProjectionConsistencyCheck checker(0x1234);
    // original vector length 20
    approx_psi::BitVector original(20, false);
    original[2] = true;
    original[5] = true;
    original[7] = true;

    std::vector<size_t> mask {2, 7, 5};
    approx_psi::BitVector projected{true, true, true};
    assert(checker.verify_projection(original, projected, mask));

    projected[1] = false;
    assert(!checker.verify_projection(original, projected, mask));

    std::cout << "All tests passed.\n";
    return 0;
}
