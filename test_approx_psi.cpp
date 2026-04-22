#include "name_encoding.h"
#include "ass.h"
#include "rlc.h"
#include <cassert>
#include <iostream>
#include <stdexcept>

using namespace approx_psi;

namespace {

uint64_t reconstruct_value(const Share& a, const Share& b) {
    return a.value + b.value;
}

void log_pass(const char* test_name) {
    std::cout << "[PASS] " << test_name << "\n";
}

void test_name_encoding() {
    NameEncoding encoder({1024, 3});
    auto v = encoder.encode_name_tail_token("Alice Smith");
    assert(v.size() <= 1024);
    log_pass("NameEncoding: output size stays within configured bit-vector length");

    auto v2 = encoder.encode_name_tail_token("Alice Smith");
    assert(v == v2);
    log_pass("NameEncoding: repeated encoding is deterministic");

    auto v3 = encoder.encode_name_tail_token("ALICE-SMITH");
    auto v4 = encoder.encode_name_tail_token("SMITH ALICE");
    assert(v3.size() == v4.size());
    log_pass("NameEncoding: variant inputs still produce compatible encoded vectors");

    auto v5 = encoder.encode_name_tail_token("SIMON BARON-COHEN");
    auto v6 = encoder.encode_name_tail_token("SIMON COHEN");
    assert(v5 != v6);
    log_pass("NameEncoding: Tail-Token preserves distinctness while sharing hyphen-derived evidence");
}

void test_ass() {
    AuthenticatedSecretSharing ass(0x1234567890ABCDEFULL);
    constexpr uint32_t round = 7;
    constexpr uint64_t secret = 42ULL;

    auto [a0, a1] = ass.share(secret, round);
    assert(ass.verify(a0, round));
    assert(ass.verify(a1, round));
    assert(reconstruct_value(a0, a1) == secret);
    log_pass("ASS: shares verify and reconstruct the original value");

    // Shares should be bound to the round they were created in.
    assert(!ass.verify(a0, round + 1));
    assert(!ass.verify(a1, round + 1));
    log_pass("ASS: wrong-round verification is rejected");

    // Tampering any authenticated field should fail verification.
    {
        Share bad = a0;
        bad.value ^= 1ULL;
        assert(!ass.verify(bad, round));
        log_pass("ASS: altered share value is detected");
    }
    {
        Share bad = a0;
        bad.mac = 0;
        assert(!ass.verify(bad, round));
        log_pass("ASS: altered MAC is detected");
    }
    {
        Share bad = a0;
        bad.key_id = 9;
        assert(!ass.verify(bad, round));
        log_pass("ASS: altered key_id is detected");
    }

    auto sum0 = ass.add(a0, a0, round);
    assert(ass.verify(sum0, round));
    assert(sum0.value == a0.value + a0.value);
    log_pass("ASS: add() preserves verifiability");

    bool threw = false;
    try {
        auto [bit_a, bit_b] = ass.share(1ULL, round);
        (void)bit_a;
        ass.multiply_bit_vector(bit_b, bit_b, round);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw && "multiply_bit_vector should reject non-bit-valued ASS shares");
    log_pass("ASS: multiply_bit_vector rejects non-bit-valued ASS shares");
}

void test_rlc() {
    ProjectionConsistencyCheck checker(0x1234);

    BitVector original(20);
    original[2] = true;
    original[5] = true;
    original[7] = true;

    std::vector<size_t> mask{2, 7, 5};
    BitVector projected(3);
    projected[0] = true;
    projected[1] = true;
    projected[2] = true;
    assert(checker.verify_projection(original, projected, mask));
    log_pass("RLC: correct projection passes verification");

    {
        BitVector bad = projected;
        bad[1] = false;
        assert(!checker.verify_projection(original, bad, mask));
        log_pass("RLC: altered projected bit is detected");
    }
    {
        BitVector short_proj(2);
        short_proj[0] = true;
        short_proj[1] = true;
        assert(!checker.verify_projection(original, short_proj, mask));
        log_pass("RLC: wrong projection length is detected");
    }
    {
        std::vector<size_t> bad_mask{2, 7, 25};
        assert(!checker.verify_projection(original, projected, bad_mask));
        log_pass("RLC: invalid mask index is detected");
    }
    {
        BitVector altered_original = original;
        altered_original[7] = false;
        assert(!checker.verify_projection(altered_original, projected, mask));
        log_pass("RLC: altered original vector is detected");
    }
}

} // namespace

int main() {
    test_name_encoding();
    test_ass();
    test_rlc();

    std::cout << "All tests passed.\n";
    return 0;
}
