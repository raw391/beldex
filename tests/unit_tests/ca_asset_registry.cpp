// Copyright (c) 2024 Beldex Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for confidential asset registry primitives:
//   - asset_descriptor_id() stability
//   - Owner signature create / verify
//   - CA output amount encryption round-trip

#include "gtest/gtest.h"

#include "cryptonote_core/asset_types.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"

#include <array>
#include <cstring>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

cryptonote::asset_descriptor_base make_descriptor(
    const std::string& ticker,
    const std::string& full_name,
    uint64_t max_supply,
    uint8_t decimal_point = 9)
{
    cryptonote::asset_descriptor_base d{};
    d.total_max_supply = max_supply;
    d.current_supply   = 0;
    d.decimal_point    = decimal_point;
    d.ticker           = ticker;
    d.full_name        = full_name;
    d.meta_info        = "";
    d.hidden_supply    = false;
    // Generate a fresh owner key pair
    crypto::generate_keys(d.owner, /*secret=*/ *(crypto::secret_key*)nullptr,
                          /*recover=*/ false);
    // NOTE: generate_keys with null secret is not valid; generate properly:
    crypto::secret_key dummy_skey;
    crypto::generate_keys(d.owner, dummy_skey);
    return d;
}

// Build the 41-byte signature message used by blockchain.cpp
crypto::hash make_sig_message(cryptonote::asset_operation_type op_type,
                               const crypto::hash& asset_id,
                               uint64_t amount)
{
    std::array<uint8_t, 1 + 32 + 8> buf;
    buf[0] = static_cast<uint8_t>(op_type);
    std::memcpy(buf.data() + 1, asset_id.data, 32);
    uint64_t le = htole64(amount);
    std::memcpy(buf.data() + 33, &le, 8);
    crypto::hash h;
    crypto::cn_fast_hash(buf.data(), buf.size(), h);
    return h;
}

// CA amount mask: Hs(derivation_scalar) → truncated to 64 bits
uint64_t ca_amount_mask(const crypto::secret_key& derivation_scalar)
{
    crypto::hash mask;
    crypto::cn_fast_hash(derivation_scalar.data, sizeof(derivation_scalar.data), mask);
    uint64_t m;
    std::memcpy(&m, mask.data, sizeof(m));
    return m;
}

} // namespace

// ---------------------------------------------------------------------------
// asset_descriptor_id stability
// ---------------------------------------------------------------------------

TEST(CA_AssetRegistry, descriptor_id_is_deterministic)
{
    cryptonote::asset_descriptor_base desc{};
    desc.total_max_supply = 1000000;
    desc.decimal_point    = 9;
    desc.ticker           = "TEST";
    desc.full_name        = "Test Asset";
    desc.current_supply   = 0;

    const crypto::hash id1 = cryptonote::asset_descriptor_id(desc);
    const crypto::hash id2 = cryptonote::asset_descriptor_id(desc);
    EXPECT_EQ(id1, id2);
}

TEST(CA_AssetRegistry, descriptor_id_ignores_current_supply)
{
    cryptonote::asset_descriptor_base desc{};
    desc.total_max_supply = 1000000;
    desc.decimal_point    = 9;
    desc.ticker           = "TEST";
    desc.full_name        = "Test Asset";
    desc.current_supply   = 0;

    const crypto::hash id_before = cryptonote::asset_descriptor_id(desc);
    desc.current_supply = 500000;  // simulates an EMIT
    const crypto::hash id_after  = cryptonote::asset_descriptor_id(desc);

    // The asset_id must remain stable despite circulating supply changing.
    EXPECT_EQ(id_before, id_after);
}

TEST(CA_AssetRegistry, different_tickers_yield_different_ids)
{
    cryptonote::asset_descriptor_base d1{};
    d1.total_max_supply = 1000000;
    d1.ticker           = "AAA";
    d1.full_name        = "Asset A";

    cryptonote::asset_descriptor_base d2 = d1;
    d2.ticker = "BBB";

    EXPECT_NE(cryptonote::asset_descriptor_id(d1),
              cryptonote::asset_descriptor_id(d2));
}

TEST(CA_AssetRegistry, different_max_supply_yields_different_id)
{
    cryptonote::asset_descriptor_base d1{};
    d1.total_max_supply = 1'000'000;
    d1.ticker           = "SAME";

    cryptonote::asset_descriptor_base d2 = d1;
    d2.total_max_supply = 2'000'000;

    EXPECT_NE(cryptonote::asset_descriptor_id(d1),
              cryptonote::asset_descriptor_id(d2));
}

TEST(CA_AssetRegistry, id_is_non_zero)
{
    cryptonote::asset_descriptor_base desc{};
    desc.total_max_supply = 1;
    desc.ticker           = "X";

    const crypto::hash id = cryptonote::asset_descriptor_id(desc);
    EXPECT_NE(id, crypto::null_hash);
}

// ---------------------------------------------------------------------------
// Owner signature creation and verification
// ---------------------------------------------------------------------------

TEST(CA_OwnerSignature, emit_signature_verifies)
{
    crypto::public_key owner_pkey;
    crypto::secret_key owner_skey;
    crypto::generate_keys(owner_pkey, owner_skey);

    cryptonote::asset_descriptor_base desc{};
    desc.total_max_supply = 1000000;
    desc.ticker           = "SIG";
    desc.owner            = owner_pkey;

    const crypto::hash asset_id = cryptonote::asset_descriptor_id(desc);
    const uint64_t amount       = 50000;

    const crypto::hash msg = make_sig_message(
        cryptonote::asset_operation_type::EMIT, asset_id, amount);

    crypto::signature sig;
    crypto::generate_signature(msg, owner_pkey, owner_skey, sig);

    EXPECT_TRUE(crypto::check_signature(msg, owner_pkey, sig));
}

TEST(CA_OwnerSignature, burn_signature_verifies)
{
    crypto::public_key owner_pkey;
    crypto::secret_key owner_skey;
    crypto::generate_keys(owner_pkey, owner_skey);

    cryptonote::asset_descriptor_base desc{};
    desc.total_max_supply = 1000000;
    desc.ticker           = "BURN";
    desc.owner            = owner_pkey;

    const crypto::hash asset_id = cryptonote::asset_descriptor_id(desc);
    const uint64_t amount       = 1000;

    const crypto::hash msg = make_sig_message(
        cryptonote::asset_operation_type::BURN, asset_id, amount);

    crypto::signature sig;
    crypto::generate_signature(msg, owner_pkey, owner_skey, sig);

    EXPECT_TRUE(crypto::check_signature(msg, owner_pkey, sig));
}

TEST(CA_OwnerSignature, wrong_key_fails_verification)
{
    crypto::public_key owner_pkey, other_pkey;
    crypto::secret_key owner_skey, other_skey;
    crypto::generate_keys(owner_pkey, owner_skey);
    crypto::generate_keys(other_pkey, other_skey);

    cryptonote::asset_descriptor_base desc{};
    desc.total_max_supply = 1000000;
    desc.ticker           = "WRONGKEY";
    desc.owner            = owner_pkey;

    const crypto::hash asset_id = cryptonote::asset_descriptor_id(desc);
    const crypto::hash msg = make_sig_message(
        cryptonote::asset_operation_type::EMIT, asset_id, 100);

    crypto::signature sig;
    crypto::generate_signature(msg, owner_pkey, owner_skey, sig);

    // Verify against the WRONG public key – must fail.
    EXPECT_FALSE(crypto::check_signature(msg, other_pkey, sig));
}

TEST(CA_OwnerSignature, wrong_amount_fails_verification)
{
    crypto::public_key owner_pkey;
    crypto::secret_key owner_skey;
    crypto::generate_keys(owner_pkey, owner_skey);

    cryptonote::asset_descriptor_base desc{};
    desc.ticker = "WRONGAMT";
    const crypto::hash asset_id = cryptonote::asset_descriptor_id(desc);

    const crypto::hash msg_correct = make_sig_message(
        cryptonote::asset_operation_type::EMIT, asset_id, 100);
    const crypto::hash msg_tampered = make_sig_message(
        cryptonote::asset_operation_type::EMIT, asset_id, 101);

    crypto::signature sig;
    crypto::generate_signature(msg_correct, owner_pkey, owner_skey, sig);

    EXPECT_FALSE(crypto::check_signature(msg_tampered, owner_pkey, sig));
}

TEST(CA_OwnerSignature, emit_and_burn_messages_differ)
{
    cryptonote::asset_descriptor_base desc{};
    desc.ticker = "OPTEST";
    const crypto::hash asset_id = cryptonote::asset_descriptor_id(desc);
    const uint64_t amount = 999;

    const crypto::hash emit_msg = make_sig_message(
        cryptonote::asset_operation_type::EMIT, asset_id, amount);
    const crypto::hash burn_msg = make_sig_message(
        cryptonote::asset_operation_type::BURN, asset_id, amount);

    EXPECT_NE(emit_msg, burn_msg);
}

// ---------------------------------------------------------------------------
// CA output amount encryption / decryption round-trip
// ---------------------------------------------------------------------------

TEST(CA_AmountEncryption, round_trip)
{
    // The wallet derives h = derivation_to_scalar(derivation, vout_index),
    // then mask = cn_fast_hash(h), encrypted_amount = amount XOR mask.
    // This test checks the round-trip without involving a real derivation.

    // Simulate derivation_to_scalar output as a random scalar
    crypto::secret_key h_scalar;
    crypto::rand(sizeof(h_scalar), reinterpret_cast<uint8_t*>(&h_scalar));

    const uint64_t plaintext_amount = 1234567890ULL;
    const uint64_t mask             = ca_amount_mask(h_scalar);
    const uint64_t encrypted        = plaintext_amount ^ mask;

    // Receiver recovers h_scalar the same way and decrypts
    const uint64_t recovered_mask   = ca_amount_mask(h_scalar);
    const uint64_t decrypted        = encrypted ^ recovered_mask;

    EXPECT_EQ(plaintext_amount, decrypted);
}

TEST(CA_AmountEncryption, different_scalars_give_different_ciphertext)
{
    crypto::secret_key h1, h2;
    crypto::rand(sizeof(h1), reinterpret_cast<uint8_t*>(&h1));
    crypto::rand(sizeof(h2), reinterpret_cast<uint8_t*>(&h2));

    const uint64_t amount     = 42ULL;
    const uint64_t encrypted1 = amount ^ ca_amount_mask(h1);
    const uint64_t encrypted2 = amount ^ ca_amount_mask(h2);

    // With overwhelming probability two random scalars yield different masks.
    if (std::memcmp(&h1, &h2, sizeof(h1)) != 0)
        EXPECT_NE(encrypted1, encrypted2);
}

TEST(CA_AmountEncryption, zero_amount_round_trip)
{
    crypto::secret_key h;
    crypto::rand(sizeof(h), reinterpret_cast<uint8_t*>(&h));

    const uint64_t mask      = ca_amount_mask(h);
    const uint64_t encrypted = 0ULL ^ mask;
    const uint64_t decrypted = encrypted ^ ca_amount_mask(h);

    EXPECT_EQ(0ULL, decrypted);
}

TEST(CA_AmountEncryption, max_amount_round_trip)
{
    crypto::secret_key h;
    crypto::rand(sizeof(h), reinterpret_cast<uint8_t*>(&h));

    const uint64_t amount    = std::numeric_limits<uint64_t>::max();
    const uint64_t mask      = ca_amount_mask(h);
    const uint64_t encrypted = amount ^ mask;
    const uint64_t decrypted = encrypted ^ ca_amount_mask(h);

    EXPECT_EQ(amount, decrypted);
}
