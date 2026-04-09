#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "quoting_enclave_tdqe.h"
#include "tdqe_mldsa_adapter.h"

int main(void)
{
    uint8_t public_key[SGX_QL_MLDSA_65_PUB_KEY_SIZE] = {0};
    uint8_t private_key[TDQE_MLDSA_65_PRIVATE_KEY_SIZE] = {0};
    uint8_t signature[SGX_QL_MLDSA_65_SIG_SIZE] = {0};
    uint8_t seed[TDQE_MLDSA_65_SEED_SIZE] = {0};
    uint8_t seed_again[TDQE_MLDSA_65_SEED_SIZE] = {0};
    uint8_t public_key_again[SGX_QL_MLDSA_65_PUB_KEY_SIZE] = {0};
    uint8_t private_key_again[TDQE_MLDSA_65_PRIVATE_KEY_SIZE] = {0};
    uint8_t seed_other[TDQE_MLDSA_65_SEED_SIZE] = {0};
    uint8_t public_key_other[SGX_QL_MLDSA_65_PUB_KEY_SIZE] = {0};
    uint8_t private_key_other[TDQE_MLDSA_65_PRIVATE_KEY_SIZE] = {0};
    uint8_t tampered_message[48] = {
        0x54, 0x44, 0x58, 0x2d, 0x50, 0x51, 0x2d, 0x61,
        0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69,
        0x6f, 0x6e, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d,
        0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2d, 0x30,
        0x31, 0x2d, 0x6d, 0x6c, 0x64, 0x73, 0x61, 0x2d,
        0x36, 0x35, 0x2d, 0x6f, 0x6b, 0x21, 0x21, 0x21
    };
    const uint8_t message[48] = {
        0x54, 0x44, 0x58, 0x2d, 0x50, 0x51, 0x2d, 0x61,
        0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69,
        0x6f, 0x6e, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d,
        0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x2d, 0x30,
        0x31, 0x2d, 0x6d, 0x6c, 0x64, 0x73, 0x61, 0x2d,
        0x36, 0x35, 0x2d, 0x6f, 0x6b, 0x21, 0x21, 0x21
    };
    size_t i = 0;

    for (i = 0; i < TDQE_MLDSA_65_SEED_SIZE; ++i) {
        seed[i] = (uint8_t)i;
        seed_again[i] = (uint8_t)i;
        seed_other[i] = (uint8_t)(0xA0u + i);
    }

    if (0 != tdqe_mldsa65_keygen(public_key, private_key, seed)) {
        fprintf(stderr, "[test] tdqe_mldsa65_keygen failed\n");
        return 1;
    }

    if (0 != tdqe_mldsa65_sign(signature, message, sizeof(message), private_key)) {
        fprintf(stderr, "[test] tdqe_mldsa65_sign failed\n");
        return 1;
    }

    if (0 != tdqe_mldsa65_verify(signature, message, sizeof(message), public_key)) {
        fprintf(stderr, "[test] tdqe_mldsa65_verify failed for valid signature\n");
        return 1;
    }

    tampered_message[0] ^= 0x01u;
    if (0 == tdqe_mldsa65_verify(signature, tampered_message, sizeof(tampered_message), public_key)) {
        fprintf(stderr, "[test] tdqe_mldsa65_verify unexpectedly accepted a tampered message\n");
        return 1;
    }

    signature[0] ^= 0x01u;
    if (0 == tdqe_mldsa65_verify(signature, message, sizeof(message), public_key)) {
        fprintf(stderr, "[test] tdqe_mldsa65_verify unexpectedly accepted a tampered signature\n");
        return 1;
    }
    signature[0] ^= 0x01u;

    if (0 != tdqe_mldsa65_keygen(public_key_again, private_key_again, seed_again)) {
        fprintf(stderr, "[test] tdqe_mldsa65_keygen failed on repeated deterministic seed\n");
        return 1;
    }

    if ((0 != memcmp(public_key, public_key_again, sizeof(public_key))) ||
        (0 != memcmp(private_key, private_key_again, sizeof(private_key)))) {
        fprintf(stderr, "[test] tdqe_mldsa65_keygen is not deterministic for the same seed\n");
        return 1;
    }

    if (0 != tdqe_mldsa65_keygen(public_key_other, private_key_other, seed_other)) {
        fprintf(stderr, "[test] tdqe_mldsa65_keygen failed on second seed\n");
        return 1;
    }

    if (0 == memcmp(public_key, public_key_other, sizeof(public_key))) {
        fprintf(stderr, "[test] tdqe_mldsa65_keygen produced the same public key for different seeds\n");
        return 1;
    }

    printf("[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK\n");
    printf("[test] sizes: pub=%zu priv=%zu sig=%zu\n",
           sizeof(public_key),
           sizeof(private_key),
           sizeof(signature));
    return 0;
}
