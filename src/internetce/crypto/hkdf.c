/**
 * HKDF (HMAC Key Derivation Function) module
 * The HMAC Hash function is SHA256.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../include/crypto.h"
#include "../include/debug.h"


web_status_t hkdf_Extract(const uint8_t salt[], size_t salt_size, const uint8_t ikm[], size_t ikm_size, uint8_t prk[]) {
    uint8_t default_salt[CIPHER_SUITE_HASH_SIZE];
    const uint8_t *actual_salt = salt;
    if(salt == NULL) {
        memset(default_salt, 0, CIPHER_SUITE_HASH_SIZE);
        actual_salt = default_salt;
        salt_size = CIPHER_SUITE_HASH_SIZE;
    }

    return hkdf_HMAC(actual_salt, salt_size, ikm, ikm_size, prk);
}

web_status_t hkdf_Expand(const uint8_t prk[], const uint8_t info[], size_t info_size, uint8_t dst[], size_t dst_size) {
    web_status_t ret_val = WEB_NO_DATA;
    const unsigned int nb_iterations = (dst_size + CIPHER_SUITE_HASH_SIZE - 1) / CIPHER_SUITE_HASH_SIZE;
    const size_t max_context_size = CIPHER_SUITE_HASH_SIZE + info_size + 1;
    uint8_t previous_hash[CIPHER_SUITE_HASH_SIZE];
    uint8_t context_buffer[max_context_size];
    size_t context_buffer_size;
    size_t size_left = dst_size;
    for(unsigned int i=1; i<=nb_iterations; i++) {
        if(i != 1) {
            context_buffer_size = CIPHER_SUITE_HASH_SIZE + info_size + 1;
            memcpy(context_buffer, previous_hash, CIPHER_SUITE_HASH_SIZE);
            memcpy(context_buffer + CIPHER_SUITE_HASH_SIZE, info, info_size);
        } else {
            context_buffer_size = info_size + 1;
            memcpy(context_buffer, info, info_size);
        }
        context_buffer[context_buffer_size - 1] = i;

        ret_val = hkdf_HMAC(prk, CIPHER_SUITE_HASH_SIZE, context_buffer, context_buffer_size, previous_hash);
        if(ret_val != WEB_SUCCESS) {
            memset(dst, 0, i * CIPHER_SUITE_HASH_SIZE);
            break;
        }
        memcpy(dst + (i - 1) * CIPHER_SUITE_HASH_SIZE, previous_hash, min(size_left, CIPHER_SUITE_HASH_SIZE));
        size_left -= CIPHER_SUITE_HASH_SIZE;
    }

    /* Clearing any contextual info on the stack for security purposes */
    memset(previous_hash, 0, CIPHER_SUITE_HASH_SIZE);
    memset(context_buffer, 0, max_context_size);

    return ret_val;
}

web_status_t hkdf_ExpandLabel(const uint8_t secret[], const char *label, const uint8_t hash[], size_t hash_size,
                              uint8_t dst[], size_t dst_size) {
    const char *tls_str = "tls13 ";
    size_t hkdfLabel_size = sizeof(uint16_t) + 1 + strlen(tls_str) + strlen(label) + 1 + hash_size;
    uint8_t hkdfLabel[hkdfLabel_size];
    *(uint16_t *)hkdfLabel = htons(dst_size);

    uint8_t *buf_label = hkdfLabel + 2;
    buf_label[0] = strlen(tls_str) + strlen(label);
    memcpy(buf_label + 1, tls_str, strlen(tls_str));
    memcpy(buf_label + 1 + strlen(tls_str), label, strlen(label));

    uint8_t *buf_context = buf_label + 1 + strlen(tls_str) + strlen(label);
    buf_context[0] = hash_size;
    memcpy(buf_context + 1, hash, hash_size);

    return hkdf_Expand(secret, hkdfLabel, hkdfLabel_size, dst, dst_size);
}

web_status_t hkdf_HMAC(const uint8_t key[], size_t key_size, const uint8_t msg[], size_t size, uint8_t dst[]) {
    uint8_t padded_key[CIPHER_SUITE_BLOCK_SIZE];

    if(sha256_IsEnabled()) {
        dbg_err("SHA256 chip already in use");
        return WEB_SHA256_IN_USE;
    }

    if(key_size > CIPHER_SUITE_BLOCK_SIZE) {
        dbg_info("Key too long, hashing");
        sha256_Init();
        sha256_Part(key, key_size);
        sha256_Hash(padded_key);
        key_size = CIPHER_SUITE_HASH_SIZE;
    } else {
        memcpy(padded_key, key, key_size);
    }

    if(key_size != CIPHER_SUITE_BLOCK_SIZE) {
        memset(padded_key + key_size, 0, CIPHER_SUITE_BLOCK_SIZE - key_size);
    }

    uint8_t o_key_pad[CIPHER_SUITE_BLOCK_SIZE];
    uint8_t i_key_pad[CIPHER_SUITE_BLOCK_SIZE];
    for(size_t i = 0; i < CIPHER_SUITE_BLOCK_SIZE; i++) {
        o_key_pad[i] = padded_key[i] ^ 0x5c;
        i_key_pad[i] = padded_key[i] ^ 0x36;
    }

    sha256_Init();
    sha256_Part(i_key_pad, CIPHER_SUITE_BLOCK_SIZE);
    sha256_Part(msg, size);
    sha256_Hash(dst);  /* temp buffer for inner hash */

    sha256_Init();
    sha256_Part(o_key_pad, CIPHER_SUITE_BLOCK_SIZE);
    sha256_Part(dst, CIPHER_SUITE_HASH_SIZE);
    sha256_Hash(dst);

    /* Clearing any contextual info on the stack for security purposes */
    memset(o_key_pad, 0, CIPHER_SUITE_BLOCK_SIZE);
    memset(i_key_pad, 0, CIPHER_SUITE_BLOCK_SIZE);
    memset(padded_key, 0, CIPHER_SUITE_BLOCK_SIZE);

    return WEB_SUCCESS;
}
