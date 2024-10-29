/**
 * HKDF (HMAC Key Derivation Function) module
 * The HMAC Hash function is SHA256.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../include/crypto.h"
#include "../include/debug.h"


web_status_t hkdf_Extract(const void *salt, size_t salt_size, const void *ikm, size_t ikm_size, uint8_t prk[SHA256_HASH_SIZE]) {
    uint8_t default_salt[SHA256_HASH_SIZE];
    const void *actual_salt = salt;
    if(salt == NULL) {
        memset(default_salt, 0, SHA256_HASH_SIZE);
        actual_salt = default_salt;
        salt_size = SHA256_HASH_SIZE;
    }

    return hkdf_HMAC(actual_salt, salt_size, ikm, ikm_size, prk);
}

web_status_t hkdf_Expand(uint8_t prk[SHA256_HASH_SIZE], const void *info, size_t info_size, void *output, size_t output_size) {
    web_status_t ret_val = WEB_NO_DATA;
    const unsigned int nb_iterations = (output_size + SHA256_HASH_SIZE - 1) / SHA256_HASH_SIZE;
    const size_t max_context_size = SHA256_HASH_SIZE + info_size + 1;
    uint8_t previous_hash[SHA256_HASH_SIZE];
    uint8_t context_buffer[max_context_size];
    size_t context_buffer_size;
    size_t size_left = output_size;
    for(unsigned int i=1; i<=nb_iterations; i++) {
        if(i != 1) {
            context_buffer_size = SHA256_HASH_SIZE + info_size + 1;
            memcpy(context_buffer, previous_hash, SHA256_HASH_SIZE);
            memcpy(context_buffer + SHA256_HASH_SIZE, info, info_size);
        } else {
            context_buffer_size = info_size + 1;
            memcpy(context_buffer, info, info_size);
        }
        context_buffer[context_buffer_size - 1] = i;

        ret_val = hkdf_HMAC(prk, SHA256_HASH_SIZE, context_buffer, context_buffer_size, previous_hash);
        if(ret_val != WEB_SUCCESS) {
            memset(output, 0, i * SHA256_HASH_SIZE);
            break;
        }
        memcpy(output + (i - 1) * SHA256_HASH_SIZE, previous_hash, min(size_left, SHA256_HASH_SIZE));
        size_left -= SHA256_HASH_SIZE;
    }

    // Clearing any contextual info on the stack for security purposes
    memset(previous_hash, 0, SHA256_HASH_SIZE);
    memset(context_buffer, 0, max_context_size);

    return ret_val;
}

web_status_t hkdf_HMAC(const void *key, size_t key_size, const void *msg, size_t size, uint8_t dst[SHA256_HASH_SIZE]) {
    const void *actual_key = key;
    uint8_t modified_key[SHA256_HASH_SIZE];  // Only used if `key_size > SHA256_HASH_SIZE`

    if(key_size > SHA256_HASH_SIZE) {
        dbg_info("Key too long, hashing");
        sha256_Init();
        sha256_Part(key, key_size);
        sha256_Hash(modified_key);
        key_size = SHA256_HASH_SIZE;
        actual_key = modified_key;
    }

    const size_t block_size = SHA256_HASH_SIZE + key_size;
    uint8_t padded_key[block_size];
    memcpy(padded_key, actual_key, key_size);
    memset(padded_key + SHA256_HASH_SIZE, 0, SHA256_HASH_SIZE);
    uint8_t o_key_pad[block_size];
    uint8_t i_key_pad[block_size];

    for(size_t i=0; i<block_size; i++) {
        o_key_pad[i] = padded_key[i] ^ 0x5c;
        i_key_pad[i] = padded_key[i] ^ 0x36;
    }

    if(sha256_IsEnabled()) {
        dbg_err("SHA256 chip already in use");
        return WEB_SHA256_IN_USE;
    }

    sha256_Init();
    sha256_Part(i_key_pad, block_size);
    sha256_Part(msg, size);
    sha256_Hash(dst);  // temp buffer for inner hash

    sha256_Init();
    sha256_Part(o_key_pad, block_size);
    sha256_Part(dst, SHA256_HASH_SIZE);
    sha256_Hash(dst);

    // Clearing any contextual info on the stack for security purposes
    memset(o_key_pad, 0, block_size);
    memset(i_key_pad, 0, block_size);
    memset(padded_key, 0, block_size);
    if(actual_key != key) {
        memset(modified_key, 0, SHA256_HASH_SIZE);
    }

    return WEB_SUCCESS;
}
