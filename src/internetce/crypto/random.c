/**
 * Random module
 * Seek for entropy from various sources, in particular from the USB bus activity
 * Unfortunately not as secured as it could be, since making a good True RNG would require more and better entropy sources.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../include/crypto.h"
#include "../include/debug.h"

#define MINIMUM_ENTROPY     16
#define ENTROPY_BUFFER_SIZE (MINIMUM_ENTROPY * 2)


/* Internal state variables */
static size_t entropy = 0;  /* This is actually not entropy but the number of random bytes gathered until now */
static uint8_t entropy_bits;  /* Temporary buffer that stores the entropy bits until there are 8 of them */
static uint8_t nb_entropy_bits;  /* Number of entropy bits (8 bits => store the byte into entropy_buffer) */
static uint8_t entropy_buffer[ENTROPY_BUFFER_SIZE];  /* Buffer that gathers entropy waiting to be fed  */
static uint8_t current_buffer_index;  /* Current index in entropy_buffer */
static uint8_t K[CIPHER_SUITE_HASH_SIZE];  /* Key used with HMAC */
static uint8_t V[CIPHER_SUITE_HASH_SIZE];  /* Current state */

void rng_Init() {
    memset(K, 0, CIPHER_SUITE_HASH_SIZE);
    memset(V, 1, CIPHER_SUITE_HASH_SIZE);
    entropy = 0;
    current_buffer_index = 0;
    entropy_bits = 0;
    nb_entropy_bits = 0;
}

bool rng_IsAvailable() {
    return entropy >= MINIMUM_ENTROPY;
}

web_status_t rng_Update() {
    if(current_buffer_index == 0) {
        dbg_verb("No available entropy");
        return 0;
    }
    if(sha256_IsEnabled()) {
        return WEB_SHA256_IN_USE;
    }

    const size_t buffer_size = CIPHER_SUITE_HASH_SIZE + 1 + current_buffer_index;
    uint8_t buffer[buffer_size];

    memcpy(buffer, V, CIPHER_SUITE_HASH_SIZE);
    buffer[CIPHER_SUITE_HASH_SIZE] = 0;
    memcpy(buffer + CIPHER_SUITE_HASH_SIZE, entropy_buffer, current_buffer_index);
    hkdf_HMAC(K, CIPHER_SUITE_HASH_SIZE, buffer, buffer_size, K);
    hkdf_HMAC(K, CIPHER_SUITE_HASH_SIZE, V, CIPHER_SUITE_HASH_SIZE, V);

    memcpy(buffer, V, CIPHER_SUITE_HASH_SIZE);
    buffer[CIPHER_SUITE_HASH_SIZE] = 1;
    hkdf_HMAC(K, CIPHER_SUITE_HASH_SIZE, buffer, buffer_size, K);
    hkdf_HMAC(K, CIPHER_SUITE_HASH_SIZE, V, CIPHER_SUITE_HASH_SIZE, V);

    /* Clearing buffer for security purposes */
    memset(buffer, 0, buffer_size);

    entropy += current_buffer_index;
    current_buffer_index = 0;
    dbg_verb("Random module seeded");

    return 0;
}

void rng_Feed(const uint8_t seed[], size_t seed_size) {
    const size_t to_be_fed = min(seed_size, ENTROPY_BUFFER_SIZE - current_buffer_index);
    for(size_t i=0; i<to_be_fed; i++) {
        entropy_buffer[current_buffer_index + i] = seed[i];
    }

    current_buffer_index += to_be_fed;

    /* Only feeding when sufficent amount of entropy is available (for performance) */
    if(current_buffer_index >= MINIMUM_ENTROPY) {
        rng_Update();  /* Only done if the SHA256 chip is available */
    }
}

void rng_FeedBit(uint8_t bit) {
    bit = bit == 0 ? 0 : 1; 
    entropy_bits = (entropy_bits << 1) + bit;
    nb_entropy_bits++;
    
    if(nb_entropy_bits == 8) {
        rng_Feed(&entropy_bits, 1);
        nb_entropy_bits = 0;
    }
}

void rng_FeedFromEvent() {
    /**
     * Usualy called when an USB event occurs.
     * As this is not a perfect entropy source, it only takes the 4 most significant bits of the LSB of the current timer value
     */
    uint8_t seed = (uint8_t)((usb_GetCycleCounter() >> 4) & 0b1111);
    for(uint8_t i=0; i<4; i++) {
        rng_FeedBit((seed >> i) & 0b1);
    }
}

web_status_t rng_Random256b(uint8_t dst[32]) {
    if(!rng_IsAvailable()) {
        dbg_err("Not enough entropy");
        return WEB_NOT_ENOUGH_ENTROPY;
    }

    const int ret_val = hkdf_HMAC(K, 32, V, 32, V);
    if(ret_val == 0) {
        memcpy(dst, V, 32);
    }

    return ret_val;
}

web_status_t rng_Random32b(uint32_t *var) {
    if(!rng_IsAvailable()) {
        dbg_warn("Not enough entropy");
        return WEB_NOT_ENOUGH_ENTROPY;
    }

    uint8_t buffer[32];
    int ret_val = rng_Random256b(buffer);
    if(ret_val == 0) {
        *var = ((uint32_t *)buffer)[0];
    }
    memset(buffer, 0, 32);  /* Clearing buffer for security purposes */
    return ret_val;
}
