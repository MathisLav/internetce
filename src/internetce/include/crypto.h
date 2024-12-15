/**
 * Cryptography functions
 */

#ifndef INTERNET_CRYPTO
#define INTERNET_CRYPTO

#include <stdint.h>
#include <stdbool.h>
#include <internet.h>


/**
 * Constants
 */

/* Sent during client hello so the server does not send a too large TLS ciphered payload.
 * 2^13-1 = 2^16 / 8 - 1 = limitation in aes128gcm where the number of bits must not be greater than 2**16-1
 * Taking 2^12 to be safe
 */
#define AES_MAX_BLOCK_SIZE  (2^12)

/* Port layout for SHA256 memory mapped port */
#define SHA256_CTRL         ((volatile uint8_t *)0xe10000)
#define SHA256_STATUS       ((volatile uint8_t *)0xe10001)
#define SHA256_ENABLE       ((volatile uint8_t *)0xe10009)
#define SHA256_BLOCK        ((volatile uint32_t *)0xe10010)
#define SHA256_HASH_DATA    ((volatile uint32_t *)0xe10060)

/* SHA256_CTRL commands */
#define SHA256_BEGIN_HASH   0x0A
#define SHA256_CONTINUE_HASH 0x0E

#define SHA256_HASH_SIZE    32


/**
 * Cryptography functions
 */

/* AES-128 GCM */

void compute_round_keys(uint8_t key_space[176]);

void cipher_aes128gcm(/* IN */  const uint8_t round_keys[176],
                      /* IN */  const void *plaintext,
                      /* IN */  size_t length_plaintext,
                      /* IN */  const uint8_t IV[12],
                      /* IN */  const void *AAD,
                      /* IN */  size_t length_aad,
                      /* OUT */ uint8_t tag[16],
                      /* OUT */ void *ciphertext);

int decipher_aes128gcm(/* IN */  const uint8_t round_keys[176],
                       /* IN */  const void *ciphertext,
                       /* IN */  size_t length_ciphertext,
                       /* IN */  const uint8_t IV[12],
                       /* IN */  const void *AAD,
                       /* IN */  size_t length_aad,
                       /* IN */  const uint8_t tag[16],
                       /* OUT */ void *plaintext);

/* Random */

void rng_Init();

bool rng_IsAvailable();

web_status_t rng_Update();

void rng_Feed(const uint8_t seed[], size_t seed_size);

void rng_FeedBit(uint8_t bit);

void rng_FeedFromEvent();

web_status_t rng_Random256b(uint8_t dst[SHA256_HASH_SIZE]);

web_status_t rng_Random32b(uint32_t *var);

/* HKDF - HMAC Key Derivation Function */

web_status_t hkdf_HMAC(const void *key, size_t key_size, const void *msg, size_t size, uint8_t dst[SHA256_HASH_SIZE]);

web_status_t hkdf_Extract(const void *salt, size_t salt_size, const void *ikm, size_t ikm_size, uint8_t prk[SHA256_HASH_SIZE]);

web_status_t hkdf_Expand(uint8_t prk[SHA256_HASH_SIZE], const void *info, size_t info_size, void *output, size_t output_size);

/* Ports */

void flash_setup();

void flash_unlock();

void flash_lock();

/* SHA256 */

bool sha256_IsEnabled();

web_status_t sha256_Init();

web_status_t sha256_Part(const void *src, size_t size);

web_status_t sha256_Hash(void *dst);

/* X25519 */

void x25519_clampscalar(uint8_t scalar[32]);

void x25519_scalarmult(uint8_t out[32], uint8_t base_point[32], uint8_t scalar[32]);


#endif // INTERNET_CRYPTO
