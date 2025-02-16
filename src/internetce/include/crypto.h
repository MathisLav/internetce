/**
 * Cryptography functions
 */

#ifndef INTERNET_CRYPTO
#define INTERNET_CRYPTO

#include <stdint.h>
#include <stdbool.h>
#include <internet.h>

#include "tls.h"


/**
 * Constants
 */

/* Sent during client hello so the server does not send a too large TLS ciphered payload.
 * 2^13-1 = 2^16 / 8 - 1 = limitation in aes128gcm where the number of bits must not be greater than 2**16-1
 * Taking 2^12 to be safe
 */
#define AES_MAX_BLOCK_SIZE  (2^12)
#define AES_128_TAG_SIZE    16
#define AES_128_KEY_SIZE    16
#define AES_128_IV_SIZE     12

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
#define SHA256_BLOCK_SIZE   64

/* X25519 */
#define X25519_SECRET_SIZE  32

/* In case I choose to add other hash functions */
#define CIPHER_SUITE_HASH_SIZE   SHA256_HASH_SIZE
#define CIPHER_SUITE_BLOCK_SIZE  SHA256_BLOCK_SIZE


/**
 * Types
 */

typedef struct aes128gcm_endpoint_data {
    uint8_t round_keys[176];
    uint8_t static_iv[12];
    size_t sequence_number;             /**< In theory the seq_num is 64-bit wide, in practice, 24 bits is enough   */
} aes128gcm_endpoint_data_t;

typedef struct aes128gcm_data {
    aes128gcm_endpoint_data_t cipher_data;
    aes128gcm_endpoint_data_t decipher_data;
} aes128gcm_data_t;


/**
 * Cryptography functions
 */

/* AES-128 GCM */

web_callback_data_t *aes128gcm_init_callback(uint8_t cipher_key[AES_128_KEY_SIZE], uint8_t cipher_iv[AES_128_IV_SIZE],
                                             uint8_t decipher_key[AES_128_KEY_SIZE], uint8_t decipher_iv[AES_128_IV_SIZE]);

void aes128gcm_free_callback(web_callback_data_t *cipher_data);

web_status_t aes128gcm_cipher_callback(void *dest, void *source, size_t length, void *aad, size_t aad_length,
                                       web_callback_data_t *user_data);

web_status_t aes128gcm_decipher_callback(void *dest, void *source, size_t length, void *aad, size_t aad_length,
                                         web_callback_data_t *user_data);

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

web_status_t rng_Random256b(uint8_t dst[32]);

web_status_t rng_Random32b(uint32_t *var);

/* HKDF - HMAC Key Derivation Function */

web_status_t hkdf_Extract(const uint8_t salt[], size_t salt_size, const uint8_t ikm[], size_t ikm_size, uint8_t prk[]);

web_status_t hkdf_Expand(const uint8_t prk[], const uint8_t info[], size_t info_size, uint8_t dst[], size_t dst_size);

web_status_t hkdf_ExpandLabel(const uint8_t secret[], const char *label, const uint8_t hash[], size_t hash_size,
                              uint8_t dst[], size_t dst_size);

web_status_t hkdf_HMAC(const uint8_t key[], size_t key_size, const uint8_t msg[], size_t size, uint8_t dst[]);

/* Key Schedule */

web_status_t add_transcript_message(linked_transcript_msg_t **transcript, const void *data, size_t size, tls_sender_t sender);

web_status_t compute_transcript_hash(const linked_transcript_msg_t *transcript, tls_hs_sender_msg_type_t until, uint8_t hash[]);

web_status_t compute_early_secret(const linked_transcript_msg_t *transcript, uint8_t current_secret[], const uint8_t psk[],
                                  size_t psk_length, uint8_t binder_key[], uint8_t client_early_traffic_secret[],
                                  uint8_t early_exporter_master_secret[]);

web_status_t compute_handshake_secret(const linked_transcript_msg_t *transcript, uint8_t current_secret[], const uint8_t dhe_ss[],
                                      size_t dhe_ss_size, uint8_t client_hs_traffic_secret[], uint8_t server_hs_traffic_secret[]);

web_status_t compute_master_secret(const linked_transcript_msg_t *transcript, uint8_t current_secret[],
                                   uint8_t client_ap_traffic_secret[], uint8_t server_ap_traffic_secret[],
                                   uint8_t exporter_master_secret[], uint8_t resumption_master_secret[]);

web_status_t update_traffic_secret(const uint8_t current_traffic_secret[], uint8_t new_traffic_secret[]);

web_status_t compute_key_iv_pair(const uint8_t secret[], uint8_t key[], size_t key_size, uint8_t iv[], size_t iv_size);

void _free_transcript(linked_transcript_msg_t **transcript);

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

void x25519_scalarmult(uint8_t out[32], const uint8_t base_point[32], uint8_t scalar[32]);


#endif // INTERNET_CRYPTO
