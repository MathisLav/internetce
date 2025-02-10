#include <internet.h>
#include <string.h>

#include "../include/crypto.h"
#include "../include/debug.h"

cipher_callbacks_t aes128gcm_callbacks = {
    .init = aes128gcm_init_callback,
    .free = aes128gcm_free_callback,
    .cipher = aes128gcm_cipher_callback,
    .decipher = aes128gcm_decipher_callback,
    .extra_size = AES_128_TAG_SIZE,
    .key_size = AES_128_KEY_SIZE,
    .iv_size = AES_128_IV_SIZE
};


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_callback_data_t *aes128gcm_init_callback(uint8_t cipher_key[AES_128_KEY_SIZE], uint8_t cipher_iv[AES_128_IV_SIZE],
                                             uint8_t decipher_key[AES_128_KEY_SIZE], uint8_t decipher_iv[AES_128_IV_SIZE]) {
    aes128gcm_data_t *cipher_struct = _malloc(sizeof(aes128gcm_data_t));
    if(cipher_struct == NULL) {
        dbg_err("No memory");
        return NULL;
    }

    /* Local cipher data */
    memcpy(cipher_struct->cipher_data.static_iv, cipher_iv, AES_128_IV_SIZE);
    memcpy(cipher_struct->cipher_data.round_keys, cipher_key, AES_128_KEY_SIZE);
    compute_round_keys(cipher_struct->cipher_data.round_keys);
    cipher_struct->cipher_data.sequence_number = 0;

    /* Distant cipher data */
    memcpy(cipher_struct->decipher_data.static_iv, decipher_iv, AES_128_IV_SIZE);
    memcpy(cipher_struct->decipher_data.round_keys, decipher_key, AES_128_KEY_SIZE);
    compute_round_keys(cipher_struct->decipher_data.round_keys);
    cipher_struct->decipher_data.sequence_number = 0;

    return cipher_struct;
}

void aes128gcm_free_callback(web_callback_data_t *cipher_data) {
    _free(cipher_data);
}

web_status_t aes128gcm_cipher_callback(void *dest, void *source, size_t length, void *aad, size_t aad_length,
                                       web_callback_data_t *user_data) {
    aes128gcm_endpoint_data_t *cipher_data = &((aes128gcm_data_t *)user_data)->cipher_data;
    uint8_t current_iv[12];
    memcpy(current_iv, cipher_data->static_iv, 12);
    uint8_t *seq_number_bytes = (uint8_t *)&cipher_data->sequence_number;
    current_iv[11] ^= seq_number_bytes[0];  /* little to big endian */
    current_iv[10] ^= seq_number_bytes[1];
    current_iv[9] ^= seq_number_bytes[2];
    cipher_data->sequence_number++;
    cipher_aes128gcm(cipher_data->round_keys, source, length, current_iv, aad, aad_length, dest + length, dest);

    return WEB_SUCCESS;
}

web_status_t aes128gcm_decipher_callback(void *dest, void *source, size_t length, void *aad, size_t aad_length,
                                         web_callback_data_t *user_data) {
    aes128gcm_endpoint_data_t *decipher_data = &((aes128gcm_data_t *)user_data)->decipher_data;
    uint8_t current_iv[12];
    memcpy(current_iv, decipher_data->static_iv, 12);
    uint8_t *seq_number_bytes = (void *)&decipher_data->sequence_number;
    current_iv[11] ^= seq_number_bytes[0];  /* little to big endian */
    current_iv[10] ^= seq_number_bytes[1];
    current_iv[9] ^= seq_number_bytes[2];
    decipher_data->sequence_number++;
    const int ret_val = decipher_aes128gcm(decipher_data->round_keys, source, length - AES_128_TAG_SIZE, current_iv,
                                           aad, aad_length, source + length - AES_128_TAG_SIZE, dest);

    return ret_val == 0 ? WEB_SUCCESS : WEB_ERROR_FAILED;
}
