#include <internet.h>
#include <string.h>

#include "../include/crypto.h"
#include "../include/tls.h"
#include "../include/debug.h"


web_status_t add_transcript_message(linked_transcript_msg_t **transcript, tls_record_t *record) {
    /* Note: Messages are already in the correct order (ordering is expected by the TLS client FSM) */
    void *data = _malloc(ntohs(record->length));
    if(data == NULL) {
        return WEB_NOT_ENOUGH_MEM;
    }
    memcpy(data, record->data, ntohs(record->length));
    linked_transcript_msg_t *adding = _malloc(sizeof(linked_transcript_msg_t));
    if(adding == NULL) {
        _free(data);
        return WEB_NOT_ENOUGH_MEM;
    }
    adding->length = ntohs(record->length);
    adding->data = data;
    adding->next = NULL;  /* Adding the element at the end of the linked list */

    linked_transcript_msg_t *current = *transcript;
    linked_transcript_msg_t *prev = NULL;
    while(current != NULL) {
        prev = current;
        current = current->next;
    }
    if(prev != NULL) {
        prev->next = adding;
    } else {
        *transcript = adding;
    }

    // TODO if HelloRetryRequest (see session ID)...

    return WEB_SUCCESS;
}

web_status_t compute_transcript_hash(const linked_transcript_msg_t *transcript, tls_hs_msg_type_t until, uint8_t hash[]) {
    const web_status_t status = sha256_Init();
    if(status != WEB_SUCCESS) {
        return status;
    }
    
    const linked_transcript_msg_t *message = transcript;
    while(message != NULL && ((tls_handshake_t *)message->data)->hs_type <= until) {
        sha256_Part(message->data, message->length);
        message = message->next;
    }

    return sha256_Hash(hash);
}

web_status_t compute_early_secret(const linked_transcript_msg_t *transcript, uint8_t current_secret[], const uint8_t psk[],
                                  size_t psk_length, uint8_t binder_key[], uint8_t client_early_traffic_secret[],
                                  uint8_t early_exporter_master_secret[]) {
    (void)transcript;  /* might be useful later */
    web_status_t status;
    uint8_t secret[CIPHER_SUITE_HASH_SIZE];
    if(psk_length == 0 || psk == NULL) {
        uint8_t zero_psk[CIPHER_SUITE_HASH_SIZE] = {0};
        status = hkdf_Extract(NULL, 0, zero_psk, CIPHER_SUITE_HASH_SIZE, secret);
    } else {
        status = hkdf_Extract(NULL, 0, psk, psk_length, secret);
    }
    if(status != WEB_SUCCESS) {
        return status;
    }

    if(binder_key != NULL) {
        /* No PSK support, so don't care */
    }
    if(client_early_traffic_secret != NULL) {
        /* No PSK support, so don't care */
    }
    if(early_exporter_master_secret != NULL) {
        /* No PSK support, so don't care */
    }

    uint8_t hash_empty_str[CIPHER_SUITE_HASH_SIZE];
    status = compute_transcript_hash(NULL, 0, hash_empty_str);
    if(status == WEB_SUCCESS) {
        status = hkdf_ExpandLabel(secret, "derived", hash_empty_str, CIPHER_SUITE_HASH_SIZE, current_secret, CIPHER_SUITE_HASH_SIZE);
    }
    memset(secret, 0, CIPHER_SUITE_HASH_SIZE);
    return status;
}

web_status_t compute_handshake_secret(const linked_transcript_msg_t *transcript, uint8_t current_secret[], const uint8_t dhe_ss[],
                                      size_t dhe_ss_size, uint8_t client_hs_traffic_secret[], uint8_t server_hs_traffic_secret[]) {
    web_status_t status;
    uint8_t hash[CIPHER_SUITE_HASH_SIZE];
    uint8_t secret[CIPHER_SUITE_HASH_SIZE];
    status = hkdf_Extract(current_secret, CIPHER_SUITE_HASH_SIZE, dhe_ss, dhe_ss_size, secret);
    if(status != WEB_SUCCESS) {
        return status;
    }
    
    status = compute_transcript_hash(transcript, TLS_HS_TYPE_SERVER_HELLO, hash);
    if(client_hs_traffic_secret != NULL && status == WEB_SUCCESS) {
        status = hkdf_ExpandLabel(secret, "c hs traffic", hash, CIPHER_SUITE_HASH_SIZE, client_hs_traffic_secret, CIPHER_SUITE_HASH_SIZE);
    }
    if(server_hs_traffic_secret != NULL && status == WEB_SUCCESS) {
        status = hkdf_ExpandLabel(secret, "s hs traffic", hash, CIPHER_SUITE_HASH_SIZE, server_hs_traffic_secret, CIPHER_SUITE_HASH_SIZE);
    }

    if(status == WEB_SUCCESS) {
        status = compute_transcript_hash(NULL, 0, hash);
        if(status == WEB_SUCCESS) {
            status = hkdf_ExpandLabel(secret, "derived", hash, CIPHER_SUITE_HASH_SIZE, current_secret, CIPHER_SUITE_HASH_SIZE);
        }
    }

    memset(secret, 0, CIPHER_SUITE_HASH_SIZE);
    memset(hash, 0, CIPHER_SUITE_HASH_SIZE);
    return status;
}

web_status_t compute_master_secret(const linked_transcript_msg_t *transcript, uint8_t current_secret[],
                                   uint8_t client_ap_traffic_secret[], uint8_t server_ap_traffic_secret[],
                                   uint8_t exporter_master_secret[], uint8_t resumption_master_secret[]) {
    web_status_t status;
    uint8_t hash[CIPHER_SUITE_HASH_SIZE];
    uint8_t secret[CIPHER_SUITE_HASH_SIZE];
    uint8_t zero_psk[CIPHER_SUITE_HASH_SIZE] = {0};
    status = hkdf_Extract(current_secret, CIPHER_SUITE_HASH_SIZE, zero_psk, CIPHER_SUITE_HASH_SIZE, secret);
    if(status != WEB_SUCCESS) {
        return status;
    }

    if(client_ap_traffic_secret != NULL) {
        status = compute_transcript_hash(transcript, TLS_HS_TYPE_FINISHED, hash);
        if(status == WEB_SUCCESS) {
            status = hkdf_ExpandLabel(secret, "c ap traffic", hash, CIPHER_SUITE_HASH_SIZE, client_ap_traffic_secret, CIPHER_SUITE_HASH_SIZE);
        }
        if(status != WEB_SUCCESS) {
            goto end;
        }
    }
    if(server_ap_traffic_secret != NULL) {
        status = compute_transcript_hash(transcript, TLS_HS_TYPE_FINISHED, hash);
        if(status == WEB_SUCCESS) {
            status = hkdf_ExpandLabel(secret, "s ap traffic", hash, CIPHER_SUITE_HASH_SIZE, server_ap_traffic_secret, CIPHER_SUITE_HASH_SIZE);
        }
        if(status != WEB_SUCCESS) {
            goto end;
        }
    }
    if(exporter_master_secret != NULL) {
        /* Don't care for now */
    }
    if(resumption_master_secret != NULL) {
        /* Don't care for now */
    }

end:
    memset(secret, 0, CIPHER_SUITE_HASH_SIZE);
    memset(hash, 0, CIPHER_SUITE_HASH_SIZE);
    return status;
}

web_status_t update_traffic_secret(const uint8_t current_traffic_secret[], uint8_t new_traffic_secret[]) {
    web_status_t status;
    uint8_t hash[CIPHER_SUITE_HASH_SIZE];
    status = compute_transcript_hash(NULL, 0, hash);
    if(status == WEB_SUCCESS) {
        status = hkdf_ExpandLabel(current_traffic_secret, "traffic upd", hash, CIPHER_SUITE_HASH_SIZE, new_traffic_secret, CIPHER_SUITE_HASH_SIZE);
        memset(hash, 0, CIPHER_SUITE_HASH_SIZE);
    }
    return status;
}

web_status_t compute_key_iv_pair(const uint8_t secret[], uint8_t key[], size_t key_size, uint8_t iv[], size_t iv_size) {
    web_status_t status;
    status = hkdf_ExpandLabel(secret, "key", NULL, 0, key, key_size);
    if(status == WEB_SUCCESS) {
        status = hkdf_ExpandLabel(secret, "iv", NULL, 0, iv, iv_size);
    }
    return status;
}

void _free_transcript(linked_transcript_msg_t **transcript) {
    linked_transcript_msg_t *message = *transcript;
    linked_transcript_msg_t *next;
    while(message != NULL) {
        next = message->next;
        _free(message->data);
        _free(message);
        message = next;
    }
    *transcript = NULL;
}
