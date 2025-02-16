#include <internet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "include/tls.h"
#include "include/tcp.h"
#include "include/core.h"
#include "include/debug.h"
#include "include/crypto.h"

#include "include/http.h"  // todo remove


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_status_t web_DeliverTLSData(tls_exchange_t *tls_exch, void *data, size_t length_data) {
	return web_DeliverTLSRecord(tls_exch, data, length_data, TLS_APPLI_DATA_TYPE);
}

web_status_t web_DeliverTLSRecord(tls_exchange_t *tls_exch, void *data, size_t length_data, tls_content_type_t tls_type) {
	/* only allocating for the length + tls header because it will be _reallocated in web_DeliveryTCPSegment */
	size_t total_size = sizeof(tls_record_t) + length_data;
	if(tls_exch->tls_state >= TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS) {  /* If encrypted */
		total_size += tls_exch->cipher_callbacks->extra_size + 1 /* Content Type */ + 0 /* padding */;
	}

	uint8_t *buffer = _malloc(total_size);
	if(buffer == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	memcpy(buffer + sizeof(tls_record_t), data, length_data);

	const web_status_t ret_val = _recursive_DeliverTLSRecord(tls_exch, buffer, buffer + sizeof(tls_record_t), length_data,
															 tls_type);
	_free(buffer);
	return ret_val;
}


tls_exchange_t *web_TLSConnect(uint32_t ip_dst, web_port_t port_dst, const char *server_name, web_appli_callback_t *callback,
							   web_callback_data_t *user_data) {
	size_t server_name_length = strlen(server_name);
	if(server_name_length > TLS_SERVER_NAME_MAX_LENGTH) {
		dbg_err("SNI too long: %d > %d", server_name_length, TLS_SERVER_NAME_MAX_LENGTH);
		return NULL;
	}

	/* Creating the internal TLS structure */
	tls_exchange_t *tls_exch = _malloc(sizeof(tls_exchange_t));
	if(tls_exch == NULL) {
		dbg_err("No memory left");
		return NULL;
	}
	tls_exch->record = _malloc(sizeof(tls_record_t));  /* Allocating the memory for the TLS header until we receive the actual size of the record */
	if(tls_exch->record == NULL) {
		_free(tls_exch);
		dbg_err("No memory left");
		return NULL;
	}
	tls_exch->received_length = 0;
	tls_exch->tls_state = TLS_STATE_WAIT_SERVER_HELLO;
	tls_exch->cipher_callbacks = NULL;
	tls_exch->transcript = NULL;
	tls_exch->appli_callback = callback;
	tls_exch->appli_data = user_data;

	/* Filling the client_hello buffer */
	size_t hs_length = sizeof(tls_handshake_ce_t) + server_name_length;
	const tls_handshake_ce_t client_hello = {
    	.hs_type = TLS_HS_TYPE_CLIENT_HELLO,
		.client_hello_length = htonl24(hs_length - 4),
		.version = TLS_VERSION_1_2,
		.random = {},	// memcpied
		.session_id_length = 32,			        	// Session ID not used in TLS 1.3
		.session_id = {},	// memcpied
		.cipher_suite_length = htons(SIZE_CIPHER_SUITES),
    	.cipher_suites = LIST_SUPPORTED_CIPHER_SUITES,
    	.comp_methods_length = 1,    					// Always 1
    	.null_compression = 0,       					// no compression methods in TLS 1.3
		.extensions_length = htons(TOTAL_EXTENSIONS_SIZE + server_name_length),
    	.sup_versions_ext = (tls_supported_versions_ce_t){
			.extension_id = TLS_SUPPORTED_VERSIONS_EXT_ID,
			.extension_length = htons(3),
			.data_length = 2,
			.version_tls_13 = TLS_VERSION_1_3
		},
    	.ec_point_ext = (tls_ec_point_formats_ce_t){
			.extension_id = TLS_EC_POINT_FORMATS_EXT_ID,
			.extension_length = htons(2),
			.data_length = 1,
			.uncompressed = 0x00
		},
    	.sup_groups_ext = (tls_supported_groups_ce_t){
			.extension_id = TLS_SUPPORTED_GROUPS_EXT_ID,
			.extension_length = htons(2 + SIZE_GROUPS),
			.data_length = htons(SIZE_GROUPS),
			.ec_x25519 = GROUP_EC_X25519
		},
    	.sup_sign_algo_ext = (tls_signature_algo_ce_t){
			.extension_id = TLS_SIGNATURE_ALGO_EXT_ID,
			.extension_length = htons(2 + SIZE_SIGNATURE_ALGO),
			.data_length = htons(SIZE_SIGNATURE_ALGO),
			.algorithms = LIST_SUPPORTED_SIGNATURE_ALGO
		},
    	.key_share_ext = (tls_key_share_ce_t){
			.extension_id = TLS_KEY_SHARE_EXT_ID,
			.extension_length = htons(38),
			.data_length = htons(36),
			.x25519_type = GROUP_EC_X25519,
			.x25519_size = htons(X25519_SECRET_SIZE),
			.x25519_pub_key = {}	// memcpied
		},
		.alpn_ext = (tls_alpn_ce_t){
			.extension_id = TLS_ALPN_EXT_ID,
			.extension_length = htons(11),
			.data_length = htons(9),
			.http_1_1_length = 8,
			.http_1_1_id = "http/1.1"
		},
    	.session_ticket_ext = (tls_session_ticket_ce_t){
			.extension_id = TLS_SESSION_TICKET_EXT_ID,
			.extension_length = 0
		},
    	.ext_msecret_ext = (tls_extended_msecret_ce_t){
			.extension_id = TLS_EXTENDED_MSECRET_EXT_ID,
			.extension_length = 0
		},
		.record_size_limit_ext = (tls_record_size_limit_ce_t){
			.extension_id = TLS_RECORD_SIZE_LIMIT_EXT_ID,
			.extension_length = htons(2),
			.record_size_limit = AES_MAX_BLOCK_SIZE
		},
    	.server_name_ext = (tls_server_name_ce_t){
			.extension_id = TLS_SERVER_NAME_EXT_ID,
			.extension_length = htons(sizeof(tls_server_name_ce_t) + server_name_length - 4),
			.entry_length = htons(sizeof(tls_server_name_ce_t) + server_name_length - 6),
			.dns_type = 0x00,  // DNS hostname
			.hostname_length = htons(server_name_length),
			.hostname = {}  // memcpied
		}
	};

	uint8_t *client_hello_record = _malloc(hs_length + sizeof(tls_record_t));
	if(client_hello_record == NULL) {
		dbg_err("No memory");
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}
	tls_handshake_ce_t *client_hello_ptr = (tls_handshake_ce_t *)(client_hello_record + sizeof(tls_record_t));
	memcpy(client_hello_ptr, &client_hello, sizeof(tls_handshake_ce_t));

	/* Computing public key */
	tls_exch->client_private_key = _malloc(X25519_SECRET_SIZE);
	if(tls_exch->client_private_key == NULL) {
		dbg_err("No memory");
		_free(client_hello_record);
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}
	const uint8_t base_point[X25519_SECRET_SIZE] = {9, 0};  // see x25519 specs
	rng_Random256b(tls_exch->client_private_key);
	x25519_scalarmult(client_hello_ptr->key_share_ext.x25519_pub_key, base_point, tls_exch->client_private_key);

	/* client_random & server_name */
	rng_Random256b(client_hello_ptr->session_id);
	rng_Random256b(client_hello_ptr->random);
	memcpy(client_hello_ptr->server_name_ext.hostname, server_name, server_name_length);

	/* Compute Early Secret */
	tls_exch->current_secret = _malloc(CIPHER_SUITE_HASH_SIZE);
	if(tls_exch->current_secret == NULL) {
		dbg_err("No memory");
		_free(tls_exch->client_private_key);
		_free(client_hello_record);
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}
	web_status_t ret_val = compute_early_secret(tls_exch->transcript, tls_exch->current_secret, NULL, 0, NULL, NULL, NULL);
	if(ret_val != WEB_SUCCESS) {
		_free(tls_exch->client_private_key);
		_free(client_hello_record);
		_free(tls_exch->current_secret);
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}

	tls_exch->tcp_exch = web_TCPConnect(ip_dst, port_dst, fetch_tls_part, tls_exch);
	if(tls_exch->tcp_exch == NULL) {
		_free(tls_exch->client_private_key);
		_free(client_hello_record);
		_free(tls_exch->current_secret);
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}

	ret_val = _recursive_DeliverTLSRecord(tls_exch, client_hello_record, client_hello_ptr, hs_length, TLS_HANDSHAKE_TYPE);
	if(ret_val != WEB_SUCCESS) {
		web_TCPClose(tls_exch->tcp_exch, true);
		_free(tls_exch->client_private_key);
		_free(client_hello_record);
		_free(tls_exch->current_secret);
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}

	return tls_exch;
}


void web_TLSClose(tls_exchange_t *tls_exch, tls_alert_description_t reason) {
	web_SendTLSAlert(tls_exch, reason);

	// TODO free tout maintenant ?
	_free_tls_connection(tls_exch);
}


web_status_t web_SendTLSAlert(tls_exchange_t *tls_exch, tls_alert_description_t alert_desc) {
	tls_alert_record_t buffer;
	if(alert_desc == TLS_ALERT_CLOSE_NOTIFY || alert_desc == TLS_ALERT_USER_CANCELED) {
		buffer.alert_level = TLS_ALERT_LEVEL_WARNING;
	} else {
		buffer.alert_level = TLS_ALERT_LEVEL_FATAL;
	}
	buffer.alert_description = alert_desc;
	return web_DeliverTLSRecord(tls_exch, &buffer, sizeof(tls_alert_record_t), TLS_ALERT_TYPE);
}




web_status_t appli_callback(web_port_t port, link_msg_type_t msg_type, void *msg, size_t length, web_callback_data_t *user_data) {
	(void)port; (void)msg_type; (void)msg; (void)user_data;
	switch(msg_type) {
		case LINK_MSG_TYPE_DATA:
			printf("RCVED: %.*s\n", length, (char *)msg);
			break;
		case LINK_MSG_TYPE_RST:
			printf("DATA RST\n");
			break;
		case LINK_MSG_TYPE_FIN:
			printf("DATA FIN\n");
			break;
		default:
			printf("DATA ???\n");
			break;
	}
	return WEB_SUCCESS;
}

void test_tls() {
	web_TLSConnect(ip_ascii_to_hex("192.168.1.36"), 443, "localhost", appli_callback, NULL);
	while(!os_GetCSC()) {
		web_WaitForEvents();
	}
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

web_status_t _recursive_DeliverTLSRecord(tls_exchange_t *tls_exch, void *buffer, void *data, size_t length_data,
										 uint8_t opaque_type) {
	if(data - sizeof(tls_record_t) < buffer) {
		dbg_err("Can't push TLS record");
		_free(buffer);
		return WEB_NOT_ENOUGH_MEM;
	}

	if(tls_exch->tls_state < TLS_STATE_CONNECTED) {
		add_transcript_message(&tls_exch->transcript, data, length_data, TLS_SENDER_CLIENT);
	}

	/* Filling the TLS record header */
	tls_record_t *tls_record = (tls_record_t *)(data - sizeof(tls_record_t));
	tls_record->legacy_version = TLS_VERSION_1_2;

	if(tls_exch->tls_state >= TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS) {  /* If encrypted */
		const size_t ciphered_length = length_data + 1 /* Content type */ + tls_exch->cipher_callbacks->extra_size;
		((uint8_t *)data)[length_data] = opaque_type;
		tls_record->opaque_type = TLS_APPLI_DATA_TYPE;
		tls_record->length = htons(ciphered_length);
		tls_exch->cipher_callbacks->cipher(data, data, length_data + 1 /* Content type */, tls_record,
										   sizeof(tls_record_t), tls_exch->cipher_data);
		length_data = ciphered_length;
	} else {
		tls_record->opaque_type = opaque_type;
		tls_record->length = htons(length_data);
	}

	return web_DeliverTCPSegment(tls_exch->tcp_exch, tls_record, length_data + sizeof(tls_record_t), FLAG_TCP_PSH | FLAG_TCP_ACK);
}

web_status_t fetch_handshake_extensions(const uint8_t *extensions, size_t length, const uint8_t **server_public_key) {
	const uint8_t *ptr = extensions;
	while(ptr < extensions + length) {
		/* C won't allow me to use switch case when using htons... */
		const size_t ext_type = *(uint16_t *)ptr;
		const size_t ext_size = ntohs(*(uint16_t *)(ptr + 2));
		if(ext_type == TLS_SUPPORTED_VERSIONS_EXT_ID) {
			/* Searching TLS Version 1.3 */
			const uint16_t *ptr_16b = (uint16_t *)(ptr + 4);
			if(ptr[3] != 2 || *ptr_16b != TLS_VERSION_1_3) {
				dbg_err("Unsupported TLS version");
				return WEB_ERROR_FAILED;
			}
		} else if(ext_type == TLS_KEY_SHARE_EXT_ID) {
			const uint16_t *ptr_16b = (uint16_t *)ptr;
			if(ext_size == X25519_SECRET_SIZE + 4 && ptr_16b[2] == GROUP_EC_X25519) {
				*server_public_key = ptr + 8;
			} else {
				return WEB_ERROR_FAILED;
			}
		} else if(ext_type == TLS_ALPN_EXT_ID) {
			dbg_info("ALPN");
		} else {
			dbg_info("Unknown TLS ext: %x", ext_type);
		}
		ptr += ext_size + 4;
	}

	return WEB_SUCCESS;
}

web_status_t compute_cipher_data(tls_exchange_t *tls_exch) {
	web_status_t status;
	uint8_t cipher_key[tls_exch->cipher_callbacks->key_size];
	uint8_t cipher_iv[tls_exch->cipher_callbacks->iv_size];
	uint8_t decipher_key[tls_exch->cipher_callbacks->key_size];
	uint8_t decipher_iv[tls_exch->cipher_callbacks->iv_size];

	status = compute_key_iv_pair(tls_exch->current_client_traffic_secret, cipher_key, tls_exch->cipher_callbacks->key_size,
								 cipher_iv, tls_exch->cipher_callbacks->iv_size);
	if(status != WEB_SUCCESS) {
		dbg_err("Unable to compute client key/iv pair");
		return status;
	}

	status = compute_key_iv_pair(tls_exch->current_server_traffic_secret, decipher_key, tls_exch->cipher_callbacks->key_size,
								 decipher_iv, tls_exch->cipher_callbacks->iv_size);
	if(status != WEB_SUCCESS) {
		dbg_err("Unable to compute server key/iv pair");
		return status;
	}

	tls_exch->cipher_data = tls_exch->cipher_callbacks->init(cipher_key, cipher_iv, decipher_key, decipher_iv);
	return tls_exch->cipher_data == NULL ? WEB_ERROR_FAILED : WEB_SUCCESS;
}

web_status_t fetch_server_hello(tls_exchange_t *tls_exch, tls_handshake_t *server_hello, size_t length) {
	(void)length;
	web_status_t status;
	const size_t sh_length = server_hello->length;
	if(server_hello->version != TLS_VERSION_1_2 || sh_length < sizeof(tls_handshake_t) + 2 + 1 + 2) {  // cipher_suite + comp_meth + ext_size
		return WEB_ERROR_FAILED;
	}
	const uint8_t *pointer_sh = (uint8_t *)server_hello + sizeof(tls_handshake_t) - 1;
	pointer_sh += *pointer_sh + 1;  // Skipping session ID

	/* Selected cipher suite */
	if(*(uint16_t *)pointer_sh != TLS_AES_128_GCM_SHA256) {
		dbg_err("Unsupported cipher suite");
		return WEB_ERROR_FAILED;
	}
	pointer_sh += 2;

	/* Compression method must be 0 */
	if(*pointer_sh != 0x00) {
		dbg_err("Unsupported compression method");
		return WEB_ERROR_FAILED;
	}
	pointer_sh++;

	/* Parse extensions */
	const size_t ext_size = ntohs(*(uint16_t *)pointer_sh);
	const uint8_t *extensions = pointer_sh + 2;
	const uint8_t *server_public_key = NULL;
	status = fetch_handshake_extensions(extensions, ext_size, &server_public_key);
	if(status != WEB_SUCCESS || server_public_key == NULL) {
		dbg_err("Unable to fetch extensions");
		return status;
	}
	tls_exch->cipher_callbacks = &aes128gcm_callbacks;  // Should be retrieved from the server hello if several cipher suites were supported

	// TODO If HelloRetryRequest...

	/* All necessary memory data */
	tls_exch->current_server_traffic_secret = _malloc(CIPHER_SUITE_HASH_SIZE);
	if(tls_exch->current_server_traffic_secret == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	tls_exch->current_client_traffic_secret = _malloc(CIPHER_SUITE_HASH_SIZE);
	if(tls_exch->current_client_traffic_secret == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	uint8_t shared_secret[X25519_SECRET_SIZE];
	x25519_scalarmult(shared_secret, server_public_key, tls_exch->client_private_key);
	memset(tls_exch->client_private_key, 0, X25519_SECRET_SIZE);
	_free(tls_exch->client_private_key);
	tls_exch->client_private_key = NULL;

	/* (De)cipher algo. initialization */
	status = compute_handshake_secret(tls_exch->transcript, tls_exch->current_secret, shared_secret, X25519_SECRET_SIZE,
									  tls_exch->current_client_traffic_secret, tls_exch->current_server_traffic_secret);
	if(status == WEB_SUCCESS) {
		/* Computing handshake-specific secrets */
		status = compute_cipher_data(tls_exch);
	}

	/* Freeing critical data */
	memset(shared_secret, 0, X25519_SECRET_SIZE);
	return status;
}

web_status_t fetch_server_finished(tls_exchange_t *tls_exch, tls_finished_t *server_finished, size_t length) {
	uint8_t hash[CIPHER_SUITE_HASH_SIZE];
	uint8_t finished_key[CIPHER_SUITE_HASH_SIZE];
	uint8_t finished_value[CIPHER_SUITE_HASH_SIZE];

	/* Check server finished */
	hkdf_ExpandLabel(tls_exch->current_server_traffic_secret, "finished", NULL, 0, finished_key, CIPHER_SUITE_HASH_SIZE);
	compute_transcript_hash(tls_exch->transcript, TLS_HS_SERVER_FINISHED - 1, hash);
	hkdf_HMAC(finished_key, CIPHER_SUITE_HASH_SIZE, hash, CIPHER_SUITE_HASH_SIZE, finished_value);
	if(length != CIPHER_SUITE_HASH_SIZE + 4 || memcmp(server_finished->data, finished_value, CIPHER_SUITE_HASH_SIZE) != 0) {
		dbg_err("Incorrect server finished");
		return WEB_ERROR_FAILED;
	}

	/* Send client finished */
	const size_t length_finished_buffer = sizeof(tls_finished_t) + CIPHER_SUITE_HASH_SIZE;
	uint8_t finished_buffer[length_finished_buffer];
	tls_finished_t *client_finished = (tls_finished_t *)finished_buffer;
	client_finished->hs_type = TLS_HS_TYPE_FINISHED;
	client_finished->length = htonl24(CIPHER_SUITE_HASH_SIZE);
	hkdf_ExpandLabel(tls_exch->current_client_traffic_secret, "finished", NULL, 0, finished_key, CIPHER_SUITE_HASH_SIZE);
	compute_transcript_hash(tls_exch->transcript, TLS_HS_SERVER_FINISHED, hash);
	hkdf_HMAC(finished_key, CIPHER_SUITE_HASH_SIZE, hash, CIPHER_SUITE_HASH_SIZE, client_finished->data);
	web_DeliverTLSRecord(tls_exch, finished_buffer, length_finished_buffer, TLS_HANDSHAKE_TYPE);

	/* Compute application traffic secrets */
	tls_exch->cipher_callbacks->free(tls_exch->cipher_data);
	compute_master_secret(tls_exch->transcript, tls_exch->current_secret, tls_exch->current_client_traffic_secret,
						  tls_exch->current_server_traffic_secret, NULL, NULL);
	_free_transcript(&tls_exch->transcript);
	return compute_cipher_data(tls_exch);
}

web_status_t fetch_handshake_message(tls_exchange_t *tls_exch, tls_handshake_t *handshake_msg, size_t length) {
	web_status_t status = WEB_SUCCESS;
	dbg_info("Received hs: %u", handshake_msg->hs_type);

	if(tls_exch->tls_state < TLS_STATE_CONNECTED) {
		add_transcript_message(&tls_exch->transcript, handshake_msg, length, TLS_SENDER_SERVER);
	}

	switch(tls_exch->tls_state) {
		case TLS_STATE_WAIT_SERVER_HELLO:
			if(handshake_msg->hs_type != TLS_HS_TYPE_SERVER_HELLO) {
				status = WEB_ERROR_FAILED;
				break;
			}
			status = fetch_server_hello(tls_exch, handshake_msg, length);
			if(status != WEB_SUCCESS) {
				break;
			}
			tls_exch->tls_state = TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS;
			break;
		case TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS:
			if(handshake_msg->hs_type != TLS_HS_TYPE_ENCRYPTED_EXTENSIONS) {
				status = WEB_ERROR_FAILED;
				break;
			}
			tls_exch->tls_state = TLS_STATE_WAIT_CERT_CR;
			break;
		case TLS_STATE_WAIT_CERT_CR:
			if(handshake_msg->hs_type == TLS_HS_TYPE_CERTIFICATE_REQUEST) {
				tls_exch->tls_state = TLS_STATE_WAIT_CERTIFICATE;
				status = WEB_NOT_SUPPORTED;
				// TODO alert
			} else if(handshake_msg->hs_type == TLS_HS_TYPE_CERTIFICATE) {
				tls_exch->tls_state = TLS_STATE_WAIT_CERTIFICATE_VERIFY;
			} else {
				status = WEB_ERROR_FAILED;
			}
			break;
		case TLS_STATE_WAIT_CERTIFICATE:
			if(handshake_msg->hs_type != TLS_HS_TYPE_CERTIFICATE) {
				status = WEB_ERROR_FAILED;
				break;
			}
			tls_exch->tls_state = TLS_STATE_WAIT_CERTIFICATE_VERIFY;
			break;
		case TLS_STATE_WAIT_CERTIFICATE_VERIFY:
			if(handshake_msg->hs_type != TLS_HS_TYPE_CERTIFICATE_VERIFY) {
				status = WEB_ERROR_FAILED;
				break;
			}
			tls_exch->tls_state = TLS_STATE_WAIT_FINISHED;
			break;
		case TLS_STATE_WAIT_FINISHED:
			if(handshake_msg->hs_type != TLS_HS_TYPE_FINISHED) {
				status = WEB_ERROR_FAILED;
				break;
			}
			status = fetch_server_finished(tls_exch, (tls_finished_t *)handshake_msg, length);
			if(status == WEB_SUCCESS) {
				tls_exch->tls_state = TLS_STATE_CONNECTED;
			}
			break;
		case TLS_STATE_CONNECTED:
			if(handshake_msg->hs_type == TLS_HS_TYPE_NEW_SESSION_TICKET) {
				
			} else if(handshake_msg->hs_type == TLS_HS_TYPE_CERTIFICATE_REQUEST) {
				status = WEB_NOT_SUPPORTED;
			} else if(handshake_msg->hs_type == TLS_HS_TYPE_KEY_UPDATE) {

			} else {
				status = WEB_ERROR_FAILED;
			}
			break;
		case TLS_STATE_CLOSE_NOTIFY_SENT:
		case TLS_STATE_CLOSE_NOTIFY_RECEIVED:
		default:
			status = WEB_ERROR_FAILED;
			break;
	}

	if(status != WEB_SUCCESS) {
		dbg_err("Received an unexpected message %u in state %u", handshake_msg->hs_type, tls_exch->tls_state);
	}

	return status;
}

web_status_t fetch_tls_record(tls_exchange_t *tls_exch, void *payload, size_t length, tls_content_type_t content_type) {
	switch(content_type) {
		case TLS_ALERT_TYPE: {
			tls_alert_record_t *alert_record = (tls_alert_record_t *)payload;
			if(alert_record->alert_level == TLS_ALERT_LEVEL_WARNING) {
				dbg_warn("TLS alert: %u", alert_record->alert_description);
			} else {
				dbg_err("TLS alert: %u", alert_record->alert_description);
				tls_exch->tls_state = TLS_STATE_CLOSED;
				// TODO notifying user + partial close
			}
			break;
		} case TLS_HANDSHAKE_TYPE: {
			web_status_t ret_val = fetch_handshake_message(tls_exch, (tls_handshake_t *)payload, length);
			if(ret_val != WEB_SUCCESS) {
				// TODO alert
			}
			break;
		} case TLS_APPLI_DATA_TYPE:
			tls_exch->appli_callback(tls_exch->tcp_exch->port_src, LINK_MSG_TYPE_DATA, payload, length, tls_exch->appli_data);
			break;
		default:
			dbg_warn("Invalid TLS type: %u", content_type);
			// TODO alert
	}

	return WEB_SUCCESS;
}

web_status_t fetch_tls_encrypted_record(tls_exchange_t *tls_exch, tls_record_t *record, size_t record_length) {
	if(record->opaque_type == TLS_CHANGE_CIPHER_SPEC) {
		if(ntohs(record->length) == 1 && record->data[0] == 0x01) {
			return WEB_SUCCESS;
		} else {
			dbg_err("Invalid Ch_Ci_Sp");
			return WEB_ERROR_FAILED;
		}
	}

	web_status_t status;
	uint8_t *payload = (uint8_t *)record + sizeof(tls_record_t);
	const size_t payload_length = record_length - sizeof(tls_record_t);
	status = tls_exch->cipher_callbacks->decipher(payload, payload, payload_length, record, sizeof(tls_record_t),
												  tls_exch->cipher_data);
	if(status == WEB_SUCCESS) {
		size_t decipher_length = payload_length - tls_exch->cipher_callbacks->extra_size;
		/* Removing padding */
		const uint8_t *padded_payload = payload + decipher_length - 1;
		while(*padded_payload == 0x00) {
			padded_payload--;
			if(padded_payload <= payload) {
				dbg_err("Invalid padding");
				return WEB_ERROR_FAILED;
			}
		}
		decipher_length = padded_payload - payload;
		status = fetch_tls_record(tls_exch, payload, decipher_length, *padded_payload /* Content type */);
	} else {
		dbg_err("Unable to decrypt!");
	}

	return status;
}

web_status_t fetch_tls_part(web_port_t port, link_msg_type_t msg_type, void *data, size_t length,
						    web_callback_data_t *user_data) {
	(void)port; (void)user_data;
	
	tls_exchange_t *tls_exch = (tls_exchange_t *)user_data;
	if(msg_type == LINK_MSG_TYPE_RST) {
		return tls_exch->appli_callback(tls_exch->tcp_exch->port_src, LINK_MSG_TYPE_RST, NULL, 0, tls_exch->appli_data);
	} else if(msg_type == LINK_MSG_TYPE_FIN) {
		return tls_exch->appli_callback(tls_exch->tcp_exch->port_src, LINK_MSG_TYPE_FIN, NULL, 0, tls_exch->appli_data);
	}

	if(tls_exch->received_length < sizeof(tls_record_t)) {
		/* The exchange has just started */
		if(length + tls_exch->received_length >= sizeof(tls_record_t)) {
			/* Must have access to the exact size of the final TLS record */
			memcpy((void *)tls_exch->record + tls_exch->received_length, data, sizeof(tls_record_t) - tls_exch->received_length);
			/* Allocating the needed buffer */
			void *new_buffer = _realloc(tls_exch->record, ntohs(tls_exch->record->length) + sizeof(tls_record_t));
			if(new_buffer == NULL) {
				dbg_err("No memory left");
				web_TLSClose(tls_exch, TLS_ALERT_INTERNAL_ERROR);
				return WEB_NOT_ENOUGH_MEM;
			}
			tls_exch->record = new_buffer;
		}
	}

	size_t to_copy = length; 
	if(length + tls_exch->received_length >= sizeof(tls_record_t)) {
		to_copy = min(length, ntohs(tls_exch->record->length) + sizeof(tls_record_t) - tls_exch->received_length);
	}
	memcpy((void *)tls_exch->record + tls_exch->received_length, data, to_copy);
	tls_exch->received_length += to_copy;

	/* Checking whether the record has yet been fully downloaded or not */
	if(tls_exch->received_length >= sizeof(tls_record_t)) {
		const size_t record_size = ntohs(tls_exch->record->length) + sizeof(tls_record_t);
		if(tls_exch->received_length == record_size) {
			if(tls_exch->tls_state >= TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS) {  /* If encrypted */
				fetch_tls_encrypted_record(tls_exch, tls_exch->record, tls_exch->received_length);
			} else {
				fetch_tls_record(tls_exch, tls_exch->record->data, tls_exch->received_length - sizeof(tls_record_t),
								 tls_exch->record->opaque_type);
			}

			_free(tls_exch->record);
			/* Reset structure for the next TLS record */
			tls_exch->record = _malloc(sizeof(tls_record_t));
			if(tls_exch->record == NULL) {
				dbg_err("No memory left");
				web_TLSClose(tls_exch, TLS_ALERT_INTERNAL_ERROR);
				return WEB_NOT_ENOUGH_MEM;
			}
			tls_exch->received_length = 0;
		}
	}

	web_status_t status = WEB_SUCCESS;
	const size_t remaining_data = length - to_copy;
	if(remaining_data > 0) {
		status = fetch_tls_part(port, msg_type, data + to_copy, remaining_data, user_data);
	}
	
	return status;
}

void _free_tls_connection(tls_exchange_t *tls_exch) {
	if(tls_exch == NULL) {
		dbg_err("Error in _free_tls_connection");
	}
	tls_exch->cipher_callbacks->free(tls_exch->cipher_data);

	_free_transcript(&tls_exch->transcript);

	if(tls_exch->current_secret != NULL) {
		_free(tls_exch->current_secret);
		tls_exch->current_secret = NULL;
	}
	if(tls_exch->client_private_key != NULL) {
		_free(tls_exch->client_private_key);
		tls_exch->client_private_key = NULL;
	}
	if(tls_exch->current_client_traffic_secret != NULL) {
		_free(tls_exch->current_client_traffic_secret);
		tls_exch->current_client_traffic_secret = NULL;
	}
	if(tls_exch->current_server_traffic_secret != NULL) {
		_free(tls_exch->current_server_traffic_secret);
		tls_exch->current_server_traffic_secret = NULL;
	}

	_free(tls_exch->record);
	web_TCPClose(tls_exch->tcp_exch, false);
	_free(tls_exch);
}
