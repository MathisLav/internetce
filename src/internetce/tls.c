#include <internet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "include/tls.h"
#include "include/tcp.h"
#include "include/core.h"
#include "include/debug.h"
#include "include/crypto.h"


tls_ticket_list_t *tls_ticket_list = NULL;


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_status_t web_DeliverTLSData(tls_exchange_t *tls_exch, void *data, size_t length) {
	if(tls_exch->tls_state != TLS_STATE_CONNECTED) {
		dbg_warn("TLS exchange not open");
		return WEB_ERROR_FAILED;
	}
	return deliver_tls_record(tls_exch, data, length, TLS_APPLI_DATA_TYPE);
}

tls_exchange_t *web_TLSConnect(uint32_t ip_dst, web_port_t port_dst, const char *server_name, web_appli_callback_t *callback,
							   web_callback_data_t *user_data) {
	web_status_t ret_val = WEB_SUCCESS;
	size_t server_name_length = strlen(server_name);
	if(server_name_length > TLS_SERVER_NAME_MAX_LENGTH) {
		dbg_err("SNI too long: %d > %d", server_name_length, TLS_SERVER_NAME_MAX_LENGTH);
		return NULL;
	}

	/* Creating the internal TLS structure */
	tls_exchange_t *tls_exch = _malloc(sizeof(tls_exchange_t), "tlsx");
	if(tls_exch == NULL) {
		dbg_err("No memory left");
		return NULL;
	}
	memset(tls_exch, 0, sizeof(tls_exchange_t));  /* for security purposes */
	tls_exch->record = _malloc(sizeof(tls_record_t), "tlsr");  /* Allocating the memory for the TLS header until we receive the actual size of the record */
	if(tls_exch->record == NULL) {
		_free(tls_exch);
		dbg_err("No memory left");
		return NULL;
	}
	tls_exch->tls_state = TLS_STATE_WAIT_SERVER_HELLO;

	/* Compute Early Secret */
	tls_exch->current_secret = _malloc(CIPHER_SUITE_HASH_SIZE, "early");
	if(tls_exch->current_secret == NULL) {
		dbg_err("No memory left");
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}

	tls_exch->tcp_exch = web_TCPConnect(ip_dst, port_dst, fetch_tls_part, tls_exch);
	if(tls_exch->tcp_exch == NULL) {
		_free(tls_exch->current_secret);
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}

	// TODO for now tickets don't work
	//	-> binder is not recognized
	//	-> seems that the TLS_PSK_MODE_KE mode is not supported servers fir security reasons?
	//	   If true, the gain becomes very low
	tls_ticket_list_t *ticket = NULL;  // tls_ticket_list_t *ticket = find_session_ticket(ip_dst);
	
	/* Send client hello */
	if(ticket == NULL) {
		ret_val = send_new_connection(tls_exch, server_name, server_name_length);
	} else {
		ret_val = send_resumption_connection(tls_exch, server_name, server_name_length, ticket);
		_free(ticket->psk);
		_free(ticket);
	}
	if(ret_val != WEB_SUCCESS) {
		dbg_err("TLS HS failed (1)");
		web_TCPClose(tls_exch->tcp_exch, true);
		_free(tls_exch->current_secret);
		_free(tls_exch->record);
		_free(tls_exch);
		return NULL;
	}

	/* Blocking here so the function has the same behavior than web_TCPConnect */
	bool is_timeouted = false;
	delay_event(TIMEOUT_TLS_HANDSHAKE * 1000, boolean_scheduler, boolean_destructor, &is_timeouted);
	while(tls_exch->tls_state != TLS_STATE_CONNECTED) {
		web_WaitForEvents();
		if(is_timeouted) {
			dbg_err("TLS HS timeout");
			tls_close(tls_exch, TLS_ALERT_INTERNAL_ERROR, false);
			return NULL;
		}
		if(tls_exch->tls_state > TLS_STATE_CONNECTED) {
			dbg_err("TLS HS failed (2)");
			remove_event(&is_timeouted);
			/* tls_close should already have been called by the implem */
			return NULL;
		}
	}
	remove_event(&is_timeouted);

	/* Enabling user callbacks */
	tls_exch->appli_callback = callback;
	tls_exch->appli_data = user_data;

	return tls_exch;
}

void web_TLSClose(tls_exchange_t *tls_exch, bool is_abort) {
	/*
	 * Unlike what the RFC recommends, the "Read socket" is also closed in TLSCLOSE.
	 * This is because applications must free the data related to the connection at some time or another.
	 * It would be hard for it to keep track of opened connections if data were freed at an unpredictable time.
	 */
	if(tls_exch->tls_state < TLS_STATE_CONNECTED) {
		send_alert(tls_exch, TLS_ALERT_USER_CANCELED);
	}
	tls_close(tls_exch, is_abort ? TLS_ALERT_INTERNAL_ERROR : TLS_ALERT_CLOSE_NOTIFY, true);
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

web_status_t deliver_tls_record(tls_exchange_t *tls_exch, void *data, size_t length_data, tls_content_type_t tls_type) {
	/* only allocating for the length + tls header because it will be _reallocated in web_DeliveryTCPSegment */
	size_t total_size = sizeof(tls_record_t) + length_data;
	if(tls_exch->tls_state >= TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS && tls_type != TLS_CHANGE_CIPHER_SPEC) {  /* If encrypted */
		total_size += tls_exch->cipher_callbacks->extra_size + 1 /* Content Type */ + 0 /* padding */;
	}

	uint8_t *buffer = _malloc(total_size, "tlsd");
	if(buffer == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	memcpy(buffer + sizeof(tls_record_t), data, length_data);

	const web_status_t ret_val = _recursive_DeliverTLSRecord(tls_exch, buffer, buffer + sizeof(tls_record_t), length_data,
															 tls_type);
	_free(buffer);
	return ret_val;
}

web_status_t _recursive_DeliverTLSRecord(tls_exchange_t *tls_exch, void *buffer, void *data, size_t length_data,
										 uint8_t opaque_type) {
	if(data - sizeof(tls_record_t) < buffer) {
		dbg_err("Can't push TLS record");
		_free(buffer);
		return WEB_NOT_ENOUGH_MEM;
	}

	if(tls_exch->tls_state < TLS_STATE_CONNECTED && opaque_type != TLS_CHANGE_CIPHER_SPEC) {
		add_transcript_message(&tls_exch->transcript, data, length_data, TLS_SENDER_CLIENT);
	}

	/* Filling the TLS record header */
	tls_record_t *tls_record = (tls_record_t *)(data - sizeof(tls_record_t));
	tls_record->legacy_version = TLS_VERSION_1_2;

	if(tls_exch->tls_state >= TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS && opaque_type != TLS_CHANGE_CIPHER_SPEC) {  /* If encrypted */
		const size_t ciphered_length = length_data + 1 /* Content type */ + tls_exch->cipher_callbacks->extra_size;
		((uint8_t *)data)[length_data] = opaque_type;
		tls_record->opaque_type = TLS_APPLI_DATA_TYPE;
		tls_record->length = htons(ciphered_length);
		tls_exch->cipher_callbacks->cipher(data, data, length_data + 1 /* Content type */, tls_record, sizeof(tls_record_t),
										   tls_exch->cipher_data);
		length_data = ciphered_length;
	} else {
		tls_record->opaque_type = opaque_type;
		tls_record->length = htons(length_data);
	}

	return web_DeliverTCPSegment(tls_exch->tcp_exch, tls_record, length_data + sizeof(tls_record_t));
}

web_status_t send_alert(tls_exchange_t *tls_exch, tls_alert_t alert_desc) {
	tls_alert_record_t buffer;
	if(alert_desc == TLS_ALERT_CLOSE_NOTIFY || alert_desc == TLS_ALERT_USER_CANCELED) {
		buffer.alert_level = TLS_ALERT_LEVEL_WARNING;
	} else {
		buffer.alert_level = TLS_ALERT_LEVEL_FATAL;
	}
	buffer.alert_description = alert_desc;
	return deliver_tls_record(tls_exch, &buffer, sizeof(tls_alert_record_t), TLS_ALERT_TYPE);
}

void fill_client_hello_header(void **ptr, size_t client_hello_size) {
	tls_client_hello_header_t *header = *ptr;
	header->hs_type = TLS_HS_TYPE_CLIENT_HELLO;
	header->client_hello_length = htonl24(client_hello_size - 4);
	header->version = TLS_VERSION_1_2;
	rng_Random256b(header->random);
	header->session_id_length = 32;	  	/* Session ID not used in TLS 1.3 */
	rng_Random256b(header->session_id);
	header->cipher_suite_length = htons(SIZE_CIPHER_SUITES);
	header->cipher_suites[0] = (uint16_t[])LIST_SUPPORTED_CIPHER_SUITES[0];
	header->cipher_suites[1] = (uint16_t[])LIST_SUPPORTED_CIPHER_SUITES[1];
	header->comp_methods_length = 1;    	/* Always 1 */
	header->null_compression = 0;       	/* no compression methods in TLS 1.3 */
	header->extensions_length = htons(client_hello_size - sizeof(tls_client_hello_header_t));
	*ptr = header + 1;
}

void fill_supported_versions_ext(void **ptr) {
	tls_supported_versions_ce_t *ext = *ptr;
	ext->extension_id = TLS_SUPPORTED_VERSIONS_EXT_ID;
	ext->extension_length = htons(3);
	ext->data_length = 2;
	ext->version_tls_13 = TLS_VERSION_1_3;
	*ptr = ext + 1;
}

void fill_ec_point_formats_ext(void **ptr) {
	tls_ec_point_formats_ce_t *ext = *ptr;
	ext->extension_id = TLS_EC_POINT_FORMATS_EXT_ID;
	ext->extension_length = htons(2);
	ext->data_length = 1;
	ext->uncompressed = 0x00;
	*ptr = ext + 1;
}

void fill_supported_groups_ext(void **ptr) {
	tls_supported_groups_ce_t *ext = *ptr;
	ext->extension_id = TLS_SUPPORTED_GROUPS_EXT_ID;
	ext->extension_length = htons(2 + SIZE_GROUPS);
	ext->data_length = htons(SIZE_GROUPS);
	ext->ec_x25519 = GROUP_EC_X25519;
	*ptr = ext + 1;
}

void fill_signature_algorithms_ext(void **ptr) {
	tls_signature_algo_ce_t *ext = *ptr;
	ext->extension_id = TLS_SIGNATURE_ALGO_EXT_ID;
	ext->extension_length = htons(2 + SIZE_SIGNATURE_ALGO);
	ext->data_length = htons(SIZE_SIGNATURE_ALGO);
	ext->algorithms[0] = (uint16_t[])LIST_SUPPORTED_SIGNATURE_ALGO[0];
	ext->algorithms[1] = (uint16_t[])LIST_SUPPORTED_SIGNATURE_ALGO[1];
	*ptr = ext + 1;
}

void fill_key_share_ext(void **ptr, uint8_t client_private_key[]) {
	if(client_private_key != NULL) {
		tls_key_share_ce_t *ext = *ptr;
		const uint8_t base_point[X25519_SECRET_SIZE] = {9, 0};  /* see x25519 specs */
		ext->extension_id = TLS_KEY_SHARE_EXT_ID;
		ext->extension_length = htons(38);
		ext->data_length = htons(36);
		ext->x25519_type = GROUP_EC_X25519;
		ext->x25519_size = htons(X25519_SECRET_SIZE);
		x25519_scalarmult(ext->x25519_pub_key, base_point, client_private_key);
		*ptr = ext + 1;
	} else {
		tls_empty_key_share_ce_t *ext = *ptr;
		ext->extension_id = TLS_KEY_SHARE_EXT_ID;
		ext->extension_length = htons(2);
		ext->data_length = htons(0);
		*ptr = ext + 1;
	}
}

void fill_alpn_ext(void **ptr) {
	tls_alpn_ce_t *ext = *ptr;
	ext->extension_id = TLS_ALPN_EXT_ID;
	ext->extension_length = htons(11);
	ext->data_length = htons(9);
	ext->http_1_1_length = 8;
	memcpy((char *)ext->http_1_1_id, "http/1.1", 8);
	*ptr = ext + 1;
}

void fill_psk_key_exchange_mode_ext(void **ptr) {
	tls_psk_key_exchange_mode_ce_t *ext = *ptr;
	ext->extension_id = TLS_PSK_KEY_EXCHANGE_MODE_EXT_ID;
	ext->extension_length = htons(2);
	ext->psk_key_exchange_mode_length = 1;
	ext->psk_key_exchange_mode_ke = TLS_PSK_MODE_DHE_KE;
	*ptr = ext + 1;
}

void fill_record_size_limit_ext(void **ptr) {
	tls_record_size_limit_ce_t *ext = *ptr;
	ext->extension_id = TLS_RECORD_SIZE_LIMIT_EXT_ID;
	ext->extension_length = htons(2);
	ext->record_size_limit = htons(TLS_MAX_BLOCK_SIZE);
	*ptr = ext + 1;
}

void fill_max_fragment_length(void **ptr) {
	tls_max_fragment_length_ce_t *ext = *ptr;
	ext->extension_id = TLS_MAX_FRAGMENT_LENGTH_EXT_ID;
	ext->extension_length = htons(1);
	ext->max_fragment_length = TLS_MAX_FRAGMENT_LENGTH_2_12;
	*ptr = ext + 1;
}

void fill_server_name_ext(void **ptr, const char *sni, size_t sni_length) {
	tls_server_name_ce_t *ext = *ptr;
	ext->extension_id = TLS_SERVER_NAME_EXT_ID;
	ext->extension_length = htons(sizeof(tls_server_name_ce_t) + sni_length - 4);
	ext->entry_length = htons(sizeof(tls_server_name_ce_t) + sni_length - 6);
	ext->dns_type = 0x00;	/* DNS hostname */
	ext->hostname_length = htons(sni_length);
	memcpy(ext->hostname, sni, sni_length);
	*ptr = (void *)(ext + 1) + sni_length;
}

void fill_pre_shared_key_ext(void **ptr, const void *buffer, const uint8_t ticket[], uint8_t ticket_length, uint32_t obfuscated_age,
							 uint8_t binder_key[]) {
	tls_pre_shared_key_ce_t *ext = *ptr;
	ext->extension_id = TLS_PRE_SHARED_KEY_EXT_ID;
	ext->extension_length = htons(sizeof(tls_pre_shared_key_ce_t) - 4 + ticket_length + sizeof(tls_pre_shared_key_end_ce_t) +
								  CIPHER_SUITE_HASH_SIZE);
	ext->identities_length = htons(sizeof(uint16_t) + ticket_length + sizeof(uint32_t));
	ext->identity_length = htons(ticket_length);
	memcpy(ext->identity, ticket, ticket_length);

	tls_pre_shared_key_end_ce_t *end = (void *)(ext + 1) + ticket_length;
	end->obfuscated_ticket_age = htonl(obfuscated_age);
	end->binders_length = htons(1 + CIPHER_SUITE_HASH_SIZE);
	end->binder_entry_length = CIPHER_SUITE_HASH_SIZE;

	/* Computing binder entry */
	uint8_t client_hello_hash[CIPHER_SUITE_HASH_SIZE];
	sha256_Init();
	sha256_Part(buffer, (void *)end - buffer + sizeof(uint32_t) /* obfuscated age */);
	sha256_Hash(client_hello_hash);
	hkdf_HMAC(binder_key, CIPHER_SUITE_HASH_SIZE, client_hello_hash, CIPHER_SUITE_HASH_SIZE, end->binder_entry);

	*ptr = (void *)(end + 1) + CIPHER_SUITE_HASH_SIZE;
}

web_status_t send_new_connection(tls_exchange_t *tls_exch, const char *sni, size_t sni_length) {
	/* Compute early_secret (when no PSK) */
	web_status_t ret_val = compute_early_secret(tls_exch->transcript, tls_exch->current_secret, NULL, 0, NULL, NULL, NULL);
	if(ret_val != WEB_SUCCESS) {
		return ret_val;
	}
	
	/* Generating private key */
	tls_exch->client_private_key = _malloc(X25519_SECRET_SIZE, "pkey");
	if(tls_exch->client_private_key == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	rng_Random256b(tls_exch->client_private_key);

	/* Filling the client hello message */
	const size_t client_hello_size = (sizeof(tls_client_hello_header_t) + sizeof(tls_supported_versions_ce_t) +
									  sizeof(tls_ec_point_formats_ce_t) + sizeof(tls_supported_groups_ce_t) +
									  sizeof(tls_signature_algo_ce_t) + sizeof(tls_key_share_ce_t) + sizeof(tls_alpn_ce_t) +
									  sizeof(tls_psk_key_exchange_mode_ce_t) + sizeof(tls_record_size_limit_ce_t) +
									  sizeof(tls_max_fragment_length_ce_t) + sizeof(tls_server_name_ce_t) + sni_length);
	uint8_t buffer[client_hello_size];
	void *client_hello_ptr = buffer;
	fill_client_hello_header(&client_hello_ptr, client_hello_size);
	fill_supported_versions_ext(&client_hello_ptr);
	fill_ec_point_formats_ext(&client_hello_ptr);
	fill_supported_groups_ext(&client_hello_ptr);
	fill_signature_algorithms_ext(&client_hello_ptr);
	fill_key_share_ext(&client_hello_ptr, tls_exch->client_private_key);
	fill_alpn_ext(&client_hello_ptr);
	fill_psk_key_exchange_mode_ext(&client_hello_ptr);
	fill_record_size_limit_ext(&client_hello_ptr);
	fill_max_fragment_length(&client_hello_ptr);
	fill_server_name_ext(&client_hello_ptr, sni, sni_length);

	/* Personal check, no fallback */
	if((size_t)((uint8_t *)client_hello_ptr - buffer) != client_hello_size) {
		dbg_warn("Client Hello size mismatch");
	}

	return deliver_tls_record(tls_exch, buffer, client_hello_size, TLS_HANDSHAKE_TYPE);
}

tls_ticket_list_t *find_session_ticket(uint32_t ip) {
	tls_ticket_list_t *ticket = tls_ticket_list;
	tls_ticket_list_t *previous = NULL;
	while(ticket != NULL) {
		if(time(NULL) - ticket->start_date > ntohl(ticket->ticket.lifetime)) {
			/* Ticket is too old, removing it */
			tls_ticket_list_t *next = ticket->next;
			if(previous != NULL) {
				previous->next = next;
			} else {
				tls_ticket_list = next;
			}
			_free(ticket->psk);
			_free(ticket);
			ticket = next;
			continue;
		}
		if(ticket->ip_server == ip) {
			/* Ticket is only used once */
			if(previous != NULL) {
				previous->next = ticket->next;
			} else {
				tls_ticket_list = ticket->next;
			}
			return ticket;
		}
		ticket = ticket->next;
	}
	return NULL;
}

web_status_t send_resumption_connection(tls_exchange_t *tls_exch, const char *sni, size_t sni_length, tls_ticket_list_t *ticket) {
	web_status_t ret_val = WEB_SUCCESS;
	dbg_info("Resuming connection\n");

	/* Age of the ticket should be OK, already checked by find_session_ticket */
	const uint32_t obfuscated_age = (time(NULL) - ticket->start_date) * 1000 /* MS */ + ntohl(ticket->ticket.age_add);

	/* Compute early_secret (when PSK is in use) */
	uint8_t binder_key[CIPHER_SUITE_HASH_SIZE];
	ret_val = compute_early_secret(tls_exch->transcript, tls_exch->current_secret, ticket->psk, ticket->psk_length, binder_key,
								   NULL, NULL);
	if(ret_val != WEB_SUCCESS) {
		return ret_val;
	}

	const void *ticket_ptr = (void *)&ticket->ticket.nonce + ticket->ticket.nonce_length;
	const uint8_t ticket_length = ntohs(*(uint16_t *)ticket_ptr);
	const size_t psk_ext_size = (sizeof(tls_pre_shared_key_ce_t) + ticket_length + sizeof(tls_pre_shared_key_end_ce_t) +
								 CIPHER_SUITE_HASH_SIZE);
	const size_t client_hello_size = (sizeof(tls_client_hello_header_t) + sizeof(tls_supported_versions_ce_t) +
									  sizeof(tls_signature_algo_ce_t) + sizeof(tls_key_share_ce_t) +
									  sizeof(tls_supported_groups_ce_t) + sizeof(tls_alpn_ce_t) +
									  sizeof(tls_psk_key_exchange_mode_ce_t) + sizeof(tls_record_size_limit_ce_t) +
									  sizeof(tls_max_fragment_length_ce_t) + sizeof(tls_server_name_ce_t) +
									  psk_ext_size + sni_length);
	uint8_t buffer[client_hello_size];
	void *client_hello_ptr = buffer;

	tls_exch->client_private_key = _malloc(X25519_SECRET_SIZE, "pkeyr");
	if(tls_exch->client_private_key == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	rng_Random256b(tls_exch->client_private_key);

	/* Filling the client hello message */
	fill_client_hello_header(&client_hello_ptr, client_hello_size);
	fill_supported_versions_ext(&client_hello_ptr);
	fill_key_share_ext(&client_hello_ptr, tls_exch->client_private_key);
	fill_supported_groups_ext(&client_hello_ptr);
	fill_signature_algorithms_ext(&client_hello_ptr);
	fill_alpn_ext(&client_hello_ptr);
	fill_psk_key_exchange_mode_ext(&client_hello_ptr);
	fill_record_size_limit_ext(&client_hello_ptr);
	fill_max_fragment_length(&client_hello_ptr);
	fill_server_name_ext(&client_hello_ptr, sni, sni_length);
	fill_pre_shared_key_ext(&client_hello_ptr, buffer, ticket_ptr + sizeof(uint16_t), ticket_length, obfuscated_age, binder_key);

	/* Personal check, no fallback */
	if((size_t)((uint8_t *)client_hello_ptr - buffer) != client_hello_size) {
		dbg_warn("Client Hello size mismatch");
	}

	return deliver_tls_record(tls_exch, buffer, client_hello_size, TLS_HANDSHAKE_TYPE);
}

tls_alert_t fetch_handshake_extensions(const uint8_t *extensions, size_t length, const uint8_t **server_public_key) {
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
				return TLS_ALERT_PROTOCOL_VERSION;
			}
		} else if(ext_type == TLS_KEY_SHARE_EXT_ID) {
			const uint16_t *ptr_16b = (uint16_t *)ptr;
			if(ext_size == X25519_SECRET_SIZE + 4 && ptr_16b[2] == GROUP_EC_X25519 && server_public_key != NULL) {
				*server_public_key = ptr + 8;
			} else {
				return TLS_ALERT_HANDSHAKE_FAILURE;
			}
		} else if(ext_type == TLS_ALPN_EXT_ID) {
			if(ext_size < 11 || ptr[6] < 8 || memcmp(ptr + 7, "http/1.1", 8) != 0) {
				dbg_err("Unsupported ALPN: %.*s", ptr[6], ptr + 7);
				return TLS_ALERT_HANDSHAKE_FAILURE;
			}
		} else if(ext_type == TLS_PRE_SHARED_KEY_EXT_ID) {
			/* Just catching */
		} else if(ext_type == TLS_SERVER_NAME_EXT_ID) {
			/* Just catching */
		} else if(ext_type == TLS_MAX_FRAGMENT_LENGTH_EXT_ID) {
			/* Just catching */
		} else {
			dbg_info("Unknown TLS ext: %x", ext_type);
		}
		ptr += ext_size + 4;
	}

	return TLS_ALERT_NONE;
}

tls_alert_t compute_cipher_data(tls_exchange_t *tls_exch) {
	web_status_t status;
	uint8_t cipher_key[tls_exch->cipher_callbacks->key_size];
	uint8_t cipher_iv[tls_exch->cipher_callbacks->iv_size];
	uint8_t decipher_key[tls_exch->cipher_callbacks->key_size];
	uint8_t decipher_iv[tls_exch->cipher_callbacks->iv_size];

	if(tls_exch->cipher_data != NULL) {
		tls_exch->cipher_callbacks->free(tls_exch->cipher_data);
		tls_exch->cipher_data = NULL;
	}

	status = compute_key_iv_pair(tls_exch->current_client_traffic_secret, cipher_key, tls_exch->cipher_callbacks->key_size,
								 cipher_iv, tls_exch->cipher_callbacks->iv_size);
	if(status != WEB_SUCCESS) {
		dbg_err("Unable to compute client key/iv pair");
		return TLS_ALERT_INTERNAL_ERROR;
	}

	status = compute_key_iv_pair(tls_exch->current_server_traffic_secret, decipher_key, tls_exch->cipher_callbacks->key_size,
								 decipher_iv, tls_exch->cipher_callbacks->iv_size);
	if(status != WEB_SUCCESS) {
		dbg_err("Unable to compute server key/iv pair");
		return TLS_ALERT_INTERNAL_ERROR;
	}

	tls_exch->cipher_data = tls_exch->cipher_callbacks->init(cipher_key, cipher_iv, decipher_key, decipher_iv);
	return tls_exch->cipher_data == NULL ? TLS_ALERT_INTERNAL_ERROR : TLS_ALERT_NONE;
}

tls_alert_t fetch_server_hello(tls_exchange_t *tls_exch, tls_hello_t *server_hello, size_t length) {
	(void)length;
	tls_alert_t status;
	const size_t sh_length = server_hello->header.length;
	if(server_hello->version != TLS_VERSION_1_2 || sh_length < sizeof(tls_hello_t) + 2 + 1 + 2) {  /* cipher_suite + comp_meth + ext_size */
		return TLS_ALERT_PROTOCOL_VERSION;
	}

	/*
	 * Checking if it's a HelloRetryRequest.
	 * This should not happen in our case because only one cipher suite is supported (so the server can't pick another one)
	 */
	const uint8_t hello_retry_random[] = HELLO_RETRY_VALUE;
	if(memcmp(hello_retry_random, server_hello->random, sizeof(hello_retry_random)) == 0) {
		dbg_err("Unsupported: HelloRetryRequest");
		return TLS_ALERT_INTERNAL_ERROR;
	}

	const uint8_t *pointer_sh = (uint8_t *)server_hello + sizeof(tls_hello_t) - 1;
	pointer_sh += *pointer_sh + 1;  /* Skipping session ID */

	/* Selected cipher suite */
	if(*(uint16_t *)pointer_sh != TLS_AES_128_GCM_SHA256) {
		dbg_err("Unsupported cipher suite");
		return TLS_ALERT_HANDSHAKE_FAILURE;
	}
	pointer_sh += 2;

	/* Compression method must be 0 */
	if(*pointer_sh != 0x00) {
		dbg_err("Unsupported compression method");
		return TLS_ALERT_HANDSHAKE_FAILURE;
	}
	pointer_sh++;

	/* Parse extensions */
	const size_t ext_size = ntohs(*(uint16_t *)pointer_sh);
	const uint8_t *extensions = pointer_sh + 2;
	const uint8_t *server_public_key = NULL;
	status = fetch_handshake_extensions(extensions, ext_size, &server_public_key);
	if(status != TLS_ALERT_NONE) {
		dbg_err("Unable to fetch extensions");
		return status;
	}
	if(server_public_key == NULL) {
		return TLS_ALERT_MISSING_EXTENSION;
	}

	/* Should be retrieved from the server hello if several cipher suites were supported */
	tls_exch->cipher_callbacks = &aes128gcm_callbacks;

	/* All necessary memory data */
	tls_exch->current_server_traffic_secret = _malloc(CIPHER_SUITE_HASH_SIZE, "csts");
	if(tls_exch->current_server_traffic_secret == NULL) {
		return TLS_ALERT_INTERNAL_ERROR;
	}
	tls_exch->current_client_traffic_secret = _malloc(CIPHER_SUITE_HASH_SIZE, "ccts");
	if(tls_exch->current_client_traffic_secret == NULL) {
		return TLS_ALERT_INTERNAL_ERROR;
	}
	uint8_t shared_secret[X25519_SECRET_SIZE];
	x25519_scalarmult(shared_secret, server_public_key, tls_exch->client_private_key);
	memset(tls_exch->client_private_key, 0, X25519_SECRET_SIZE);
	_free(tls_exch->client_private_key);
	tls_exch->client_private_key = NULL;

	/* (De)cipher algo. initialization */
	const web_status_t ret_val = compute_handshake_secret(tls_exch->transcript, tls_exch->current_secret, shared_secret,
														  X25519_SECRET_SIZE, tls_exch->current_client_traffic_secret,
														  tls_exch->current_server_traffic_secret);
	if(ret_val != WEB_SUCCESS) {
		return TLS_ALERT_INTERNAL_ERROR;
	}

	/* Computing handshake-specific secrets */
	status = compute_cipher_data(tls_exch);

	/* Freeing critical data */
	memset(shared_secret, 0, X25519_SECRET_SIZE);
	return status;
}

tls_alert_t fetch_encrypted_extension(tls_exchange_t *tls_exch, const tls_encrypted_extensions_t *encrypted_ext, size_t length) {
	(void)tls_exch; (void)length;
	const size_t ext_size = ntohs(encrypted_ext->extensions_size);
	return fetch_handshake_extensions(encrypted_ext->extensions, ext_size, NULL);
}

tls_alert_t fetch_server_finished(tls_exchange_t *tls_exch, tls_finished_t *server_finished, size_t length) {
	uint8_t hash[CIPHER_SUITE_HASH_SIZE];
	uint8_t finished_key[CIPHER_SUITE_HASH_SIZE];
	uint8_t finished_value[CIPHER_SUITE_HASH_SIZE];

	/* Check server finished */
	hkdf_ExpandLabel(tls_exch->current_server_traffic_secret, "finished", NULL, 0, finished_key, CIPHER_SUITE_HASH_SIZE);
	compute_transcript_hash(tls_exch->transcript, TLS_HS_SERVER_FINISHED - 1, hash);
	hkdf_HMAC(finished_key, CIPHER_SUITE_HASH_SIZE, hash, CIPHER_SUITE_HASH_SIZE, finished_value);
	if(length != CIPHER_SUITE_HASH_SIZE + 4 || memcmp(server_finished->hash, finished_value, CIPHER_SUITE_HASH_SIZE) != 0) {
		dbg_err("Incorrect server finished");
		return TLS_ALERT_DECRYPT_ERROR;
	}

	/* Send client finished */
	const size_t length_finished_buffer = sizeof(tls_finished_t) + CIPHER_SUITE_HASH_SIZE;
	uint8_t finished_buffer[length_finished_buffer];
	tls_finished_t *client_finished = (tls_finished_t *)finished_buffer;
	client_finished->header.hs_type = TLS_HS_TYPE_FINISHED;
	client_finished->header.length = htonl24(CIPHER_SUITE_HASH_SIZE);
	hkdf_ExpandLabel(tls_exch->current_client_traffic_secret, "finished", NULL, 0, finished_key, CIPHER_SUITE_HASH_SIZE);
	compute_transcript_hash(tls_exch->transcript, TLS_HS_SERVER_FINISHED, hash);
	hkdf_HMAC(finished_key, CIPHER_SUITE_HASH_SIZE, hash, CIPHER_SUITE_HASH_SIZE, client_finished->hash);
	deliver_tls_record(tls_exch, finished_buffer, length_finished_buffer, TLS_HANDSHAKE_TYPE);

	/* Compute application traffic secrets */
	tls_exch->res_master_secret = _malloc(CIPHER_SUITE_HASH_SIZE, "resms");
	if(tls_exch->res_master_secret == NULL) {
		return TLS_ALERT_INTERNAL_ERROR;
	}
	compute_master_secret(tls_exch->transcript, tls_exch->current_secret, tls_exch->current_client_traffic_secret,
						  tls_exch->current_server_traffic_secret, NULL, tls_exch->res_master_secret);
	_free_transcript(&tls_exch->transcript);
	return compute_cipher_data(tls_exch);
}

tls_alert_t fetch_new_session_ticket(tls_exchange_t *tls_exch, const tls_new_session_ticket_t *session_ticket, size_t length) {
	/* Queuing the ticket in the session ticket list */
	tls_ticket_list_t *new_ticket = _malloc(sizeof(tls_ticket_list_t) + length - sizeof(tls_session_ticket_t), "ticket");
	if(new_ticket == NULL) {
		return TLS_ALERT_INTERNAL_ERROR;
	}

	memcpy(&new_ticket->ticket, &session_ticket->ticket, length);
	new_ticket->next = tls_ticket_list;
	new_ticket->ip_server = tls_exch->tcp_exch->ip_dst;
	new_ticket->start_date = time(NULL);  /* epoch in seconds */
	new_ticket->psk_length = CIPHER_SUITE_HASH_SIZE;
	new_ticket->psk = _malloc(CIPHER_SUITE_HASH_SIZE, "psk");
	if(new_ticket->psk == NULL) {
		_free(new_ticket);
		return TLS_ALERT_INTERNAL_ERROR;
	}

	hkdf_ExpandLabel(tls_exch->res_master_secret, "resumption", session_ticket->ticket.nonce,
					 session_ticket->ticket.nonce_length, new_ticket->psk, CIPHER_SUITE_HASH_SIZE);
	tls_ticket_list = new_ticket;
	dbg_verb("New ticket registered");

	return TLS_ALERT_NONE;
}

tls_alert_t fetch_key_update_request(tls_exchange_t *tls_exch, tls_key_update_t *key_upd_msg, size_t length) {
	(void)length;
	key_upd_msg->key_update_request = TLS_KEY_UPDATE_NOT_REQUESTED;
	deliver_tls_record(tls_exch, key_upd_msg, sizeof(tls_key_update_t), TLS_HANDSHAKE_TYPE);
	hkdf_ExpandLabel(tls_exch->current_client_traffic_secret, "traffic upd", NULL, 0, tls_exch->current_client_traffic_secret, CIPHER_SUITE_HASH_SIZE);
	hkdf_ExpandLabel(tls_exch->current_server_traffic_secret, "traffic upd", NULL, 0, tls_exch->current_server_traffic_secret, CIPHER_SUITE_HASH_SIZE);
	compute_cipher_data(tls_exch);
	return TLS_ALERT_NONE;
}

tls_alert_t fetch_certificate_request(tls_exchange_t *tls_exch, const tls_cert_request_t *cert_request, size_t length) {
	(void)length;
	const size_t response_size = sizeof(tls_empty_certificate_t) + cert_request->context_size + sizeof(uint24_t);
	uint8_t response_buffer[response_size];
	tls_empty_certificate_t *certificate_response = (tls_empty_certificate_t *)response_buffer;
	certificate_response->header.hs_type = TLS_HS_TYPE_CERTIFICATE;
	certificate_response->header.length = htonl24(response_size - sizeof(tls_handshake_t));
	memcpy(&certificate_response->context_size, &cert_request->context_size, sizeof(uint8_t) + cert_request->context_size);
	*(uint24_t *)&response_buffer[response_size - sizeof(uint24_t)] = 0;  /* Empty certificate list */
	deliver_tls_record(tls_exch, certificate_response, response_size, TLS_HANDSHAKE_TYPE);
	return TLS_ALERT_NONE;
}

tls_alert_t fetch_handshake_message(tls_exchange_t *tls_exch, tls_handshake_t *handshake_msg, size_t length) {
	tls_alert_t status = TLS_ALERT_NONE;
	dbg_verb("Received hs: %u", handshake_msg->hs_type);

	if(tls_exch->tls_state < TLS_STATE_CONNECTED) {
		add_transcript_message(&tls_exch->transcript, handshake_msg, length, TLS_SENDER_SERVER);
	}

	switch(tls_exch->tls_state) {
		case TLS_STATE_WAIT_SERVER_HELLO:
			if(handshake_msg->hs_type != TLS_HS_TYPE_SERVER_HELLO) {
				status = TLS_ALERT_UNEXPECTED_MESSAGE;
				break;
			}
			status = fetch_server_hello(tls_exch, (tls_hello_t *)handshake_msg, length);
			if(status != TLS_ALERT_NONE) {
				break;
			}
			uint8_t change_cs_content = 1;
			deliver_tls_record(tls_exch, &change_cs_content, sizeof(uint8_t), TLS_CHANGE_CIPHER_SPEC);
			tls_exch->tls_state = TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS;
			break;
		case TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS:
			if(handshake_msg->hs_type != TLS_HS_TYPE_ENCRYPTED_EXTENSIONS) {
				status = TLS_ALERT_UNEXPECTED_MESSAGE;
				break;
			}
			tls_exch->tls_state = TLS_STATE_WAIT_CERT_CR;
			const tls_encrypted_extensions_t *encrypted_ext = (tls_encrypted_extensions_t *)handshake_msg;
			status = fetch_encrypted_extension(tls_exch, encrypted_ext, length);
			break;
		case TLS_STATE_WAIT_CERT_CR:
			if(handshake_msg->hs_type == TLS_HS_TYPE_CERTIFICATE_REQUEST) {
				tls_exch->tls_state = TLS_STATE_WAIT_CERTIFICATE;
				const tls_cert_request_t *cert_request = (tls_cert_request_t *)handshake_msg;
				status = fetch_certificate_request(tls_exch, cert_request, length);
			} else if(handshake_msg->hs_type == TLS_HS_TYPE_CERTIFICATE) {
				tls_exch->tls_state = TLS_STATE_WAIT_CERTIFICATE_VERIFY;
			} else {
				status = TLS_ALERT_UNEXPECTED_MESSAGE;
			}
			break;
		case TLS_STATE_WAIT_CERTIFICATE:
			if(handshake_msg->hs_type != TLS_HS_TYPE_CERTIFICATE) {
				status = TLS_ALERT_UNEXPECTED_MESSAGE;
				break;
			}
			tls_exch->tls_state = TLS_STATE_WAIT_CERTIFICATE_VERIFY;
			break;
		case TLS_STATE_WAIT_CERTIFICATE_VERIFY:
			if(handshake_msg->hs_type != TLS_HS_TYPE_CERTIFICATE_VERIFY) {
				status = TLS_ALERT_UNEXPECTED_MESSAGE;
				break;
			}
			tls_exch->tls_state = TLS_STATE_WAIT_FINISHED;
			break;
		case TLS_STATE_WAIT_FINISHED:
			if(handshake_msg->hs_type != TLS_HS_TYPE_FINISHED) {
				status = TLS_ALERT_UNEXPECTED_MESSAGE;
				break;
			}
			status = fetch_server_finished(tls_exch, (tls_finished_t *)handshake_msg, length);
			if(status == TLS_ALERT_NONE) {
				dbg_info("TLS handshake done");
				tls_exch->tls_state = TLS_STATE_CONNECTED;
			}
			break;
		case TLS_STATE_CONNECTED:
		case TLS_STATE_CLOSE_NOTIFY_SENT:
			if(handshake_msg->hs_type == TLS_HS_TYPE_NEW_SESSION_TICKET) {
				const tls_new_session_ticket_t *session_ticket = (tls_new_session_ticket_t *)handshake_msg;
				const size_t ticket_size = ntohl24(session_ticket->header.length);
				status = fetch_new_session_ticket(tls_exch, session_ticket, ticket_size);
			} else if(handshake_msg->hs_type == TLS_HS_TYPE_CERTIFICATE_REQUEST) {
				const tls_cert_request_t *cert_request = (tls_cert_request_t *)handshake_msg;
				status = fetch_certificate_request(tls_exch, cert_request, length);
			} else if(handshake_msg->hs_type == TLS_HS_TYPE_KEY_UPDATE) {
				tls_key_update_t *key_upd_msg = (tls_key_update_t *)handshake_msg;
				if(key_upd_msg->key_update_request == TLS_KEY_UPDATE_REQUESTED) {
					status = fetch_key_update_request(tls_exch, key_upd_msg, length);
				} else {
					dbg_warn("Weird key update msg?");
				}
			} else {
				status = TLS_ALERT_UNEXPECTED_MESSAGE;
			}
			break;
		case TLS_STATE_CLOSE_NOTIFY_RECEIVED:
		default:
			dbg_err("Unexpected TLS state!");
			break;
	}

	if(status != TLS_ALERT_NONE) {
		dbg_err("TLS HS failed: msg=%u ; state=%u", handshake_msg->hs_type, tls_exch->tls_state);
	}

	return status;
}

void received_close_signal(tls_exchange_t *tls_exch) {
	/* Some servers do not send CLOSE NOTIFY alert and only send a FIN segment to signal the end of a connection */
	if(tls_exch->appli_callback != NULL) {
		tls_exch->appli_callback(tls_exch->tcp_exch->port_src, LINK_MSG_TYPE_FIN, NULL, 0, tls_exch->appli_data);
	}
	/*
	 * The CLOSE_NOTIFY alert is actually ignored by the implementation. This is because the implementation
	 * closes the read socket at the same time as the write socket (ie during the web_TLSClose).
	 * Hence, the following lines are only formalities
	 */
	if(tls_exch->tls_state == TLS_STATE_CLOSE_NOTIFY_SENT) {
		tls_exch->tls_state = TLS_STATE_CLOSED;
	} else {
		tls_exch->tls_state = TLS_STATE_CLOSE_NOTIFY_RECEIVED;
	}
}

tls_alert_t fetch_alert_record(tls_exchange_t *tls_exch, tls_alert_record_t *alert_record) {
	switch(alert_record->alert_description) {
		case TLS_ALERT_CLOSE_NOTIFY:
			received_close_signal(tls_exch);
			break;
		case TLS_ALERT_USER_CANCELED:
			/* Ignore, the remote host will send us a CLOSE_NOTIFY record soon */
			break;
		default:
			/* Fatal */
			dbg_err("Received fatal alert: %u", alert_record->alert_description);
			unexpected_abort(tls_exch, TLS_ALERT_NONE);
			break;
	}
	return TLS_ALERT_NONE;
}

tls_alert_t fetch_tls_record(tls_exchange_t *tls_exch, void *payload, size_t length, tls_content_type_t content_type) {
	tls_alert_t ret_val = TLS_ALERT_NONE;
	switch(content_type) {
		case TLS_ALERT_TYPE:
			ret_val = fetch_alert_record(tls_exch, (tls_alert_record_t *)payload);
			break;
		case TLS_HANDSHAKE_TYPE: {
			size_t fetched_size = 0;
			while(fetched_size < length) {
				tls_handshake_t *const hs_msg = (tls_handshake_t *)(payload + fetched_size); 
				const size_t hs_msg_size = htonl24(hs_msg->length) + sizeof(tls_handshake_t);
				ret_val = fetch_handshake_message(tls_exch, (tls_handshake_t *)(payload + fetched_size), hs_msg_size);
				if(ret_val != TLS_ALERT_NONE) {
					dbg_err("Err during hs");
					return ret_val;
				}
				fetched_size += hs_msg_size;
			}
			break;
		} case TLS_APPLI_DATA_TYPE:
			/* Ignoring the returned value of the callback (for now?) */
			if(tls_exch->appli_callback != NULL) {
				tls_exch->appli_callback(tls_exch->tcp_exch->port_src, LINK_MSG_TYPE_DATA, payload, length, tls_exch->appli_data);
			}
			break;
		default:
			dbg_warn("Invalid TLS type: %u", content_type);
			ret_val = TLS_ALERT_UNEXPECTED_MESSAGE;
			break;
	}

	return ret_val;
}

tls_alert_t fetch_tls_encrypted_record(tls_exchange_t *tls_exch, tls_record_t *record, size_t record_length) {
	if(record->opaque_type == TLS_CHANGE_CIPHER_SPEC) {
		if(ntohs(record->length) == 1 && record->data[0] == 0x01) {
			return TLS_ALERT_NONE;
		} else {
			dbg_err("Invalid Ch_Ci_Sp");
			return TLS_ALERT_UNEXPECTED_MESSAGE;
		}
	}

	uint8_t *payload = (uint8_t *)record + sizeof(tls_record_t);
	const size_t payload_length = record_length - sizeof(tls_record_t);
	web_status_t status = tls_exch->cipher_callbacks->decipher(payload, payload, payload_length, record, sizeof(tls_record_t),
												  			   tls_exch->cipher_data);
	if(status != WEB_SUCCESS) {
		dbg_err("Unable to decrypt!");
		return TLS_ALERT_BAD_RECORD_MAC;
	}

	size_t decipher_length = payload_length - tls_exch->cipher_callbacks->extra_size;
	/* Removing padding */
	const uint8_t *padded_payload = payload + decipher_length - 1;
	while(*padded_payload == 0x00) {
		padded_payload--;
		if(padded_payload <= payload) {
			dbg_err("Invalid padding");
			return TLS_ALERT_INTERNAL_ERROR;
		}
	}
	decipher_length = padded_payload - payload;
	return fetch_tls_record(tls_exch, payload, decipher_length, *padded_payload /* Content type */);;
}

web_status_t fetch_tls_part(web_port_t port, link_msg_type_t msg_type, void *data, size_t length,
						    web_callback_data_t *user_data) {
	(void)port; (void)user_data;
	
	tls_exchange_t *tls_exch = (tls_exchange_t *)user_data;
	if(tls_exch->tls_state == TLS_STATE_CLOSED) {
		dbg_warn("Callback called in CLOSED state");
		return WEB_ERROR_FAILED;
	}

	if(msg_type == LINK_MSG_TYPE_RST) {
		unexpected_abort(tls_exch, TLS_ALERT_NONE);
		return WEB_SUCCESS;
	} else if(msg_type == LINK_MSG_TYPE_FIN) {
		/* Some servers send a FIN without sending a CLOSE NOTIFY alert */
		if(tls_exch->tls_state != TLS_STATE_CLOSE_NOTIFY_RECEIVED && tls_exch->tls_state != TLS_STATE_CLOSED) {
			received_close_signal(tls_exch);
		}
		return WEB_SUCCESS;
	}

	/* Trying to retrieve the exact length of the downloading record */
	if(tls_exch->received_length < sizeof(tls_record_t) && length + tls_exch->received_length >= sizeof(tls_record_t)) {
		memcpy((void *)tls_exch->record + tls_exch->received_length, data, sizeof(tls_record_t) - tls_exch->received_length);
		const size_t record_length = ntohs(tls_exch->record->length);
		if(record_length > TLS_MAX_BLOCK_SIZE + tls_exch->cipher_callbacks->extra_size + 1 /* data type */) {
			dbg_err("Record too big: %uB", record_length);
			unexpected_abort(tls_exch, TLS_ALERT_RECORD_OVERFLOW);
			return WEB_ERROR_FAILED;
		}
		void *new_buffer = _realloc(tls_exch->record, record_length + sizeof(tls_record_t));
		if(new_buffer == NULL) {
			dbg_err("No memory left");
			unexpected_abort(tls_exch, TLS_ALERT_INTERNAL_ERROR);
			return WEB_NOT_ENOUGH_MEM;
		}
		tls_exch->record = new_buffer;
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
			tls_alert_t alert = TLS_ALERT_NONE;
			if(tls_exch->tls_state >= TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS) {  /* If encrypted */
				alert = fetch_tls_encrypted_record(tls_exch, tls_exch->record, tls_exch->received_length);
			} else {
				alert = fetch_tls_record(tls_exch, tls_exch->record->data,
										 tls_exch->received_length - sizeof(tls_record_t),
										 tls_exch->record->opaque_type);
			}
			if(alert != TLS_ALERT_NONE) {
				dbg_err("Err during record fetch");
				unexpected_abort(tls_exch, alert);
				return WEB_ERROR_FAILED;
			}

			_free(tls_exch->record);
			/* Reset structure for the next TLS record */
			tls_exch->record = _malloc(sizeof(tls_record_t), "tlsr2");
			if(tls_exch->record == NULL) {
				dbg_err("No memory left");
				unexpected_abort(tls_exch, TLS_ALERT_INTERNAL_ERROR);
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

void free_session_tickets() {
	tls_ticket_list_t *ticket = tls_ticket_list;
	while(ticket != NULL) {
		tls_ticket_list_t *next = ticket->next;
		_free(ticket->psk);
		_free(ticket);
		ticket = next;
	}
	tls_ticket_list = NULL;
}

void unexpected_abort(tls_exchange_t *tls_exch, tls_alert_t reason) {
	if(tls_exch->appli_callback != NULL) {
		tls_exch->appli_callback(tls_exch->tcp_exch->port_src, LINK_MSG_TYPE_RST, NULL, 0, tls_exch->appli_data);
	}
	tls_close(tls_exch, reason, false);
}

void tls_close(tls_exchange_t *tls_exch, tls_alert_t reason, bool is_from_appli) {
	/* tls_close might have been already called by the implem, then by the appli */
	if(tls_exch->tls_state != TLS_STATE_CLOSED) {
		if(reason != TLS_ALERT_NONE) {
			send_alert(tls_exch, reason);
			force_send_queue();  /* Before the TCPClose flushes the sending queue */
		}
		tls_exch->tls_state = TLS_STATE_CLOSED;
		web_TCPClose(tls_exch->tcp_exch, !is_from_appli);

		_free_transcript(&tls_exch->transcript);
		if(tls_exch->cipher_data != NULL) {
			tls_exch->cipher_callbacks->free(tls_exch->cipher_data);
			tls_exch->cipher_data = NULL;
		}
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
		if(tls_exch->res_master_secret != NULL) {
			_free(tls_exch->res_master_secret);
			tls_exch->res_master_secret = NULL;
		}
		if(tls_exch->record != NULL) {
			_free(tls_exch->record);
			tls_exch->record = NULL;
		}
	}

	/* Only removing the tls_exchange_t structure if the close is from the appli or during the handshake */
	if(is_from_appli || tls_exch->appli_callback == NULL) {
		_free(tls_exch);
	}
}
