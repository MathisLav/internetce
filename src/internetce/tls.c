#include <internet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "include/tls.h"
#include "include/tcp.h"
#include "include/debug.h"
#include "include/crypto.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_status_t web_DeliverTLSData(tcp_exchange_t *tcp_exch, void *data, size_t length_data) {
	// only allocating for the length + tls header because it will be reallocated in web_DeliveryTCPSegment
	void *buffer = malloc(sizeof(tls_record_t) + length_data);
	if(buffer == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	memcpy(buffer + sizeof(tls_record_t), data, length_data);

	return _recursive_PushTLSRecord(buffer, buffer + sizeof(tls_record_t), length_data, tcp_exch, TLS_APPLI_DATA_TYPE);
}

web_status_t web_TLSHandhake(tcp_exchange_t *tcp_exch, const char *server_name) {
	size_t server_name_length = strlen(server_name);
	if(server_name_length > TLS_SERVER_NAME_MAX_LENGTH) {
		dbg_err("SNI too long: %d > %d", server_name_length, TLS_SERVER_NAME_MAX_LENGTH);
		return WEB_ERROR_FAILED;
	}

	if(!rng_IsAvailable()) {
		dbg_err("Not enough entropy");
		return WEB_NOT_ENOUGH_ENTROPY;
	}

	size_t hs_length = sizeof(tls_handshake_ce_t) + server_name_length;

	const tls_handshake_ce_t hello_record = {
    	.hs_type = TLS_HANDSHAKE_CLIENT_HELLO_TYPE,
		.client_hello_length = htonl24(hs_length - 4),
		.version = TLS_VERSION_1_2,
		.random = {},	// memcpied
		.session_id_length = 32,			        	// Session ID not used in TLS 1.3
		.session_id = {},	// memcpied
		.cipher_suit_length = htons(SIZE_CIPHER_SUITS),
    	.cipher_suits = LIST_SUPPORTED_CIPHER_SUITS,
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
			.x25519_size = htons(32),
			.x25519_pub_key = {}	// memcpied
		},
		.alpn_ext = (tls_alpn_ce_t){
			.extension_id = TLS_ALPN_EXT_ID,
			.extension_length = htons(11),
			.http_1_1_length = 9,
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

	uint8_t hello_buffer[hs_length + sizeof(tls_record_t)];
	tls_handshake_ce_t *hello_buffer_record = (tls_handshake_ce_t *)(hello_buffer + sizeof(tls_record_t));
	memcpy(hello_buffer_record, &hello_record, sizeof(tls_handshake_ce_t));

	/* Computing public key */
	uint8_t private_key[32];
	uint8_t public_key[32];
	uint8_t base_point[32] = {9, 0};  // see x25519 specs
	rng_Random256b(private_key);
	x25519_clampscalar(private_key);
	x25519_scalarmult(public_key, base_point, private_key);
	memcpy(hello_buffer_record->key_share_ext.x25519_pub_key, public_key, 32);

	/* client_random & server_name */
	rng_Random256b(hello_buffer_record->session_id);
	rng_Random256b(hello_buffer_record->random);
	memcpy(hello_buffer_record->server_name_ext.hostname, server_name, server_name_length);

	printf("Send: %p\n", hello_buffer);

	_recursive_PushTLSRecord(hello_buffer, hello_buffer_record, hs_length, tcp_exch, TLS_HANDSHAKE_TYPE);

	return WEB_SUCCESS;
}

void web_TLSTest(const char *server_name) {
	uint32_t ip = web_SendDNSRequest(server_name);
	// uint32_t ip = ip_ascii_to_hex("192.168.1.36");
	printf("IP: %lx\n", ip);

	tls_exchange_t *tls_exch = malloc(sizeof(tls_exchange_t));
	/* Allocating the memory for the TLS header until we receive the actual size of the record */
	tls_exch->record = malloc(sizeof(tls_record_t));
	tls_exch->received_length = 0;

	tcp_exchange_t *tcp_exch = web_TCPConnect(ip, HTTPS_PORT, fetch_tls_part, tls_exch);
	web_WaitForEvents(); // sending Ack
	if(tcp_exch == NULL) {
		printf("FAILED connection\n");
		pause();
		return;
	}

	tls_exch->tcp_exch = tcp_exch;
	web_TLSHandhake(tcp_exch, server_name);
}

void web_TLSClose(tls_exchange_t *tls_exch) {
	// TODO send a BYE record?

	web_TCPClose(tls_exch->tcp_exch);

	if(tls_exch != NULL) {
		free(tls_exch->record);
		free(tls_exch);
	}
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

web_status_t _recursive_PushTLSRecord(void *buffer, void *data, size_t length_data, tcp_exchange_t *tcp_exch,
									  uint8_t opaque_type) {
	if(data - sizeof(tls_record_t) < buffer) {
		dbg_err("Can't push TLS record");
		free(buffer);
		return WEB_NOT_ENOUGH_MEM;
	}

	/* Filling the TLS record header */
	size_t size = length_data + sizeof(tls_record_t);
	tls_record_t *tls_record = (tls_record_t *)(data - sizeof(tls_record_t));
	tls_record->opaque_type = opaque_type;
	tls_record->legacy_version = TLS_VERSION_1_2;
	tls_record->length = htons(length_data);

	return web_DeliverTCPSegment(tcp_exch, tls_record, size, FLAG_TCP_PSH | FLAG_TCP_ACK, 0, NULL);
}

web_status_t fetch_tls_record(tls_exchange_t *tls_exch) {
	const tls_record_t *record = tls_exch->record;
	const uint8_t *content = record->data;

	switch(record->opaque_type) {
		case TLS_CHANGE_CIPHER_SPEC:
			printf("Change Cipher Spec received\n");
			break;
		case TLS_ALERT_TYPE:
			if(record->length != 0) {
				tls_alert_record_t *alert_record = (tls_alert_record_t *)content;
				if(alert_record->alert_level == TLS_ALERT_LEVEL_WARNING) {
					dbg_warn("TLS alert: %u", alert_record->alert_description);
				} else {
					dbg_err("TLS alert: %u", alert_record->alert_description);
					// TODO fallback to new TLS connection ?
				}
			} else {
				dbg_err("Empty TLS alert");
			}
			break;
		case TLS_HANDSHAKE_TYPE:
			printf("Server Hello received\n");
			break;
		case TLS_APPLI_DATA_TYPE:
			printf("Appli data received\n");
			break;
		default:
			dbg_warn("Invalid TLS type: %u", record->opaque_type);
	}

	// debug(record, 8);
	// pause();

	return WEB_SUCCESS;
}

web_status_t fetch_tls_part(web_port_t port, uint8_t protocol, void *data, size_t length,
						    web_callback_data_t *user_data) {
	(void)port; (void)protocol; (void)user_data;
	
	tls_exchange_t *tls_exch = (tls_exchange_t *)user_data;
	if(tls_exch->received_length < sizeof(tls_record_t)) {
		/* The exchange has just started */
		if(length + tls_exch->received_length >= sizeof(tls_record_t)) {
			/* Must have access to the exact size of the final TLS record */
			memcpy((void *)tls_exch->record + tls_exch->received_length, data, sizeof(tls_record_t) - tls_exch->received_length);
			/* Allocating the needed buffer */
			void *new_buffer = realloc(tls_exch->record, ntohs(tls_exch->record->length) + sizeof(tls_record_t));
			if(new_buffer == NULL) {
				dbg_err("No memory left");
				web_TLSClose(tls_exch);
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
		if(tls_exch->received_length >= ntohs(tls_exch->record->length) + sizeof(tls_record_t)) {
			dbg_info("TLS data on port %u OK", port);
			fetch_tls_record(tls_exch);

			/* Reset structure for the next TLS record */
			free(tls_exch->record);
			tls_exch->record = malloc(sizeof(tls_record_t));
			if(tls_exch->record == NULL) {
				dbg_err("No memory left");
				web_TLSClose(tls_exch);
				return WEB_NOT_ENOUGH_MEM;
			}
			tls_exch->received_length = 0;
		}
	}

	const size_t remaining_data = length - to_copy;
	if(remaining_data > 0) {
		fetch_tls_part(port, protocol, data + to_copy, remaining_data, user_data);
	}
	
	return WEB_SUCCESS;
}
