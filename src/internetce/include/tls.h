/**
 * TLS related functions
 */

#ifndef INTERNET_TLS
#define INTERNET_TLS

#include <internet.h>
#include "core.h"
#include "crypto.h"


/**
 * External structures
 */

extern cipher_callbacks_t aes128gcm_callbacks;

/**
 * Constants
 */

#define TIMEOUT_TLS_HANDSHAKE			20

#define TLS_VERSION_1_0					htons(0x0301)
#define TLS_VERSION_1_2					htons(0x0303)
#define TLS_VERSION_1_3					htons(0x0304)

#define NUMBER_SUPPORTED_CIPHER_SUITES	2
#define TLS_AES_128_GCM_SHA256			htons(0x1301)
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV htons(0x00ff)
#define LIST_SUPPORTED_CIPHER_SUITES 	{TLS_AES_128_GCM_SHA256, TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
#define SIZE_CIPHER_SUITES               (NUMBER_SUPPORTED_CIPHER_SUITES * sizeof(uint16_t))

#define NUMBER_SUPPORTED_GROUPS			1
#define GROUP_EC_X25519					htons(0x001d)
#define LIST_SUPPORTED_GROUPS			{GROUP_EC_X25519}
#define SIZE_GROUPS                     (NUMBER_SUPPORTED_GROUPS * sizeof(uint16_t))

#define NUMBER_SUPPORTED_SIGNATURE_ALGO 2
#define SIGN_RSA_PSS_RSAE_SHA256		htons(0x0804)	// Not implemented yet
#define SIGN_ECDSA_SECP256R1_SHA256		htons(0x0403)	// Not implemented yet
#define LIST_SUPPORTED_SIGNATURE_ALGO	{SIGN_RSA_PSS_RSAE_SHA256, SIGN_ECDSA_SECP256R1_SHA256}
#define SIZE_SIGNATURE_ALGO             (NUMBER_SUPPORTED_SIGNATURE_ALGO * sizeof(uint16_t))

#define TLS_MAX_FRAGMENT_LENGTH_EXT_ID	htons(0x0001)
#define TLS_SUPPORTED_VERSIONS_EXT_ID	htons(0x002b)
#define TLS_EC_POINT_FORMATS_EXT_ID		htons(0x000b)
#define TLS_SUPPORTED_GROUPS_EXT_ID		htons(0x000a)
#define TLS_SIGNATURE_ALGO_EXT_ID		htons(0x000d)
#define TLS_KEY_SHARE_EXT_ID			htons(0x0033)
#define TLS_ALPN_EXT_ID					htons(0x0010)
#define TLS_EXTENDED_MSECRET_EXT_ID		htons(0x0017)
#define TLS_PSK_KEY_EXCHANGE_MODE_EXT_ID htons(0x002d)
#define TLS_PRE_SHARED_KEY_EXT_ID		htons(0x0029)
#define TLS_RECORD_SIZE_LIMIT_EXT_ID	htons(0x001c)
#define TLS_SERVER_NAME_EXT_ID			htons(0x0000)
#define TLS_PADDING_EXT_ID				htons(0x0015)

#define TLS_SERVER_NAME_MAX_LENGTH		128

#define HELLO_RETRY_VALUE	{0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,\
							 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C}

#define TLS_MAX_BLOCK_SIZE	AES_MAX_BLOCK_SIZE  /* Limiting factor */


/**
 * Enums
 */

typedef enum tls_key_exch_mode {
	TLS_PSK_MODE_KE		= 0,
	TLS_PSK_MODE_DHE_KE	= 1,
} tls_key_exch_mode_t;

typedef enum tls_alert_level {
	TLS_ALERT_LEVEL_WARNING	= 1,
	TLS_ALERT_LEVEL_FATAL	= 2
} tls_alert_level_t;

typedef enum tls_alert {
	TLS_ALERT_CLOSE_NOTIFY						= 0,
	TLS_ALERT_UNEXPECTED_MESSAGE				= 10,
	TLS_ALERT_BAD_RECORD_MAC					= 20,
	TLS_ALERT_DECRYPTION_FAILED_RESERVED		= 21,
	TLS_ALERT_RECORD_OVERFLOW					= 22,
	TLS_ALERT_DECOMPRESSION_FAILURE_RESERVED	= 30,
	TLS_ALERT_HANDSHAKE_FAILURE					= 40,
	TLS_ALERT_NO_CERTIFICATE_RESERVED			= 41,
	TLS_ALERT_BAD_CERTIFICATE					= 42,
	TLS_ALERT_UNSUPPORTED_CERTIFICATE			= 43,
	TLS_ALERT_CERTIFICATE_REVOKED				= 44,
	TLS_ALERT_CERTIFICATE_EXPIRED				= 45,
	TLS_ALERT_CERTIFICATE_UNKNOWN				= 46,
	TLS_ALERT_ILLEGAL_PARAMETER					= 47,
	TLS_ALERT_UNKNOWN_CA						= 48,
	TLS_ALERT_ACCESS_DENIED						= 49,
	TLS_ALERT_DECODE_ERROR						= 50,
	TLS_ALERT_DECRYPT_ERROR						= 51,
	TLS_ALERT_EXPORT_RESTRICTION_RESERVED		= 60,
	TLS_ALERT_PROTOCOL_VERSION					= 70,
	TLS_ALERT_INSUFFICIENT_SECURITY				= 71,
	TLS_ALERT_INTERNAL_ERROR					= 80,
	TLS_ALERT_INAPPROPRIATE_FALLBACK			= 86,
	TLS_ALERT_USER_CANCELED						= 90,
	TLS_ALERT_NO_RENEGOTIATION_RESERVED			= 100,
	TLS_ALERT_MISSING_EXTENSION					= 109,
	TLS_ALERT_UNSUPPORTED_EXTENSION				= 110,
	TLS_ALERT_CERTIFICATE_UNOBTAINABLE_RESERVED	= 111,
	TLS_ALERT_UNRECOGNIZED_NAME					= 112,
	TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE	= 113,
	TLS_ALERT_BAD_CERTIFICATE_HASH_VALUE_RESERVED	= 114,
	TLS_ALERT_UNKNOWN_PSK_IDENTITY				= 115,
	TLS_ALERT_CERTIFICATE_REQUIRED				= 116,
	TLS_ALERT_NO_APPLICATION_PROTOCOL			= 120,
	TLS_ALERT_NONE								= 255,
} tls_alert_t;

typedef enum tls_max_frag_length {
	TLS_MAX_FRAGMENT_LENGTH_2_9 	= 1,
	TLS_MAX_FRAGMENT_LENGTH_2_10 	= 2,
	TLS_MAX_FRAGMENT_LENGTH_2_11 	= 3,
	TLS_MAX_FRAGMENT_LENGTH_2_12 	= 4,
} tls_max_frag_length_t;


/**
 * Internal structures
 */

typedef struct tls_supported_versions_ce {
	uint16_t extension_id;      /**< 0x002b */
	uint16_t extension_length;  /**< 3      */
	uint8_t data_length;        /**< 2      */
    uint16_t version_tls_13;    /**< 0x0304 */
} tls_supported_versions_ce_t;

typedef struct tls_ec_point_formats_ce {
	uint16_t extension_id;      /**< 0x000b */
	uint16_t extension_length;  /**< 2      */
	uint8_t data_length;        /**< 1      */
    uint8_t uncompressed;       /**< 0      */
} tls_ec_point_formats_ce_t;

typedef struct tls_supported_groups_ce {
	uint16_t extension_id;      /**< 0x000a */
	uint16_t extension_length;  /**< 4      */
	uint16_t data_length;       /**< 2      */
    uint16_t ec_x25519;         /**< 0x001d */
} tls_supported_groups_ce_t;

typedef struct tls_signature_algo_ce {
	uint16_t extension_id;      /**< 0x000d */
	uint16_t extension_length;  /**< 4      */
	uint16_t data_length;       /**< 2      */
    uint16_t algorithms[NUMBER_SUPPORTED_SIGNATURE_ALGO];
} tls_signature_algo_ce_t;

typedef struct tls_key_share_ce {
	uint16_t extension_id;      /**< 0x0033 */
	uint16_t extension_length;  /**< 38     */
	uint16_t data_length;       /**< 36     */
    uint16_t x25519_type;       /**< 0x001d */
    uint16_t x25519_size;       /**< 32     */
    uint8_t x25519_pub_key[32]; /**< Variable */
} tls_key_share_ce_t;

typedef struct tls_empty_key_share_ce {
	uint16_t extension_id;      /**< 0x0033 */
	uint16_t extension_length;  /**< 2     */
	uint16_t data_length;       /**< 0     */
} tls_empty_key_share_ce_t;

typedef struct tls_alpn_ce {
	uint16_t extension_id;		/**< 0x0010	*/
	uint16_t extension_length;	/**< 11		*/
	uint16_t data_length;		/**< 9		*/
	uint8_t http_1_1_length;	/**< 8		*/
	char http_1_1_id[8];		/*< http/1.1 */
} tls_alpn_ce_t;

typedef struct tls_record_size_limit_ce {
	uint16_t extension_id;      /**< 0x001c */
	uint16_t extension_length;  /**< 2      */
	uint16_t record_size_limit;
} tls_record_size_limit_ce_t;

typedef struct tls_max_fragment_length_ce {
	uint16_t extension_id;      /**< 0x0001 */
	uint16_t extension_length;  /**< 1      */
	uint8_t max_fragment_length;
} tls_max_fragment_length_ce_t;

typedef struct tls_server_name_ce {
	uint16_t extension_id;      /**< 0x0000 */
	uint16_t extension_length;
    uint16_t entry_length;
    uint8_t dns_type;
    uint16_t hostname_length;
    uint8_t hostname[];         /**< Variable-length extension           */
} tls_server_name_ce_t;

typedef struct tls_psk_key_exchange_mode_ce {
	uint16_t extension_id;      /**< 0x002d */
	uint16_t extension_length;
	uint8_t psk_key_exchange_mode_length;
    uint8_t psk_key_exchange_mode_ke;  /**< TLS_PSK_MODE_KE only */
} tls_psk_key_exchange_mode_ce_t;

typedef struct tls_pre_shared_key_ce {
	uint16_t extension_id;      /**< 0x0029 */
	uint16_t extension_length;
	uint16_t identities_length;
	uint16_t identity_length;
	uint8_t identity[];		/**< Variable-length extension           */
	// uint32_t obfuscated_ticket_age;
	// uint16_t binders_length;
	// uint8_t binder_entry_length;
	// uint8_t binder_entry[];
} tls_pre_shared_key_ce_t;

typedef struct tls_pre_shared_key_end_ce {
	uint32_t obfuscated_ticket_age;
	uint16_t binders_length;
	uint8_t binder_entry_length;
	uint8_t binder_entry[];
} tls_pre_shared_key_end_ce_t;


/** 
 * Actual TLS handhsake structure, used in this lib according to the supported features
 */
 typedef struct tls_client_hello_header {
    uint8_t hs_type;
	uint24_t client_hello_length;
	uint16_t version;
	uint8_t random[32];
	uint8_t session_id_length;		/**< Session ID not used in TLS 1.3				*/
	uint8_t session_id[32];
	uint16_t cipher_suite_length;
    uint16_t cipher_suites[NUMBER_SUPPORTED_CIPHER_SUITES];
    uint8_t comp_methods_length;    /**< Always 1                                   */
    uint8_t null_compression;       /**< no compression methods in TLS 1.3			*/
	uint16_t extensions_length;
} tls_client_hello_header_t;

/**
 * Message sent in response to a certificate request: the calc does not have any certificate
 */
typedef struct tls_empty_certificate {
	tls_handshake_t header;
	uint8_t context_size;
	uint8_t context[];
	// uint24_t certificate_list_size;	/**< 0 here */
} tls_empty_certificate_t;


typedef struct tls_ticket_list {
	/** The following field is the IP of the server that sent the ticket.
	 *  In theory, the compared data should be the SNI, but for size and time optimization purposes, we keep the IP.
	 *  If the server IP changed => the ticket is useless and will be dropped once its lifetime is reached.
	 *  If the another server took this IP => the ticket is sent, the server will reject it and the ticket will be dropped
	 */
	uint32_t ip_server;
	uint32_t start_date;
	uint8_t psk_length;
	void *psk;
	struct tls_ticket_list *next;
	tls_session_ticket_t ticket;
	// only one cipher suite available, so no need to store these data
} tls_ticket_list_t;


/**
 * Internal functions prototype
 */

web_status_t deliver_tls_record(tls_exchange_t *tls_exch, void *data, size_t length_data, tls_content_type_t tls_type);

web_status_t _recursive_DeliverTLSRecord(tls_exchange_t *tls_exch, void *buffer, void *data, size_t length_data,
									  	 uint8_t opaque_type);

web_status_t send_alert(tls_exchange_t *tls_exch, tls_alert_t alert_desc);

void fill_client_hello_header(void **ptr, size_t client_hello_size);

void fill_supported_versions_ext(void **ptr);

void fill_ec_point_formats_ext(void **ptr);

void fill_supported_groups_ext(void **ptr);

void fill_signature_algorithms_ext(void **ptr);

void fill_key_share_ext(void **ptr, uint8_t client_private_key[]);

void fill_alpn_ext(void **ptr);

void fill_psk_key_exchange_mode_ext(void **ptr);

void fill_record_size_limit_ext(void **ptr);

void fill_max_fragment_length(void **ptr);

void fill_server_name_ext(void **ptr, const char *sni, size_t sni_length);

void fill_pre_shared_key_ext(void **ptr, const void *buffer, const uint8_t ticket[], uint8_t ticket_length, uint32_t obfuscated_age,
							 uint8_t binder_key[]);

web_status_t send_new_connection(tls_exchange_t *tls_exch, const char *sni, size_t sni_length);

tls_ticket_list_t *find_session_ticket(uint32_t ip);

web_status_t send_resumption_connection(tls_exchange_t *tls_exch, const char *sni, size_t sni_length, tls_ticket_list_t *ticket);

tls_alert_t fetch_handshake_extensions(const uint8_t extensions[], size_t length, const uint8_t **server_public_key);

tls_alert_t compute_cipher_data(tls_exchange_t *tls_exch);

tls_alert_t fetch_server_hello(tls_exchange_t *tls_exch, tls_hello_t *server_hello, size_t length);

tls_alert_t fetch_encrypted_extension(tls_exchange_t *tls_exch, const tls_encrypted_extensions_t *encrypted_ext, size_t length);

tls_alert_t fetch_server_finished(tls_exchange_t *tls_exch, tls_finished_t *server_finished, size_t length);

tls_alert_t fetch_new_session_ticket(tls_exchange_t *tls_exch, const tls_new_session_ticket_t *session_ticket, size_t length);

tls_alert_t fetch_key_update_request(tls_exchange_t *tls_exch, tls_key_update_t *key_upd_msg, size_t length);

tls_alert_t fetch_certificate_request(tls_exchange_t *tls_exch, const tls_cert_request_t *cert_request, size_t length);

tls_alert_t fetch_handshake_message(tls_exchange_t *tls_exch, tls_handshake_t *handshake_msg, size_t length);

void received_close_signal(tls_exchange_t *tls_exch);

tls_alert_t fetch_alert_record(tls_exchange_t *tls_exch, tls_alert_record_t *alert_record);

tls_alert_t fetch_tls_record(tls_exchange_t *tls_exch, void *payload, size_t length, tls_content_type_t content_type);

tls_alert_t fetch_tls_encrypted_record(tls_exchange_t *tls_exch, tls_record_t *record, size_t record_length);

web_status_t fetch_tls_part(web_port_t port, link_msg_type_t msg_type, void *data, size_t length,
							web_callback_data_t *user_data);

void free_session_tickets();

void unexpected_abort(tls_exchange_t *tls_exch, tls_alert_t reason);

void tls_close(tls_exchange_t *tls_exch, tls_alert_t reason, bool is_from_appli);


#endif // INTERNET_TLS
