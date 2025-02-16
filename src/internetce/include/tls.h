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

#define TLS_SUPPORTED_VERSIONS_EXT_ID	htons(0x002b)
#define TLS_EC_POINT_FORMATS_EXT_ID		htons(0x000b)
#define TLS_SUPPORTED_GROUPS_EXT_ID		htons(0x000a)
#define TLS_SIGNATURE_ALGO_EXT_ID		htons(0x000d)
#define TLS_KEY_SHARE_EXT_ID			htons(0x0033)
#define TLS_ALPN_EXT_ID					htons(0x0010)
#define TLS_SESSION_TICKET_EXT_ID		htons(0x0023)
#define TLS_EXTENDED_MSECRET_EXT_ID		htons(0x0017)
#define TLS_RECORD_SIZE_LIMIT_EXT_ID	htons(0x001c)
#define TLS_SERVER_NAME_EXT_ID			htons(0x0000)

#define TLS_SERVER_NAME_MAX_LENGTH		256

#define TOTAL_EXTENSIONS_SIZE (sizeof(tls_supported_versions_ce_t) + sizeof(tls_ec_point_formats_ce_t) + \
							   sizeof(tls_supported_groups_ce_t) + sizeof(tls_signature_algo_ce_t) + \
							   sizeof(tls_key_share_ce_t) + sizeof(tls_alpn_ce_t) + sizeof(tls_session_ticket_ce_t) + \
							   sizeof(tls_extended_msecret_ce_t) + sizeof(tls_record_size_limit_ce_t) + \
							   sizeof(tls_server_name_ce_t))


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

typedef struct tls_alpn_ce {
	uint16_t extension_id;		/**< 0x0010	*/
	uint16_t extension_length;	/**< 11		*/
	uint16_t data_length;		/**< 9		*/
	uint8_t http_1_1_length;	/**< 8		*/
	uint8_t http_1_1_id[8];		/*< http/1.1 */
} tls_alpn_ce_t;

typedef struct tls_session_ticket_ce {
	uint16_t extension_id;      /**< 0x0023 */
	uint16_t extension_length;  /**< 0      */
} tls_session_ticket_ce_t;

typedef struct tls_extended_msecret_ce {
	uint16_t extension_id;      /**< 0x0017 */
	uint16_t extension_length;  /**< 0      */
} tls_extended_msecret_ce_t;

typedef struct tls_record_size_limit_ce {
	uint16_t extension_id;      /**< 0x001c */
	uint16_t extension_length;  /**< 2      */
	uint16_t record_size_limit;	/**< 4096	*/
} tls_record_size_limit_ce_t;

typedef struct tls_server_name_ce {
	uint16_t extension_id;      /**< 0x0000 */
	uint16_t extension_length;
    uint16_t entry_length;
    uint8_t dns_type;
    uint16_t hostname_length;
    uint8_t hostname[];
} tls_server_name_ce_t;

// Actual TLS handhsake structure, used in this lib according to the supported features
typedef struct tls_handshake_ce {
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
    tls_supported_versions_ce_t sup_versions_ext;
    tls_ec_point_formats_ce_t ec_point_ext;
    tls_supported_groups_ce_t sup_groups_ext;
    tls_signature_algo_ce_t sup_sign_algo_ext;
    tls_key_share_ce_t key_share_ext;
	tls_alpn_ce_t alpn_ext;
    tls_session_ticket_ce_t session_ticket_ext;
    tls_extended_msecret_ce_t ext_msecret_ext;
	tls_record_size_limit_ce_t record_size_limit_ext;
    tls_server_name_ce_t server_name_ext;   /**< Variable-length extension           */
} tls_handshake_ce_t;


/**
 * Internal functions prototype
 */

web_status_t _recursive_DeliverTLSRecord(tls_exchange_t *tls_exch, void *buffer, void *data, size_t length_data,
									  	 uint8_t opaque_type);

web_status_t fetch_handshake_extensions(const uint8_t extensions[], size_t length, const uint8_t **server_public_key);

web_status_t compute_cipher_data(tls_exchange_t *tls_exch);

web_status_t fetch_server_hello(tls_exchange_t *tls_exch, tls_handshake_t *server_hello, size_t length);

web_status_t fetch_server_finished(tls_exchange_t *tls_exch, tls_finished_t *server_finished, size_t length);

web_status_t fetch_handshake_message(tls_exchange_t *tls_exch, tls_handshake_t *handshake_msg, size_t length);

web_status_t fetch_tls_record(tls_exchange_t *tls_exch, void *payload, size_t length, tls_content_type_t content_type);

web_status_t fetch_tls_encrypted_record(tls_exchange_t *tls_exch, tls_record_t *record, size_t record_length);

web_status_t fetch_tls_part(web_port_t port, link_msg_type_t msg_type, void *data, size_t length,
						    web_callback_data_t *user_data);

void _free_tls_connection(tls_exchange_t *tls_exch);


#endif // INTERNET_TLS
