/**
 * @file
 * @author Epharius
 * @dependancie usbdrvce
 * @brief Software NIC for Ti-84+CE and Ti-83 Premium CE
 *
 * This is a high-level library for interfacing with the internet.
 * To make it work, plug the calculator to a RNDIS device (basically your phone)
 * and enable the USB internet connection sharing.
 * The minimal program using this lib can be :
 * @code
 *	int main(void) {
 *		web_Init();
 *		while(!web_Connected())
 *			web_WaitForEvents();
 *		// Do whatever you want
 *		web_Cleanup();
 *		return 0;
 *	}
 * @endcode
 * Some examples of use are available in the tests/ folder.
 * This library may contain bugs. If you encounter one, please contact
 * me on www.tiplanet.org or www.cemetech.net (Epharius).
 */


#ifndef INTERNET
#define INTERNET

#include <stdbool.h>
#include <tice.h>
#include <usbdrvce.h>


/**
 * @enum web_status_t
 * A description of all the HTTP codes is available here :
 * https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
 */
typedef enum web_status {
	WEB_SUCCESS = 0,
	WEB_IGNORE = USB_IGNORE,						/**< In addition to the http status codes.	*/
	WEB_USB_ERROR,									/**< Error coming from the USB lib */
	WEB_NO_DATA,									/**< No data from the host */
	WEB_NOT_ENOUGH_MEM = USB_ERROR_NO_MEMORY,		/**< Not enough memory to store the data, or the data is more than 65Ko. */
	WEB_TIMEOUT = USB_ERROR_TIMEOUT,				/**< The transfer expired.				*/
	WEB_DNS_ERROR,									/**< An error occurred in the DNS reply.	*/
	WEB_NOT_SUPPORTED,								/**< Not yet supported */
	WEB_ERROR_FAILED,								/**< General error (a packet couldn't be sent, etc) */
	WEB_CONNECTION_TERMINATION_ERROR,				/**< Eg. an RST segment has been received */
	WEB_NOT_ENOUGH_ENTROPY,							/**< Not enought entropy */
	WEB_INVALID_ARGUMENTS,							/**< When a method has been given invalid arguments */
	WEB_SHA256_NOT_INITIALIZED,
	WEB_SHA256_IN_USE,
	HTTP_STATUS_OK = 200,
	HTTP_STATUS_MOVED_PERMANENTLY = 301,
	HTTP_STATUS_NOT_MODIFIED = 304,
	HTTP_STATUS_BAD_REQUEST = 400,
	HTTP_STATUS_UNAUTHORIZED = 401,
	HTTP_STATUS_FORBIDDEN = 403,
	HTTP_STATUS_NOT_FOUND = 404,
	HTTP_STATUS_NOT_ACCEPTABLE = 406,
	HTTP_STATUS_LENGTH_REQUIRED = 411,
	HTTP_STATUS_PAYLOAD_TOO_LARGE = 413,
	HTTP_STATUS_TOO_MANY_REQUEST = 429,
	HTTP_STATUS_INTERNAL_SERVER_ERROR = 500,
	HTTP_STATUS_BAD_GATEWAY = 502,
	HTTP_STATUS_SERVICE_UNAVAILABLE = 503
} web_status_t;

typedef enum scheduler_status {
	SCHEDULER_AGAIN,
	SCHEDULER_DESTROY,
} scheduler_status_t;

/**
 * DHCP communication states.
 */
typedef enum dhcp_state {
	DHCP_STATE_INIT,
	DHCP_STATE_SELECTING,
	DHCP_STATE_BIND,
	DHCP_STATE_RENEWING
} dhcp_state_t;

/**
 * TCP connection states for a client.
 * See https://users.cs.northwestern.edu/~agupta/cs340/project2/TCPIP_State_Transition_Diagram.pdf
 */
typedef enum tcp_state {
	TCP_STATE_LISTEN,
	TCP_STATE_SYN_RCVD,
	TCP_STATE_SYN_SENT,
	TCP_STATE_ESTABLISHED,
	TCP_STATE_FIN_WAIT_1,
	TCP_STATE_FIN_WAIT_2,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_CLOSING,
	TCP_STATE_LAST_ACK,
	TCP_STATE_TIME_WAIT,
	TCP_STATE_CLOSED
} tcp_state_t;

/**
 * State of the connection, sent to the application layer callback.
 * 	- LINK_MSG_TYPE_DATA: Data received, data and length are non-null
 * 	- LINK_MSG_TYPE_RST: The connection has been reset, data and length are invalid
 * 	- LINK_MSG_TYPE_FIN: The connection has been closed by the other side, data and length are invalid
 * When LINK_MSG_TYPE_RST and LINK_MSG_TYPE_FIN are received, the callback will never be called again.
 * The user must then call the close method of the underlying layer (web_TCPClose, web_TLSClose, etc) to free the resources
 * 	(even in the LINK_MSG_TYPE_RST case).
 */
typedef enum link_msg_type {
	LINK_MSG_TYPE_DATA,
	LINK_MSG_TYPE_RST,
	LINK_MSG_TYPE_FIN
} link_msg_type_t;

/**
 * TLS enums
 */

typedef enum tls_content_type {
	TLS_INVALID_TYPE		= 0,
	TLS_CHANGE_CIPHER_SPEC	= 20,
	TLS_ALERT_TYPE			= 21,
	TLS_HANDSHAKE_TYPE		= 22,
	TLS_APPLI_DATA_TYPE		= 23
} tls_content_type_t;

typedef enum tls_state {
	TLS_STATE_WAIT_SERVER_HELLO,
	TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS,
	TLS_STATE_WAIT_CERT_CR,  		/**< either wait for a certificate or a certificate request (but does not supporting cert_req for now) */
	TLS_STATE_WAIT_CERTIFICATE,  	/**< N/A as not supporting cert_req */
	TLS_STATE_WAIT_CERTIFICATE_VERIFY,
	TLS_STATE_WAIT_FINISHED,
	TLS_STATE_CONNECTED,
	TLS_STATE_CLOSE_NOTIFY_SENT,
	TLS_STATE_CLOSE_NOTIFY_RECEIVED,
	TLS_STATE_CLOSED,
} tls_state_t;

typedef enum tls_hs_msg_type {
	TLS_HS_TYPE_CLIENT_HELLO			= 1,
	TLS_HS_TYPE_SERVER_HELLO			= 2,
	TLS_HS_TYPE_NEW_SESSION_TICKET		= 4,
	TLS_HS_TYPE_END_OF_EARLY_DATA		= 5,
	TLS_HS_TYPE_ENCRYPTED_EXTENSIONS	= 8,
	TLS_HS_TYPE_CERTIFICATE				= 11,
	TLS_HS_TYPE_CERTIFICATE_REQUEST		= 13,
	TLS_HS_TYPE_CERTIFICATE_VERIFY		= 15,
	TLS_HS_TYPE_FINISHED				= 20,
	TLS_HS_TYPE_KEY_UPDATE				= 24,
	TLS_HS_TYPE_MESSAGE_HASH			= 254
} tls_hs_msg_type_t;

typedef enum tls_sender {
	TLS_SENDER_SERVER					= 0 << 7,
	TLS_SENDER_CLIENT					= 1 << 7,
} tls_sender_t;

#define TO_HS_SENDER_TYPE(msg, sender) ((msg << 1) | sender)

/**
 * List only the messages that can be in the transcript hash (ie that can be received during the TLS handshake)
 * Note: Because TLS chose not to be logical, messages are not in ascendant order (cert. request > server cert. verify)
 * 		 But this is 'ok' because the transcript hash is not computed around those edge cases
 */
typedef enum tls_hs_sender_msg_type {
	TLS_HS_CLIENT_CLIENT_HELLO			= TO_HS_SENDER_TYPE(TLS_HS_TYPE_CLIENT_HELLO, 			0),
	TLS_HS_SERVER_SERVER_HELLO			= TO_HS_SENDER_TYPE(TLS_HS_TYPE_SERVER_HELLO, 			0),
	TLS_HS_SERVER_ENCRYPTED_EXTENSIONS	= TO_HS_SENDER_TYPE(TLS_HS_TYPE_ENCRYPTED_EXTENSIONS, 	TLS_SENDER_SERVER),
	TLS_HS_SERVER_CERTIFICATE_REQUEST	= TO_HS_SENDER_TYPE(TLS_HS_TYPE_CERTIFICATE_REQUEST, 	TLS_SENDER_SERVER),
	TLS_HS_SERVER_CERTIFICATE			= TO_HS_SENDER_TYPE(TLS_HS_TYPE_CERTIFICATE, 			TLS_SENDER_SERVER),
	TLS_HS_SERVER_CERTIFICATE_VERIFY	= TO_HS_SENDER_TYPE(TLS_HS_TYPE_CERTIFICATE_VERIFY, 	TLS_SENDER_SERVER),
	TLS_HS_SERVER_FINISHED				= TO_HS_SENDER_TYPE(TLS_HS_TYPE_FINISHED, 				TLS_SENDER_SERVER),
	TLS_HS_CLIENT_END_OF_EARLY_DATA		= TO_HS_SENDER_TYPE(TLS_HS_TYPE_END_OF_EARLY_DATA, 		TLS_SENDER_CLIENT),
	TLS_HS_CLIENT_CERTIFICATE			= TO_HS_SENDER_TYPE(TLS_HS_TYPE_CERTIFICATE, 			TLS_SENDER_CLIENT),
	TLS_HS_CLIENT_CERTIFICATE_VERIFY	= TO_HS_SENDER_TYPE(TLS_HS_TYPE_CERTIFICATE_VERIFY, 	TLS_SENDER_CLIENT),
	TLS_HS_CLIENT_FINISHED				= TO_HS_SENDER_TYPE(TLS_HS_TYPE_FINISHED, 				TLS_SENDER_CLIENT),
} tls_hs_sender_msg_type_t;

typedef enum key_update_request_type {
	TLS_KEY_UPDATE_NOT_REQUESTED = 0,
	TLS_KEY_UPDATE_REQUESTED = 1,
} key_update_request_type_t;


/**
 * A pointer to web_callback_data_t is passed in the different
 * callbacks such as web_port_callback_t.
 * The default is void* but is can be changed by defining it yourself.
 */
#ifndef web_callback_data_t
#define web_callback_data_t void
#endif

/**
 * typedef usb_error_t (*usb_transfer_callback_t)(usb_endpoint_t endpoint,
 *                                              usb_transfer_status_t status,
 *                                              size_t transferred,
 *                                              usb_transfer_data_t *data);
 * See usbdrvce for more information.
 */
#define web_transfer_callback_t usb_transfer_callback_t

/**
 * Type used to define TCP/UDP ports.
 * A port is basically a 16bits number
 */
#define web_port_t uint16_t

/**
 * Result of HTTPGet and HTTPPost calls.
 * See tice.h for more information.
 */
#define http_data_t	var_t

/**
 * The callback used to notice a port that a message has been received.
 */
typedef web_status_t (web_port_callback_t)(web_port_t port, uint8_t protocol, void *data, size_t length,
										   web_callback_data_t *user_data);

/**
 * The callback used to notice a port that a TCP segment has been received.
 */
typedef web_status_t (web_appli_callback_t)(web_port_t port, link_msg_type_t msg_type, void *data, size_t length,
										  web_callback_data_t *user_data);

/**
 * The callback used to notice the user a DNS reply has been received.
 * If res_ip == 0xffffffff, then the request failed.
 */
typedef web_status_t (web_dns_callback_t)(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data);

/**
 * The callback called for a schedule event
 */
typedef scheduler_status_t (web_schedule_callback_t)(web_callback_data_t *user_data);

/**
 * The callback used to inform the user that the object (event, ...) will be destroyed
 */
typedef void (web_destructor_callback_t)(web_callback_data_t *user_data);

/**
 * Callback called by the TLS implementation when it needs to initialize the ciphering module
 */
typedef web_callback_data_t *(web_cipher_init_callback_t)(uint8_t cipher_key[], uint8_t cipher_iv[],
														  uint8_t decipher_key[], uint8_t decipher_iv[]);

/**
 * Callback called by the TLS implementation when it needs to free the ciphering module data
 */
typedef void (web_cipher_free_callback_t)(web_callback_data_t *user_data);

/**
 * Callback called by the TLS implementation when it needs to cipher data
 */
typedef web_status_t (web_cipher_cipher_callback_t)(void *dest, void *source, size_t length, void *aad, size_t aad_length,
													web_callback_data_t *user_data);

/**
 * Callback called by the TLS implementation when it needs to decipher data
 */
typedef web_status_t (web_cipher_decipher_callback_t)(void *dest, void *source, size_t length, void *aad, size_t aad_length,
													  web_callback_data_t *user_data);


/**
 * The next structs are descriptions of web protocol headers such as IP or HTTP.  
 */

/**
 * RNDIS messages
 */

typedef struct rndis_ctrl_msg {
	uint32_t MessageType;
	uint32_t MessageLength;
	uint32_t RequestId;
	uint8_t data[0];
} rndis_ctrl_msg_t;

typedef struct rndis_ctrl_cmplt {
	uint32_t MessageType;
	uint32_t MessageLength;
	uint32_t RequestId;
	uint32_t Status;
	uint8_t data[0];
} rndis_ctrl_cmplt_t;

typedef struct rndis_init_msg {
	uint32_t MessageType;		/**< RNDIS_INIT_MSG									*/
	uint32_t MessageLength;		/**< 24												*/
	uint32_t RequestId;
	uint32_t MajorVersion;
	uint32_t MinorVersion;
	uint32_t MaxTransferSize;
} rndis_init_msg_t;

typedef struct rndis_init_cmplt {
	uint32_t MessageType;		/**< RNDIS_INIT_CMPLT								*/
	uint32_t MessageLength;		/**< 52												*/
	uint32_t RequestId;
	uint32_t Status;
	uint32_t MajorVersion;
	uint32_t MinorVersion;
	uint32_t DeviceFlags;		/*<  */
	uint32_t Medium;
	uint32_t MaxPacketsPerTransfer;
	uint32_t MaxTransferSize;
	uint32_t PacketAlignmentFactor;
	uint32_t Reserved[2];
} rndis_init_cmplt_t;

typedef rndis_ctrl_msg_t rndis_halt_msg_t;

typedef struct rndis_set_msg {
	uint32_t MessageType;		/**< RNDIS_INIT_MSG									*/
	uint32_t MessageLength;		/**< 32												*/
	uint32_t RequestId;
	uint32_t Oid;
	uint32_t InformationBufferLength;
	uint32_t InformationBufferOffset;
	uint32_t DeviceVcHandle;	/**< 0												*/
	uint8_t OidValue[0];		/**< Oid value sent along with the message			*/
} rndis_set_msg_t;

typedef struct rndis_reset_msg {
	uint32_t MessageType;		/**< RNDIS_RESET_MSG								*/
	uint32_t MessageLength;		/**< 12												*/
	uint32_t Reserved;
} rndis_reset_msg_t;

typedef struct rndis_reset_cmplt {
	uint32_t MessageType;		/**< RNDIS_RESET_CMPLT								*/
	uint32_t MessageLength;		/**< 16												*/
	uint32_t Status;
	uint32_t AddressingReset;	/*< Set to 1 if the host needs to resend filter		*/
} rndis_reset_cmplt_t;

typedef struct rndis_keepalive_msg {
	uint32_t MessageType;
	uint32_t MessageLength;
	uint32_t RequestId;
} rndis_keepalive_msg_t;

typedef struct rndis_keepalive_cmplt {
	uint32_t MessageType;
	uint32_t MessageLength;
	uint32_t RequestId;
	uint32_t Status;
} rndis_keepalive_cmplt_t;

typedef struct rndis_packet_msg {
	uint32_t MessageType;		/**< RNDIS_PACKET_MSG								*/
	uint32_t MessageLength;
	uint32_t DataOffset;
	uint32_t DataLength;
	uint32_t OOBDataOffset;
	uint32_t OOBDataLength;
	uint32_t NumOOBDataElements;
	uint32_t PerPacketInfoOffset;
	uint32_t PerPacketInfoLength;
	uint32_t VcHandle;			/**< Must be 0										*/
	uint32_t Reserved;			/**< Must be 0										*/
	uint8_t data[];
} rndis_packet_msg_t;


/**
 * Network packets
 */

typedef struct eth_frame {
	uint8_t MAC_dst[6];
	uint8_t MAC_src[6];		/**< MAC_ADDR											*/
	uint16_t Ethertype;		/**< 0x0800 : IPv4										*/
	/* Your data must be here /void data;/ */
	// uint32_t crc;
} eth_frame_t;

typedef struct arp_message {
	uint16_t HwType;		/**< Ethernet 10Mb = 0x01								*/
	uint16_t ProtocolType;	/**< IP = 0x0800										*/
	uint8_t HwAddrLength;	/**< Ethernet = 0x06									*/
	uint8_t ProtocolAddrLength; /**< IP=0x04										*/
	uint16_t Operation;		/**< Request=0x01, Reply=0x02							*/
	uint8_t MAC_src[6];
	uint32_t IP_src;
	uint8_t MAC_dst[6];
	uint32_t IP_dst;
} arp_message_t;

typedef struct ipv4_packet {
	uint8_t VerIHL;			/**< often 0x45											*/
	uint8_t ToS;
	uint16_t TotalLength;	/**< less than 65K but MTU is often 576B (minimal required value) */
	uint16_t Id;			/**< Identification of the fragment						*/
	uint16_t FlagsFragmentOffset; /**< The first 3 bits are flags. The following bits are the Fragment Offset */
	uint8_t TTL;			/**< Time To Live										*/
	uint8_t Protocol;		/**< TCP=0x06; UDP=0x11; ICMP=0x01						*/
	uint16_t HeaderChecksum;/**< Checksum of this header							*/
	uint32_t IP_addr_src;
	uint32_t IP_addr_dst;
} ipv4_packet_t;

typedef struct icmpv4_echo {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t seq_number;
} icmpv4_echo_t;

typedef struct udp_datagram {
	web_port_t port_src;
	web_port_t port_dst;
	uint16_t length;
	uint16_t checksum;
} udp_datagram_t;

typedef struct dhcp_message {
	uint8_t op; 			/**< 0x01 for us, 0x02 for the dhcp server				*/
	uint8_t htype;			/**< 0x01												*/
	uint8_t hlen;			/**< 0x06												*/
	uint8_t hops;			/**< 0x00												*/
	uint32_t xid;			/**< Transaction ID										*/
	uint16_t secs;	
	uint16_t flags;	
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];		/**< For MAC addrs, only the 6 first bytes are used		*/
	uint8_t zeros[192];		/**< 0x00												*/
	uint32_t magicCookie;	/**< 0x63825363											*/
	uint8_t options[];		/**< Must be 0xFF terminated							*/
} dhcp_message_t;

typedef struct dns_message {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;		/**< Numbers of questions in the message.				*/
	uint16_t answerRRs;		/**< Numbers of answers in the message.					*/
	uint16_t authorityRRs;	/**< Numbers of authority answers in the message.		*/
	uint16_t additionalRRs;	/**< Numbers of additionnal records in the message.		*/
	// queries
	// answers
	// authority
	// additional
} dns_message_t;

typedef struct tcp_segment {
	web_port_t port_src;
	web_port_t port_dst;
	uint32_t seq_number;
	uint32_t ack_number;
	uint16_t dataOffset_flags;
	uint16_t windowSize;
	uint16_t checksum;
	uint16_t urgentPointer;
	uint8_t options[];
} tcp_segment_t;

typedef struct tls_record {
	uint8_t opaque_type;
	uint16_t legacy_version;
	uint16_t length;
	uint8_t data[];
} tls_record_t;

typedef struct tls_extension {
	uint16_t extension_id;
	uint16_t extension_length;
	uint8_t data[];
} tls_extension_t;

typedef struct tls_handshake {
	uint8_t hs_type;
	uint24_t length;
} tls_handshake_t;

typedef struct tls_hello {
	tls_handshake_t header;
	uint16_t version;
	uint8_t random[32];
	uint8_t zero;			/**< Session ID not used in TLS 1.3						*/
	// uint8_t cipher_suites[];
	// uint8_t compression_methods_size;
	// uint8_t zero			/**< no compression methods in TLS 1.3					*/
	// uint8_t extensions[];
} tls_hello_t;

typedef struct tls_finished {
	tls_handshake_t header;
	uint8_t hash[];
} tls_finished_t;

typedef struct tls_alert_record {
	uint8_t alert_level;
	uint8_t alert_description;
} tls_alert_record_t;

typedef struct tls_key_update {
	tls_handshake_t header;
	uint8_t key_update_request;
} tls_key_update_t;

typedef struct tls_encrypted_extensions {
	tls_handshake_t header;
	uint16_t extensions_size;
	uint8_t extensions[];
} tls_encrypted_extensions_t;



typedef struct tls_cert_request {
	tls_handshake_t header;
	uint8_t context_size;
	uint8_t context[];
	// uint16_t extensions_size;
	// uint8_t extensions[];
} tls_cert_request_t;

typedef struct tls_session_ticket {
	uint32_t lifetime;
	uint32_t age_add;
	uint8_t nonce_length;
	uint8_t nonce[];
	// uint16_t ticket_length;
	// uint8_t ticket[];
	// uint16_t extensions_length;
	// uint8_t extensions[];
} tls_session_ticket_t;

typedef struct tls_new_session_ticket {
	tls_handshake_t header;
	tls_session_ticket_t ticket;
} tls_new_session_ticket_t;

typedef struct network_pseudo_hdr {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t length;
} network_pseudo_hdr_t;


/**
 * The next structs are specific to this library.
 * They are not aim at being used outside.
 */

typedef struct tcp_segment_list {
	uint32_t relative_sn;
	size_t pl_length;		/**< Length of the payload of the segment				*/
	uint16_t flags;			/**< Flags of the segment								*/
	void *payload;			/**< The payload										*/
	struct tcp_segment_list *next;
} tcp_segment_list_t;

typedef struct msg_queue {
	size_t length;
	uint8_t *msg;
	usb_endpoint_t endpoint;
	bool send_once;
} msg_queue_t;

typedef struct pushed_seg_list {
	uint32_t next_rsn;					/**< Sequence number of the last byte of the segment+1	*/
	uint16_t flags;						/**< Flags of the segment								*/
	msg_queue_t *seg;
	struct pushed_seg_list *next;
} pushed_seg_list_t;

typedef struct dns_exchange {
	web_port_t port_src;
	web_dns_callback_t *callback;
	web_callback_data_t *user_data;
	msg_queue_t *queued_request;
} dns_exchange_t;

typedef struct tcp_exchange {
	uint32_t ip_dst;
	web_port_t port_src;
	web_port_t port_dst;
	tcp_state_t tcp_state;
	uint32_t beg_sn;
	uint32_t cur_sn;					/**< Current client's sequence number (SN of the next-sent segment)	*/
	uint32_t beg_ackn;					/**< First server's sequence number, set just after SYN ACK			*/
	uint32_t cur_ackn;					/**< Current server's sequence number (our ack number)				*/
	tcp_segment_list_t *in_segments;	/**< Received data that has not been sent to the application yet	*/
	pushed_seg_list_t *out_segments;	/**< The segments pushed on the send queue that are waiting for an ack */
	web_appli_callback_t *callback;		/**< Callback when a packet is addressed to port_src				*/
	web_callback_data_t *user_data;		/**< In our case, an http_exchange_t structure						*/
	size_t send_mss;					/**< Maximum Segment Size for the distant host						*/
} tcp_exchange_t;

typedef struct tcp_exchange_list {
	tcp_exchange_t tcp_exch;
	struct tcp_exchange_list *next;
} tcp_exchange_list_t;

typedef struct linked_transcript_msg {
	size_t length;
	tls_hs_sender_msg_type_t msg_type;
    void *data;
    struct linked_transcript_msg *next;
} linked_transcript_msg_t;

typedef struct cipher_callbacks {
	web_cipher_init_callback_t *init;
	web_cipher_free_callback_t *free;
	web_cipher_cipher_callback_t *cipher;
	web_cipher_decipher_callback_t *decipher;
	uint8_t extra_size;					/**< Size added to the plaintext to make the ciphertext (AEAD, etc)	*/
	uint8_t key_size;
	uint8_t iv_size;
} cipher_callbacks_t;

typedef struct tls_exchange {
	tls_state_t tls_state;
	size_t received_length;
	tls_record_t *record;				/**< Where to put the result: must be record_length long			*/
	tcp_exchange_t *tcp_exch;
	linked_transcript_msg_t *transcript;/**< Used by the key_schedule module								*/
	uint8_t *current_secret;			/**< The current derived secret from the key schedule				*/
	uint8_t *client_private_key;		/**< The private key of the client									*/
	uint8_t *current_server_traffic_secret;	/**< The current server traffic secret							*/
	uint8_t *current_client_traffic_secret;	/**< The current client traffic secret							*/
	uint8_t *res_master_secret;			/**< The resumption master secret derived from the key schedule		*/	
	cipher_callbacks_t *cipher_callbacks;
	web_callback_data_t *cipher_data;
	web_appli_callback_t *appli_callback;	/**< Callback when a packet is addressed to this connection		*/
	web_callback_data_t *appli_data;	/**< The opaque data provided to web_TLSConnect						*/
} tls_exchange_t;


/**
 * Noticeable constants.
 */

#define WIRELESS_RNDIS_SUBCLASS		0x01
#define WIRELESS_RNDIS_PROTOCOL		0x03
#define MISC_RNDIS_SUBCLASS	0x04
#define MISC_RNDIS_PROTOCOL	0x01

#define CMPLT_TYPE			0x80000000
#define RNDIS_PACKET_MSG 	0x00000001
#define RNDIS_INIT_MSG		0x00000002
#define RNDIS_INIT_CMPLT	0x80000002
#define RNDIS_HALT_MSG		0x00000003
#define RNDIS_QUERY_MSG		0x00000004
#define RNDIS_QUERY_CMPLT	0x80000004
#define RNDIS_SET_MSG		0x00000005
#define RNDIS_SET_CMPLT		0x80000005
#define RNDIS_RESET_MSG		0x00000006
#define RNDIS_RESET_CMPLT	0x80000006
#define RNDIS_INDICATE_MSG	0x00000007
#define RNDIS_KEEPALIVE_MSG	0x00000008
#define RNDIS_KEEPALIVE_CMPLT	0x80000008

#define RNDIS_STATUS_SUCCESS        0x00000000
#define RNDIS_STATUS_FAILURE        0xC0000001
#define RNDIS_STATUS_INVALID_DATA   0xC0010015
#define RNDIS_STATUS_NOT_SUPPORTED  0xC00000BB
#define RNDIS_STATUS_MEDIA_CONNECT  0x4001000B
#define RNDIS_STATUS_MEDIA_DISCONNECT   0x4001000C

#define SEND_EVERY			(2 * 1000)	/**< Hardcoded value but in theory this should be calculated		*/
#define TIMEOUT_NET			10			/**< Timeout for general networking requests (TCP/DNS...)			*/
#define TIMEOUT_HTTP		30			/**< Maximum time of a web request									*/
#define TIMEOUT_TIME_WAIT	30			/**< Timeout after what the connextion is freed in TIME_WAIT state	*/

#define ETH_IPV4			0x0008		/**< big endian stored												*/
#define ETH_ARP				0x0608		/**< big endian stored												*/

#define ICMP_PROTOCOL		0x01
#define TCP_PROTOCOL		0x06
#define UDP_PROTOCOL		0x11

#define ICMP_ECHO_REPLY		0
#define ICMP_ECHO_REQUEST	8			/**< ping															*/

#define SERVER_DHCP_PORT	67
#define CLIENT_DHCP_PORT	68
#define DNS_PORT			53
#define HTTP_PORT			80
#define HTTPS_PORT			443

#define MAX_SEGMENT_SIZE	1460
#define DEFAULT_MSS			536			/**< Default Maximum Segment Size									*/
#define TCP_WINDOW_SIZE		MAX_SEGMENT_SIZE * 5  /**< Considering the calculator is pretty slow			*/

#define ETH_HEADERS_SIZE	(sizeof(rndis_packet_msg_t) + (sizeof(eth_frame_t) + 4))
#define IPV4_HEADERS_SIZE	(ETH_HEADERS_SIZE + sizeof(ipv4_packet_t))
#define ICMP_HEADERS_SIZE	(IPV4_HEADERS_SIZE + sizeof(icmpv4_echo_t))
#define TCP_HEADERS_SIZE	(IPV4_HEADERS_SIZE + sizeof(tcp_segment_t))
#define UDP_HEADERS_SIZE	(IPV4_HEADERS_SIZE + sizeof(udp_datagram_t))
#define TLS_HEADERS_SIZE	(TCP_HEADERS_SIZE + sizeof(tls_record_t))
#define MIN_ETH_HDR_SIZE	64

#define FLAG_TCP_NONE		0
#define FLAG_TCP_FIN		1 << 0
#define FLAG_TCP_SYN		1 << 1
#define FLAG_TCP_RST		1 << 2
#define FLAG_TCP_PSH		1 << 3
#define FLAG_TCP_ACK		1 << 4
#define FLAG_TCP_URG		1 << 5
#define FLAG_TCP_MASK		(FLAG_TCP_FIN|FLAG_TCP_SYN|FLAG_TCP_RST|FLAG_TCP_PSH|FLAG_TCP_ACK|FLAG_TCP_URG)


/**
 * Public functions
 */

/**
 *	@brief	Initialize the library.
 *	@note	The end user must call this function and wait until web_Connected()
 *	returns true before using other functions of this library.
 */
void web_Init();

/**
 *	@brief	Cleans up the memory and the USB port.
 *	@note 	This function must be called before the program finishes.
 */
void web_Cleanup();

/**
 *	@brief	Performs an HTTP GET request to \c url and stores the address of the data in
 *	\c *data. Waits until the transfer finishes.
 *	@param	url	The target URL.
 *	@param	data This function will update *data to be the address where the downloaded data is.
 *	@param	keep_http_header If true, *data begins with the HTTP header.
 *	@returns The HTTP status code of the request or an error. See \c web_status_t
 *			 for more information.
 *	@warning The content returned by this function in data is in READ-ONLY !
 *			 Please use \c unlock_data() to write on \c data.
 */
web_status_t web_HTTPGet(const char* url, http_data_t **data, bool keep_http_header);

/**
 *	@brief	Performs an HTTPS (secured HTTP) GET request to \c url and stores the address
 *	of the data in \c *data. Waits until the transfer finishes.
 *	@param	url	The target URL.
 *	@param	data This function will update *data to be the address where the downloaded data is.
 *	@param	keep_http_header If true, *data begins with the HTTP header.
 *	@returns The HTTP status code of the request or an error. See \c web_status_t
 *			 for more information.
 *	@warning The content returned by this function in data is in READ-ONLY !
 *			 Please use \c unlock_data() to write on \c data.
 *	@note	 This is the secured version of web_HTTPGet, using TLS.
 *			 Be aware that it will take much more time than web_HTTPGet.
 *	@warning THIS IS NOT A "PROFESSIONAL" IMPLEMENTATION OF TLS. DO NOT SEND SENSITIVE DATA THROUGH IT!
 */
web_status_t web_HTTPSGet(const char* url, http_data_t **data, bool keep_http_header);

/**
 *	@brief	Performs an HTTP POST request to \c url and stores the address of the data in \c *data.
 *			Waits until the transfer finishes.
 *	@param	url	The target URL.
 *	@param	data When successful, \c *data is the address of the received HTTP content.
 *	@param	keep_http_header If true, *data begins with the HTTP header.
 *	@param	nb_params Number of additionnal parameters of the POST request.
 *	@params ... Additionnal parameters. Must be of const char* type.
 *	@example HTTPPost("www.google.com", &data, true, 2, "Age", "21", "Name", "Epharius");
 *	@returns The HTTP status code of the request or an error. See \c web_status_t for more information.
 *	@warning The content returned by this function in data is in READ-ONLY !
 *			 Please use \c unlock_data() to write on \c data.
 */
web_status_t web_HTTPPost(const char* url, http_data_t **data, bool keep_http_header, int nb_params, ...);

/**
 *	@brief	Performs an HTTPS (secured HTTP) POST request to \c url and stores the address
 *			of the data in \c *data. Waits until the transfer finishes.
 *	@param	url	The target URL.
 *	@param	data When successful, \c *data is the address of the received HTTP content.
 *	@param	keep_http_header If true, *data begins with the HTTP header.
 *	@param	nb_params Number of additionnal parameters of the POST request.
 *	@params ... Additionnal parameters. Must be of const char* type.
 *	@example HTTPPost("www.google.com", &data, true, 2, "Age", "21", "Name", "Epharius");
 *	@returns The HTTP status code of the request or an error. See \c web_status_t for more information.
 *	@warning The content returned by this function in data is in READ-ONLY !
 *			 Please use \c unlock_data() to write on \c data.
 *	@note	 This is the secured version of web_HTTPPost, using TLS.
 *			 Be aware that it will take much more time than web_HTTPPost.
 *	@warning THIS IS NOT A "PROFESSIONAL" IMPLEMENTATION OF TLS. DO NOT SEND SENSITIVE DATA THROUGH IT!
 */
web_status_t web_HTTPSPost(const char* url, http_data_t **data, bool keep_http_header, int nb_params, ...);

/**
 *	@brief	Unlocks the data so it can be modified.
 *	@warning This operation must be done only if necessary.
 *	@param	http_data The same structure as you passed to web_HTTPPost or web_HTTPGet.
 *	@returns 1 if the data is now unlocked, 0 if not.
 */
int web_UnlockData(http_data_t **http_data);

/**
 *	@brief	Locks the data so it can't be modified anymore.
 *	@warning This operation is a little bit hazardous as a Garbage Collect may occur.
 *			 If it happens, the library cannot guarantee that http_data still points to the data.
 *	@param	http_data The same structure as you passed to web_HTTPPost or web_HTTPGet.
 *	@returns 1 if the data is now locked, 0 if not.
 */
int web_LockData(http_data_t **http_data);

/**
 * @brief	Initiates the connection to the given TLS server.
 * @note	This function blocks until the TLS handshake is completed.
 * @note	You must call \c web_TCPClose to close the connection.
 * @param	ip_dst The IP address of the TLS server.
 * @param	port_dst The port of the TLS server.
 * @param	server_name The name of the server (SNI).
 * @returns A \c tls_exchange_t structure or \c NULL. You'll have to pass this structure to other TLS functions.
 */
tls_exchange_t *web_TLSConnect(uint32_t ip_dst, web_port_t port_dst, const char *server_name, web_appli_callback_t *callback,
							   web_callback_data_t *user_data);

/**
 * @brief	Close a TLS connection.
 * @note	The \c tls_exchange_t structure can't be used after calling this function.
 * @param	tls_exch The \c tls_exchange_t structure returned by \c web_TLSConnect.
 * @param	is_abort If true, the connection will be aborted and the server will be sent an error.
 */
void web_TLSClose(tls_exchange_t *tls_exch, bool is_abort);

/**
 *  @brief	Deliver a TLS data to the host connected to \c tls_exch.
 * 	@param	tls_exch The TLS exchange structure, returned by \c web_TLSConnect.
 * 	@param	data The data that must be delivered.
 * 	@param	length The length of the data.
 * 	@returns  \c WEB_SUCCESS or an error.
 */
web_status_t web_DeliverTLSData(tls_exchange_t *tls_exch, void *data, size_t length);

/**
 *	@brief	Sends a DNS request to the router's default DNS Server. Waits until the request finishes.
 *	@param	url The URL you want to know the IP address.
 *	@returns The IP address or -1 if the transfer failed.
 */
uint32_t web_SendDNSRequest(const char *url);

/**
 *	@brief	Schedules a DNS request to the router's default DNS Server.
 *  @note	Use \c web_WaitForEvents() to actually send the DNS query.
 *	@param	url The URL you want to know the IP address.
 *	@param	callback The function you want to be called once the reply is received.
 *	@param	user_data Pointer passed to your callback.
 *	@returns  \c WEB_SUCCESS or an error.
 */
web_status_t web_PushDNSRequest(const char *url, web_dns_callback_t *callback, web_callback_data_t *user_data);

/**
 * @brief  Connect the device to the specified \c ip_dst:port_dst. All messages received from this address will be
 * 		   passed to \c callback.
 * @note   This function blocks until the TCP handshake is completed.
 * @param  ip_dst The target IPv4 address.
 * @param  port_dst The target port number.
 * @param  callback The function you want to be called when a message is received from the host.
 * @param  user_data Pointer passed to your callback
 * @returns A \c tcp_exchange_t structure or \c NULL. You'll have to pass this structure to other TCP functions such as
 * 			\c web_DeliverTCPSegment.
 */
tcp_exchange_t *web_TCPConnect(uint32_t ip_dst, web_port_t port_dst, web_appli_callback_t *callback,
							   web_callback_data_t *user_data);

/**
 * @brief  Close a TCP connection.
 * @note   The \c tcp_exchange_t structure can't be used after calling this function.
 * @param  tcp_exch The \c tcp_exchange_t structure returned by \c web_TCPConnect.
 * @param  is_abort If true, the connection will be aborted (with an RST segment).
 * @returns \c WEB_SUCCESS or an error (no memory, etc).
 * @warning The \c tcp_exchange_t structure must NOT be used after calling this function.
 */
web_status_t web_TCPClose(tcp_exchange_t *tcp_exch, bool is_abort);

/**
 *  @brief	Deliver a TCP segment to the host connected to \c tcp_exch.
 * 	@note	The function insures the correct delivery of the segment with a system of acknowledgement.
 * 	@param	tcp_exch The TCP exchange structure, returned by web_TCPConnect.
 * 	@param	data The data that must be delivered.
 * 	@param	length The length of the data.
 * 	@returns  \c WEB_SUCCESS or an error.
 */
web_status_t web_DeliverTCPSegment(tcp_exchange_t *tcp_exch, void *data, size_t length);

/**
 *	@brief	Schedules the delivery of a TCP segment.
 *	@note	Use \c web_WaitForEvents() to actually send the TCP segment.
 *	@param	data The data that must be encapsulated in the TCP header.
 *	@param	length_data The length of the encapsulated data.
 *	@param	ip_dst The target IP address.
 *	@param	port_src The port number of the application performing the delivery. This port number must have been
 *			attributed with web_RequestPort(), except for special ports (<49152).
 *	@param	port_dst The port number of the target application. For example 80 for HTTP.
 *	@param	seq_number The sequence number of the next byte to send.
 *	@param	ack_number If \c FLAG_TCP_ACK is set, this stands for the next byte of data you expect.
 *	@param	flags For example \c FLAG_TCP_NONE, \c FLAG_TCP_ACK ...
 *	@param	opt_size Size of the \c options array. Must be a multiple of 4.
 *	@param	options Options of the TCP segment. The bytes are copied as they are in the TCP segment, so the length must
 *			be a multiple of 4.
 *	@returns \c WEB_SUCESS or an error.
 */
web_status_t web_SendRawTCPSegment(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								   web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags,
								   size_t opt_size, const uint8_t *options);

/**
 *	@brief	Pushes a TCP segment on the sending queue. The segment will be re-sent every \c SEND_EVERY seconds until
 *			you call \c web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the TCP segment.
 *	@param	data The data that must be encapsulated in the TCP header.
 *	@param	length_data The length of the data encapsulated.
 *	@param	ip_dst The target IP address.
 *	@param	port_src The port number of the application performing the sending. This port number must have been
 *			attributed with \c web_RequestPort(), except for special ports (<49152).
 *	@param	port_dst The port number of the target application. For example 80 for HTTP.
 *	@param	seq_number The sequence number of the next byte to send.
 *	@param	ack_number If \c FLAG_TCP_ACK is set, this stands for the next byte of data you expect.
 *	@param	flags For example \c FLAG_TCP_NONE, \c FLAG_TCP_ACK...
 *	@param	opt_size Size of the \c options array. Must be a multiple of 4.
 *	@param	options Options of the TCP segment. The bytes are copied as they are in the TCP segment, so the length must
 *			be a multiple of 4.
 *	@returns A structure that must be passed to \c web_popMessage() once a response has been received
 *			(for example an acknowledgment).
 */
msg_queue_t *web_PushRawTCPSegment(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								   web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags,
								   size_t opt_size, const uint8_t *options);

/**
 *	@brief	Schedules the delivery of an UDP datagram.
 *	@note	Use \c web_WaitForEvents() to actually send the UDP datagram.
 *	@param	data The data that must be encapsulated in the UDP header.
 *	@param	length_data The length of the data encapsulated.
 *	@param	ip_dst The target IP address.
 *	@param	port_src The port number of the application performing the delivery. This port number must have been
 *	attributed with \c web_RequestPort(), except for special ports (<49152).
 *	@param	port_dst The port number of the target application. For example 80 for HTTP.
 *	@returns \c WEB_SUCESS or an error.
 */
web_status_t web_SendUDPDatagram(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								 web_port_t port_dst);

/**
 *	@brief	Pushes an UDP datagram on the sending queue. The datagram will be re-sent every \c SEND_EVERY seconds
 *			until you call web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the UDP datagram.
 *	@param	data The data that must be encapsulated in the UDP header.
 *	@param	length_data The length of the encapsulated data.
 *	@param	ip_dst The target IP address.
 *	@param	port_src The port number of the application performing the delivery. This port number must have been
 *	attributed with web_RequestPort(), except for special ports (<49152).
 *	@param	port_dst The port number of the target application. For example 80 for HTTP.
 *	@returns A structure that must be passed to \c web_popMessage() once a response has been received.
 */
msg_queue_t *web_PushUDPDatagram(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								 web_port_t port_dst);

/**
 * @brief  Ping a foreign host.
 * @note   This function blocks until a response is received or until the timeout is reached (2 seconds).
 * @param  ip_dst The target IPv4.
 * @return \c WEB_SUCCESS if a response has been received, \c WEB_TIMEOUT if no response were received in 2 seconds and
 * 		   \c WEB_ERROR_FAILED for other errors.
 */
web_status_t web_Ping(uint32_t ip_dst);

/**
 *	@brief	Schedules the delivery of an IPv4 packet.
 *	@note	Use \c web_WaitForEvents() to actually send the IPv4 packet.
 *	@param	data The data that must be encapsulated in the IPv4 header.
 *	@param	length_data The length of the data encapsulated.
 *	@param	ip_dst The target IP address.
 *	@param  protocol The IPv4 protocol hint of the encapsulated data.
 *	@returns \c WEB_SUCESS or an error.
 */
web_status_t web_SendIPv4Packet(void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol);

/**
 *	@brief	Pushes a IPv4 packet on the sending queue. The packet will be re-sent every \c SEND_EVERY seconds
 *			until you call \c web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the IPv4 packet.
 *	@param	data The data that must be encapsulated in the IPv4 header.
 *	@param	length_data The length of the encapsulated data.
 *	@param	ip_dst The target IP address.
 *	@param	protocol The IPv4 protocol hint of the encapsulated data.
 *	@returns A structure that must be passed to \c web_popMessage() once a response has been received.
 */
msg_queue_t *web_PushIPv4Packet(void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol);

/**
 *	@brief	Schedules the delivery of an Ethernet frame.
 *	@note	Use \c web_WaitForEvents() to actually send the Ethernet frame.
 *	@param	data The data that must be encapsulated in the ethernet frame.
 *	@param	length_data The length of the data encapsulated.
 *	@param  protocol The ethernet protocol hint of the encapsulated data.
 *	@returns \c WEB_SUCESS or an error.
 */
web_status_t web_SendEthernetFrame(void *data, size_t length_data, uint16_t protocol);

/**
 *	@brief	Pushes an ethernet frame on the sending queue. The frame will be re-sent every \c SEND_EVERY seconds
 *			until you call \c web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the frame.
 *	@param	data The data that must be encapsulated in the ethernet header.
 *	@param	length_data The length of the encapsulated data.
*	@param  protocol The ethernet protocol hint of the encapsulated data.
 *	@returns A structure that must be passed to \c web_popMessage() once a response has been received.
 */
msg_queue_t *web_PushEthernetFrame(void *data, size_t length_data, uint16_t protocol);

/**
 *	@brief	Schedules the delivery of a RNDIS packet to the RNDIS device.
 *	@note	Use \c web_WaitForEvents() to actually send the packet.
 *	@param	data The data that must be encapsulated in the RNDIS header.
 *	@param	length_data The length of the encapsulated data.
 *	@returns \c WEB_SUCCESS or an error.
 */
web_status_t web_SendRNDISPacket(void *data, size_t length_data);

/**
 *	@brief	Pushes a RNDIS packet on the sending queue. The packet will be re-sent every \c SEND_EVERY seconds
 *			until you call \c web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the packet.
 *	@param	data The data that must be encapsulated in the RNDIS header.
 *	@param	length_data The length of the encapsulated data.
 *	@returns A structure that must be passed to \c web_popMessage() once a response has been received.
 */
msg_queue_t *web_PushRNDISPacket(void *data, size_t length_data);

/**
 *	@brief	Returns the IP address of the calculator, allocated by the DHCP server.
 *	@warning \c web_Connected() must return \c true before using this function.
 *	@returns The IP address allocated by the DHCP server.
 */
uint32_t web_getMyIPAddr();

/**
 *	@brief	Returns \c true if the calculator is ready to access the internet, \c false otherwise.
 *	@returns \c true if connected, \c false otherwise.
 */
bool web_Connected();

/**
 *	@brief	Waits for any internet or USB events to occur. Sends or re-sends the messages that must be sent or re-sent.
 *	@returns An error returned by a callback or \c WEB_SUCCESS.
 */
web_status_t web_WaitForEvents();

/**
 *	@brief	Requests a port number from the library.
 *	@returns A port number or 0 if no port is available.
 */
web_port_t web_RequestPort();

/**
 *	@brief	Binds a port with a function. Any message addressed to this port will be passed to this function.
 *	@param	port The port to listen.
 *	@param	callback Function that will be called if any message addressed to this port is received. Can't be \c NULL.
 *	@param	user_data Pointer passed to your callback.
 *	@returns \c WEB_SUCCESS or an error.
 *	@note Given the RNDIS restrictions (which is just a LAN behind NAT/PAT rules), you can't passively listen to a port.
 *		  It means that it is not possible to create a webserver or any application that use passive listens
 *		  (but it may be possible in the future if the library supports other physical layers such as Wi-Fi, ECM, etc).
 */
web_status_t web_ListenPort(web_port_t port, web_port_callback_t *callback, web_callback_data_t *user_data);

/**
 *	@brief	Unbinds any function linked with a given port.  
 *	@param	port The port to "forget".
 *	@returns \c WEB_SUCCESS or an error.
 */
web_status_t web_UnlistenPort(web_port_t port);

/**
 *	@brief	Pushes a message on the sending queue. The message will be re-sent every \c SEND_EVERY seconds
 *			until you call \c web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the packet.
 *	@param	msg The data that must be sent.
 *	@param	length The length of the message.
 *	@returns A structure that must be passed to \c web_popMessage() once a response has been received.
 *	@note This function may not be useful for most users. You may want to use \c web_PushRawTCPSegment or
 *		  \c web_PushUDPDatagram instead.
 */
msg_queue_t *web_PushMessage(void *msg, size_t length);

/**
 *	@brief	Removes a message from the sending queue.
 *	@param	msg The structure returned by \c web_PushXXX after you called it.
 *	@note	Must be called once you receive a response of any pushed message.
 */
void web_PopMessage(msg_queue_t *msg);


#endif // INTERNET
