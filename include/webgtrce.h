/**
 *--------------------------------------
 * Lib Name: webgtrce
 * Author: Mathis Lavigne aka Epharius
 * License: 
 * Description: This librairy aim at allowing any program to access the internet.
 *--------------------------------------
 */


#ifndef WEBGTRCE
#define WEBGTRCE

#include <usbdrvce.h>


#define DEVICE			0x00
#define RNDIS_SUBCLASS	0x01
#define RNDIS_PROTOCOL	0x03

#define RNDIS_PACKET_MSG 	0x00000001
#define RNDIS_INIT_MSG		0x00000002
#define RNDIS_INIT_CMPLT	0x80000002
#define RNDIS_SET_MSG		0x00000005
#define RNDIS_SET_CMPLT		0x80000005
typedef struct rndis_msg {
	uint32_t MessageType;
	uint32_t MessageLength;
	uint32_t RequestId;
	uint8_t data[1];
} rndis_msg_t;
typedef struct rndis_init_msg {
	uint32_t MessageType;		/**< RNDIS_INIT_MSG  */
	uint32_t MessageLength;		/**< 24  			*/
	uint32_t RequestId;
	uint32_t MajorVersion;
	uint32_t MinorVersion;
	uint32_t MaxTransferSize;
} rndis_init_msg_t;
typedef struct rndis_set_msg {
	uint32_t MessageType;		/**< RNDIS_INIT_MSG  */
	uint32_t MessageLength;		/**< 32  			*/
	uint32_t RequestId;
	uint32_t Oid;
	uint32_t InformationBufferLength;
	uint32_t InformationBufferOffset;
	uint32_t DeviceVcHandle;	/**< 0 				*/
	uint32_t OidValue;			/**< Oid value sent along with the message */
} rndis_set_msg_t;
typedef struct rndis_packet_msg {
	uint32_t MessageType;		/**< RNDIS_PACKET_MSG */
	uint32_t MessageLength;
	uint32_t DataOffset;
	uint32_t DataLength;
	uint32_t OOBDataOffset;
	uint32_t OOBDataLength;
	uint32_t NumOOBDataElements;
	uint32_t PerPacketInfoOffset;
	uint32_t PerPacketInfoLength;
	uint32_t VcHandle;		/**< Must be 0 */
	uint32_t Reserved;		/**< Must be 0 */
	/* Your data must be here /void data;/ */
} rndis_packet_msg_t;
typedef struct network_info {
	usb_device_t device;
	bool connected;
	bool enabled;
	bool configuring; /* Tells which endpoint is interesting (control or cdc) (see web_WaitForEvents()) */
	uint8_t int_cdc;
	uint8_t int_wc;
	uint8_t ep_cdc;
	uint8_t ep_wc;
	uint8_t router_MAC_addr[6];
	uint32_t DHCP_IP_addr;
	uint32_t DNS_IP_addr;
} network_info_t;

typedef struct eth_frame {
	uint8_t MAC_dst[6];
	uint8_t MAC_src[6];		/**< MAC_ADDR		*/
	uint16_t Ethertype;		/**< 0x0800 : IPv4	*/
	/* Your data must be here /void data;/ */
	uint32_t crc;
} eth_frame_t;
typedef struct ipv4_packet { // MSB First
	uint8_t VerIHL;			/**< 0x45			*/
	uint8_t ToS;			/**< often 0		*/
	uint16_t TotalLength;	/**< less than 65K but MTU is often 576B (minimal required value) */
	uint16_t Id;			/**< Identification of a fragment */
	uint16_t FlagsFragmentOffset; /**< The first 3 bits are flags. The following bits are Fragment Offset */
	uint8_t TTL;			/**< Time To Live	*/
	uint8_t Protocol;		/**< TCP=0x06; UDP=0x11; ICMP=0x01 */
	uint16_t HeaderChecksum;/**< Checksum of this header */
	uint32_t IP_addr_src;
	uint32_t IP_addr_dst;
	/* Your data must be here /void data;/ */
} ipv4_packet_t;
typedef struct ipv6_packet {
	uint32_t VerTCFL;		/**< Version 4b (=6), Trafic class 8b, Flow Label 20b */
	uint16_t PayloadLength;
	uint8_t NextHeader;
	uint8_t HopLimit;
	uint8_t IP_addr_src[16];
	uint8_t IP_addr_dst[16];
	/* Your data must be here /void data;/ */
} ipv6_packet_t;

#define web_port_t uint16_t
#ifndef web_callback_data_t
#define web_callback_data_t void
#endif
typedef usb_error_t (web_port_event_t)(web_port_t port, uint8_t protocol, void *data, size_t length, web_callback_data_t *user_data);

typedef struct port_list {
	web_port_t port;
	web_port_event_t *callback;
	web_callback_data_t *callback_data;
	struct port_list *next;
} port_list_t;


typedef struct udp_datagram {
	uint16_t port_src;
	uint16_t port_dst;
	uint16_t length;
	uint16_t checksum;
} udp_datagram_t;
typedef struct dhcp_message {
	uint8_t op; 	/**< 0x01 for us, 0x02 for the dhcp server */
	uint8_t htype;	/**< 0x01 */
	uint8_t hlen;	/**< 0x06 */
	uint8_t hops;	/**< 0x00 */
	uint32_t xid;	/**< Transaction ID */
	uint16_t secs;	
	uint16_t flags;	
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];/**< For MAC addrs, only the 6 first bytes are used */
	uint8_t zeros[192];/**< 0x00 */
	uint32_t magicCookie;/**< 0x63825363 */
	/* Options /void options;/ */
	// Must be 0xFF terminated
} dhcp_message_t;
typedef struct dns_message {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answerRRs;
	uint16_t authorityRRs;
	uint16_t additionalRRs;
	// queries
	// answers
	// authority
	// additional
} dns_message_t;
typedef struct tcp_segment {
	uint16_t port_src;
	uint16_t port_dst;
	uint32_t seq_number;
	uint32_t ack_number;
	uint16_t dataOffset_flags;
	uint16_t windowSize;
	uint16_t checksum;
	uint16_t urgentPointer;
	uint8_t options[];
} tcp_segment_t;
typedef struct tcp_segment_list {
	uint32_t relative_sn;
	size_t pl_length;			/**< Length of the payload of the segment */
	tcp_segment_t *segment; /**< The very segment */
	struct tcp_segment_list *next;
} tcp_segment_list_t;
typedef struct arp_message { /* For Ethernet -> IPv4 conversion only */
	uint16_t HwType;		/**< Ethernet 10Mb = 0x01 */
	uint16_t ProtocolType;	/**< IP = 0x0800 */
	uint8_t HwAddrLength;	/**< Ethernet = 0x06 */
	uint8_t ProtocolAddrLength; /**< IP=0x04 */
	uint16_t Operation;		/**< Request=0x01, Reply=0x02 */
	uint8_t MAC_src[6];
	uint32_t IP_src;
	uint8_t MAC_dst[6];
	uint32_t IP_dst;
} arp_message_t;


typedef enum http_status {
	USER_IGNORE = USB_IGNORE,
	SYSTEM_NOT_ENOUGH_MEM = USB_ERROR_NO_MEMORY,
	SYSTEM_TIMEOUT = USB_ERROR_TIMEOUT,
	DNS_ERROR,
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
} http_status_t;


typedef struct msg_queue {
	size_t length;
	uint8_t *msg;
	uint32_t waitingTime; /* Next time the msg will be sent */
	usb_endpoint_t endpoint;
	usb_transfer_callback_t callback;
	usb_callback_data_t *user_data;
	struct msg_queue *next;
	struct msg_queue *prev;
} msg_queue_t;

#define http_data_t	var_t
typedef struct http_data_list {
	char varname[9];
	struct http_data_list *next;
} http_data_list_t;

typedef struct pushed_seg_list {
	uint32_t relative_sn; /* Sequence number of the last byte of the segment+1 */
	msg_queue_t *seg;
	struct pushed_seg_list *next;
} pushed_seg_list_t;

typedef struct dns_exchange {
	uint32_t *res_ip;
	msg_queue_t *queued_request;
} dns_exchange_t;

typedef struct http_exchange {
	uint32_t ip_dst;
	web_port_t port_src;
	web_port_t port_dst;
	bool connected;							/* Three-way handshake completed */
	bool fin_sent;
	uint32_t timeout;
	uint32_t cur_sn;						/* Current client's sequence number (SN of the next-sent segment) */
	uint32_t cur_ackn;						/* Current server's sequence number (our ack number) */
	uint32_t beg_sn;
	uint32_t beg_ackn;						/* First server's sequence number, set just after SYN ACK */
	uint32_t relative_seqacked;				/* Relative sequence number of our last acked segment */
	bool data_chunked;
	size_t content_length;
	size_t content_received;
	size_t header_length;
	size_t chunk_counter;					/* Offset of the next chunk */
	uint16_t ackn_next_header_segment;		/* ACK number of the next header segment (See "Third process") */
	tcp_segment_list_t *segment_list;		/* Received data */
	pushed_seg_list_t *pushed_seg;			/* The segments pushed on the send queue that are waiting for an ack */
	http_data_t **data;						/* Where to put the result */
	bool keep_http_header;
	http_status_t status;					/* Status of the request: set when all segments were received (or when an error occurred) */
} http_exchange_t;



#define ipv6_addr		uint8_t*


#define SEND_EVERY		1
#define TIMEOUT			7		/* Maximum time in web_WaitForEvents() in seconds */

#define ETH_IPV4		0x0008		/* big endian stored */
#define ETH_ARP			0x0608		/* big endian stored */

#define ICMP_PROTOCOL	0x01
#define TCP_PROTOCOL	0x06
#define UDP_PROTOCOL	0x11

#define SERVER_DHCP_PORT	67
#define CLIENT_DHCP_PORT	68
#define DNS_PORT			53
#define HTTP_PORT			80
#define HTTPS_PORT			443

#define ERROR_DHCP_NACK		01

#define MAX_SEGMENT_SIZE	1036		/* Minimum MSS (the calculator does not handle ipv4 fragments) */
#define TCP_WINDOW_SIZE		MAX_SEGMENT_SIZE*7 /* Considering the calculator is pretty slow */

#define FLAG_TCP_NONE	0
#define FLAG_TCP_FIN	1 << 0
#define FLAG_TCP_SYN	1 << 1
#define FLAG_TCP_PSH	1 << 3
#define FLAG_TCP_ACK	1 << 4


void web_Cleanup();
int unlock_data(http_data_t **http_data);
int lock_data(http_data_t **http_data);
http_status_t HTTPGet(const char* url, http_data_t **data, bool keep_http_header);
http_status_t HTTPPost(const char* url, http_data_t **data, bool keep_http_header, int nb_params, ...);
static http_status_t http_request(const char *request_type, const char* url, http_data_t **data, bool keep_http_header, char *params);
void add_tcp_queue(char *data, size_t length, http_exchange_t *exchange, uint16_t flags, size_t opt_size, const uint8_t *options);
void fetch_ack(http_exchange_t *exchange, uint32_t ackn);
//http_status_t fetch_http_msg(http_data_t **data, uint32_t expected_ip, uint16_t src_port, uint32_t cur_sn, uint32_t *cur_ackn, bool keep_http_header);
usb_error_t fetch_http_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data);
static void wipe_data(http_exchange_t *exch);
void fetch_arp_msg(eth_frame_t *ethernet_frame);
void send_arp_query(uint32_t ip);
uint32_t send_dns_request(const char *addr);
void push_dns_request(const char *addr, uint32_t *res_ip);
usb_error_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data);
void dhcp_init();
usb_error_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data);
usb_error_t send_tcp_segment(char *data, size_t length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options);
static usb_error_t send_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data);
msg_queue_t *push_tcp_segment(char *data, size_t length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options);
uint16_t transport_checksum(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol);
msg_queue_t *push_udp_datagram(uint8_t *data, size_t length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst);
msg_queue_t *push_ipv4_packet(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol);
uint16_t ipv4_checksum(uint16_t *header, size_t length);
msg_queue_t *push_ethernet_frame(uint8_t *data, size_t length, uint16_t protocol);
uint32_t crc32b(uint8_t *data, size_t length);
msg_queue_t *push_rndis_packet(uint8_t *data, size_t length);
usb_error_t send_rndis_packet(uint8_t *data, size_t length);
static usb_error_t send_rndis_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data);
void web_Init();
size_t getChunkSize(const char **ascii);
bool cmpbroadcast(const uint8_t *mac_addr);
uint32_t getMyIPAddr();
bool web_Connected();
usb_error_t web_WaitForEvents();
web_port_t web_RequestPort();
void web_ListenPort(web_port_t port, web_port_event_t *callback, web_callback_data_t *callback_data);
void web_UnlistenPort(web_port_t port);
msg_queue_t *push_message(uint8_t *msg, size_t length, usb_endpoint_t endpoint, usb_transfer_callback_t callback, usb_callback_data_t *user_data);
void pop_message(msg_queue_t *msg);
static usb_error_t call_callbacks(uint8_t protocol, void *data, size_t length, web_port_t port);
static usb_error_t fetch_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst);
static usb_error_t fetch_udp_datagram(udp_datagram_t *datagram, size_t length, uint32_t ip_src, uint32_t ip_dst);
static usb_error_t fetch_IPv4_packet(ipv4_packet_t *pckt, size_t length);
static usb_error_t fetch_ethernet_frame(eth_frame_t *frame, size_t length);
static usb_error_t packets_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data);
static usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *data);
uint32_t getBigEndianValue(uint8_t *beVal);

#endif
