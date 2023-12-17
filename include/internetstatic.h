#ifndef INTERNET
#define INTERNET

#include <stdbool.h>
#include <tice.h>
#include <stdio.h>
#include <usbdrvce.h>


/**
 * @enum http_status_t
 * A description of all the HTTP codes is available here :
 * https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
 */
typedef enum http_status {
	USER_IGNORE = USB_IGNORE,						/**< In addition to the http status codes.	*/
	SYSTEM_NOT_ENOUGH_MEM = USB_ERROR_NO_MEMORY,	/**< Not enough memory to store the data, or the data is more than 65Ko. */
	SYSTEM_TIMEOUT = USB_ERROR_TIMEOUT,				/**< The transfer expired.				*/
	DNS_ERROR,										/**< An error occurred in the DNS reply.	*/
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

/**
 * @enum device_state_t
 * A list of the different states of the device
 */
typedef enum device_state {
	STATE_UNKNOWN,
	STATE_USB_CONNECTED,
	STATE_USB_ENABLED,
	STATE_RNDIS_CONFIGURING,
	STATE_DHCP_CONFIGURING,
	STATE_NETWORK_CONFIGURED,
	STATE_USB_LOST
} device_state_t;


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
typedef usb_error_t (web_port_callback_t)(web_port_t port, uint8_t protocol, void *data,
									   size_t length, web_callback_data_t *user_data);

/**
 * The callback used to notice the user a DNS reply has been received.
 */
typedef usb_error_t (web_dns_callback_t)(web_port_t port, uint32_t res_ip,
									  web_callback_data_t *user_data);


/**
 * The next structs are descriptions of web protocol headers such as IP or HTTP.  
 */

/**
 * RNDIS messages
 */

typedef struct rndis_msg {
	uint32_t MessageType;
	uint32_t MessageLength;
	uint32_t RequestId;
	uint8_t data[1];
} rndis_msg_t;

typedef struct rndis_init_msg {
	uint32_t MessageType;		/**< RNDIS_INIT_MSG									*/
	uint32_t MessageLength;		/**< 24												*/
	uint32_t RequestId;
	uint32_t MajorVersion;
	uint32_t MinorVersion;
	uint32_t MaxTransferSize;
} rndis_init_msg_t;

typedef struct rndis_set_msg {
	uint32_t MessageType;		/**< RNDIS_INIT_MSG									*/
	uint32_t MessageLength;		/**< 32												*/
	uint32_t RequestId;
	uint32_t Oid;
	uint32_t InformationBufferLength;
	uint32_t InformationBufferOffset;
	uint32_t DeviceVcHandle;	/**< 0												*/
	uint32_t OidValue;			/**< Oid value sent along with the message			*/
} rndis_set_msg_t;

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
	uint32_t crc;
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
	uint8_t data[];
} ipv4_packet_t;

typedef struct icmpv4_echo {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t seq_number;
	uint8_t payload[];
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


/**
 * The next structs are specific to this library.
 * They are not aim at being used outside.
 */

typedef struct network_info {
	usb_device_t device;
	device_state_t state;
	uint8_t ep_cdc_in;
	uint8_t ep_cdc_out;
	uint8_t ep_wc_in;
	uint8_t router_MAC_addr[6];
	uint32_t DHCP_IP_addr;
	uint32_t DNS_IP_addr;
} network_info_t;

typedef struct port_list {
	web_port_t port;
	web_port_callback_t *callback;
	web_callback_data_t *callback_data;
	struct port_list *next;
} port_list_t;

typedef struct tcp_segment_list {
	uint32_t relative_sn;
	size_t pl_length;		/**< Length of the payload of the segment				*/
	tcp_segment_t *segment;	/**< The very segment									*/
	struct tcp_segment_list *next;
} tcp_segment_list_t;

typedef struct msg_queue {
	size_t length;
	uint8_t *msg;
	uint32_t waitingTime;	/* Next time the msg will be sent						*/
	usb_endpoint_t endpoint;
	usb_transfer_callback_t callback;
	usb_callback_data_t *user_data;
	struct msg_queue *next;
	struct msg_queue *prev;
} msg_queue_t;

typedef struct http_data_list {
	char varname[9];
	struct http_data_list *next;
} http_data_list_t;

typedef struct pushed_seg_list {
	uint32_t relative_sn;	/* Sequence number of the last byte of the segment+1	*/
	msg_queue_t *seg;
	struct pushed_seg_list *next;
} pushed_seg_list_t;

typedef struct dns_exchange {
	web_dns_callback_t *callback;
	web_callback_data_t *user_data;
	msg_queue_t *queued_request;
} dns_exchange_t;

typedef struct http_exchange {
	uint32_t ip_dst;
	web_port_t port_src;
	web_port_t port_dst;
	bool connected;						/* Three-way handshake completed									*/
	bool fin_sent;
	uint32_t timeout;
	uint32_t cur_sn;					/* Current client's sequence number (SN of the next-sent segment)	*/
	uint32_t cur_ackn;					/* Current server's sequence number (our ack number)				*/
	uint32_t beg_sn;
	uint32_t beg_ackn;					/* First server's sequence number, set just after SYN ACK			*/
	uint32_t relative_seqacked;			/* Relative sequence number of our last acked segment				*/
	bool data_chunked;
	size_t content_length;
	size_t content_received;
	size_t header_length;
	size_t chunk_counter;				/* Offset of the next chunk											*/
	uint16_t ackn_next_header_segment;	/* ACK number of the next header segment (See "Third process")		*/
	tcp_segment_list_t *segment_list;	/* Received data													*/
	pushed_seg_list_t *pushed_seg;		/* The segments pushed on the send queue that are waiting for an ack*/
	http_data_t **data;					/* Where to put the result											*/
	bool keep_http_header;
	http_status_t status;				/* Status of the request: set when all segments were received (or when an error occurred) */
} http_exchange_t;


/**
 * Noticeable constants.
 */

#define DEVICE				0x00
#define WIRELESS_RNDIS_SUBCLASS		0x01
#define WIRELESS_RNDIS_PROTOCOL		0x03
#define MISC_RNDIS_SUBCLASS	0x04
#define MISC_RNDIS_PROTOCOL	0x01

#define RNDIS_PACKET_MSG 	0x00000001
#define RNDIS_INIT_MSG		0x00000002
#define RNDIS_INIT_CMPLT	0x80000002
#define RNDIS_SET_MSG		0x00000005
#define RNDIS_SET_CMPLT		0x80000005

#define SEND_EVERY			1
#define TIMEOUT				7			/**< Maximum time in web_WaitForEvents() in seconds					*/

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

#define MAX_SEGMENT_SIZE	1500			/**< Minimum MSS (the calculator does not handle ipv4 fragments)	*/
#define TCP_WINDOW_SIZE		MAX_SEGMENT_SIZE*7 /**< Considering the calculator is pretty slow				*/

#define FLAG_TCP_NONE		0
#define FLAG_TCP_FIN		1 << 0
#define FLAG_TCP_SYN		1 << 1
#define FLAG_TCP_PSH		1 << 3
#define FLAG_TCP_ACK		1 << 4


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
 *	@brief	Performs a HTTP GET request to \p url and stores the data in
 *	\p *data. Waits until the transfer finishes.
 *	@param	url	The target URL.
 *	@param	data The address to store the downloaded data.
 *	@param	keep_http_header If true, *data begins with the http header.
 *	@returns The HTTP status code of the request or an error. See \enum
 *	http_status_t for more information.
 *	@warning The content returned by this function in data is in READ-ONLY !
 *	Please use unlock_data() to write on \p data.
 */
http_status_t web_HTTPGet(const char* url, http_data_t **data, bool keep_http_header);

/**
 *	@brief	Performs a HTTP POST request to \p url and stores the data in
 *	\p *data. Waits until the transfer finishes.
 *	@param	url	The target URL.
 *	@param	data The address to store the downloaded data.
 *	@param	keep_http_header If true, *data begins with the http header.
 *	@param	nb_params Number of additionnal parameters of the POST request.
 *	@params ... Additionnal parameters. Must be of const char* type.
 *	@example HTTPPost("www.google.com", &data, true, 2, "Age", "21", "Name", "Epharius");
 *	@returns The HTTP status code of the request or an error. See \enum
 *	http_status_t for more information.
 *	@warning The content returned by this function in data is in READ-ONLY !
 *	Please use unlock_data() to write on \p data.
 */
http_status_t web_HTTPPost(const char* url, http_data_t **data, bool keep_http_header, int nb_params, ...);

/**
 *	@brief	Unlocks the data so it can be modified.
 *	@warning This operation must be done only if necessary.
 *	@param	http_data The HTTP data downloaded with HTTPGet or HTTPPost to be unlocked.
 *	@returns 1 if the data is now unlocked, 0 if not.
 */
int web_UnlockData(http_data_t **http_data);

/**
 *	@brief	Locks the data so it can't be modified anymore.
 *	@warning This operation is a little bit hazardous as a Garbage Collect may occur.
 *	If it happens, the library cannot guarantee that http_data still points to the data.
 *	@param	http_data The HTTP data downloaded with HTTPGet or HTTPPost to be unlocked.
 *	@returns 1 if the data is now locked, 0 if not.
 */
int web_LockData(http_data_t **http_data);

/**
 *	@brief	Sends a DNS request to the router's default DNS Server.
 *	Waits until the request finishes.
 *	@param	url The URL you want to know the IP address.
 *	@returns The IP address or -1 if the transfer failed.
 */
uint32_t web_SendDNSRequest(const char *url);

/**
 *	@brief	Schedules a DNS request to the router's default DNS Server.
 *	@param	url The URL you want to know the IP address.
 *	@param	callback The function you want to be called once the reply
 *	is received.
 *	@param	user_data Pointer passed to your callback.
 */
void web_ScheduleDNSRequest(const char *url, web_dns_callback_t *callback, web_callback_data_t *user_data);

/**
 *	@brief	Schedules the sending of a TCP segment.
 *	@note	Use web_WaitForEvents() to actually send the TCP segment.
 *	@param	data The data that must be encapsulated in the TCP header.
 *	@param	length The length of the data encapsulated.
 *	@param	ip_dst The target IP address.
 *	@param	port_src The port number of the application performing the sending.
 *	This port number must have been attributed with web_RequestPort(), except
 *	for special ports (<49152).
 *	@param	port_dst The port number of the target application. For example 80
 *	for HTTP.
 *	@param	seq_number The sequence number of the next byte to send.
 *	@param	ack_number If \c FLAG_TCP_ACK is set, this stands for the last byte you
 *	want to acknowledge.
 *	@param	flags For example \c FLAG_TCP_NONE, \c FLAG_TCP_ACK...
 *	@param	opt_size Size of the \p options array. Must be a multiple of 4.
 *	@param	options Options of the TCP segment. The bytes are copied as they are in
 *	the TCP segment, so the length must be a multiple of 4.
 *	@returns \c USB_SUCESS or an error.
 */
usb_error_t web_SendTCPSegment(char *data, size_t length, uint32_t ip_dst, web_port_t port_src, web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options);

/**
 *	@brief	Pushes a TCP segment on the sending queue. The segment will be re-sent 
 *	every \c SEND_EVERY seconds until you call web_popMessage(msg).
 *	@note	Use web_WaitForEvents() to actually send the TCP segment.
 *	@param	data The data that must be encapsulated in the TCP header.
 *	@param	length The length of the data encapsulated.
 *	@param	ip_dst The target IP address.
 *	@param	port_src The port number of the application performing the sending.
 *	This port number must have been attributed with web_RequestPort(), except
 *	for special ports (<49152).
 *	@param	port_dst The port number of the target application. For example 80
 *	for HTTP.
 *	@param	seq_number The sequence number of the next byte to send.
 *	@param	ack_number If \c FLAG_TCP_ACK is set, this stands for the last byte you
 *	want to acknowledge.
 *	@param	flags For example \c FLAG_TCP_NONE, \c FLAG_TCP_ACK...
 *	@param	opt_size Size of the \p options array. Must be a multiple of 4.
 *	@param	options Options of the TCP segment. The bytes are copied as they are in
 *	the TCP segment, so the length must be a multiple of 4.
 *	@returns A structure that must be passed in web_popMessage() once a response has
 *	been received (for example an acknowledgment).
 */
msg_queue_t *web_PushTCPSegment(char *data, size_t length, uint32_t ip_dst, web_port_t port_src, web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options);

/**
 *	@brief	Pushes an UDP datagram on the sending queue. The datagram will be re-sent 
 *	every \c SEND_EVERY seconds until you call web_popMessage(msg).
 *	@note	Use web_WaitForEvents() to actually send the UDP datagram.
 *	@param	data The data that must be encapsulated in the UDP header.
 *	@param	length The length of the data encapsulated.
 *	@param	ip_dst The target IP address.
 *	@param	port_src The port number of the application performing the sending.
 *	This port number must have been attributed with web_RequestPort(), except
 *	for special ports (<49152).
 *	@param	port_dst The port number of the target application. For example 80
 *	for HTTP.
 *	@returns A structure that must be passed in web_popMessage() once a response has
 *	been received.
 */
msg_queue_t *web_PushUDPDatagram(uint8_t *data, size_t length, uint32_t ip_dst, web_port_t port_src, web_port_t port_dst);

/**
 *	@brief	Pushes a IPv4 packet on the sending queue. The packet will be re-sent 
 *	every \c SEND_EVERY seconds until you call web_popMessage(msg).
 *	@note	Use web_WaitForEvents() to actually send the IPv4 packet.
 *	@param	data The data that must be encapsulated in the IPv4 header.
 *	@param	length The length of the data encapsulated.
 *	@param	ip_src Your IP address. Use web_getMyIPAddr().
 *	@param	ip_dst The target IP address.
 *	@param	protocol The protocol encapsulated (ICMP_PROTOCOL, TCP_PROTOCOL or
 *	UDP_PROTOCOL).
 *	@returns A structure that must be passed in web_popMessage() once a response has
 *	been received.
 */
msg_queue_t *web_PushIPv4Packet(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol);

/**
 *	@brief	Broadcasts an ARP request. 
 *	@param	ip The IP address you want to know the MAC address.
 *	@note	This function is pretty useless for now, as the library does not have any
 *	ARP cache. 
 */
void web_SendARPQuery(uint32_t ip);

/**
 *	@brief	Pushes an ethernet frame on the sending queue. The frame will be re-sent
 *	every \c SEND_EVERY seconds until you call web_popMessage(msg).
 *	@note	Use web_WaitForEvents() to actually send the frame.
 *	@param	data The data that must be encapsulated in the ethernet header.
 *	@param	length The length of the data encapsulated.
 *	@param	The protocol encapsulated (ETH_ARP, ETH_IPV4, ...).
 *	@returns A structure that must be passed in web_popMessage() once a response has
 *	been received.
 */
msg_queue_t *web_PushEthernetFrame(uint8_t *data, size_t length, uint16_t protocol);

/**
 *	@brief	Pushes a RNDIS packet on the sending queue. The packet will be re-sent
 *	every \c SEND_EVERY seconds until you call web_popMessage(msg).
 *	@note	Use web_WaitForEvents() to actually send the packet.
 *	@param	data The data that must be encapsulated in the RNDIS header.
 *	@param	length The length of the data encapsulated.
 *	@returns A structure that must be passed in web_popMessage() once a response has
 *	been received.
 */
msg_queue_t *web_PushRNDISPacket(uint8_t *data, size_t length);

/**
 *	@brief	Schedules the sending of a RNDIS packet to the RNDIS device.
 *	@note	Use web_WaitForEvents() to actually send the packet.
 *	@param	data The data that must be encapsulated in the RNDIS header.
 *	@param	length The length of the data encapsulated.
 *	@returns USB_SUCESS or an error.
 */
usb_error_t web_SendRNDISPacket(uint8_t *data, size_t length);

/**
 *	@brief	Returns the IP address of the calculator, allocated by the DHCP
 *	server.
 *	@warning web_Connected() must return \c true before using this function.
 *	@returns The IP address allocated by the DHCP server.
 */
uint32_t web_getMyIPAddr();

/**
 *	@brief	Returns true if the calculator is ready to communicate through
 *	the internet, false if not.
 *	@returns true if connected, false if not.
 */
bool web_Connected();

/**
 *	@brief	Waits for any internet or USB events to occur. Sends or re-sends
 *	the messages that must be sent or re-sent.
 *	@returns An error returned by a callback or USB_SUCESS.
 */
usb_error_t web_WaitForEvents();

/**
 *	@brief	Requests a port number from the library.
 *	@returns A port number or 0 if no port is available.
 */
web_port_t web_RequestPort();

/**
 *	@brief	Binds a port with a function. Any message addressed to this port
 *	will be passed to a function you've created.
 *	@param	port The port to listen.
 *	@param	callback Function that will be called if any message addressed to
 *	this port is received. Can't be NULL.
 *	@param	user_data Pointer passed to your callback.
 */
void web_ListenPort(web_port_t port, web_port_callback_t *callback, web_callback_data_t *user_data);

/**
 *	@brief	Unbinds any function linked with a speicific port.  
 *	@param	The port to "forget".
 */
void web_UnlistenPort(web_port_t port);

/**
 *	@brief	Pushes a message on the sending queue. The message will be re-sent
 *	every \c SEND_EVERY seconds until you call web_popMessage(msg).
 *	@note	Use web_WaitForEvents() to actually send the packet.
 *	@param	msg The data that must be sent.
 *	@param	length The length of the message.
 *	@param	endpoint The endpoint to communicate with.
 *	@param	callback The callback to call every time the message is sent.
 *	@param	user_data The user data to be passed to the callback.
 *	@returns A structure that must be passed in web_popMessage() once a response has
 *	been received.
 *	@note This function may not be useful for most users. You may want to use
 *	push_rndis_packet, push_tcp_segment or push_udp_datagram instead.
 */
msg_queue_t *web_pushMessage(uint8_t *msg, size_t length, usb_endpoint_t endpoint, web_transfer_callback_t callback, web_callback_data_t *user_data);

/**
 *	@brief	Removes a message from the sending queue.
 *	@param	msg The structure returned by web_pushMessage after pushing your message.
 *	@note	Must be called once you receive a response of a pushed message.
 */
void web_popMessage(msg_queue_t *msg);


/**
 * Static functions
 */

static http_status_t http_request(const char *request_type, const char* url, http_data_t **data, bool keep_http_header, char *params);
static void add_tcp_queue(char *data, size_t length, http_exchange_t *exchange, uint16_t flags, size_t opt_size, const uint8_t *options);
static void fetch_ack(http_exchange_t *exchange, uint32_t ackn);
static usb_error_t fetch_http_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data);
static void wipe_data(http_exchange_t *exch);
static usb_error_t dns_callback(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data);
static usb_error_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data);
static void dhcp_init();
static usb_error_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data);
static usb_error_t send_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data);
static uint16_t transport_checksum(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol);
static uint16_t ipv4_checksum(uint16_t *header, size_t length);
static uint32_t crc32b(uint8_t *data, size_t length);
static usb_error_t send_rndis_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data);
static size_t getChunkSize(const char **ascii);
static bool cmpbroadcast(const uint8_t *mac_addr);
static uint32_t getBigEndianValue(uint8_t *beVal);
static usb_error_t configure_usb_device();
static usb_error_t call_callbacks(uint8_t protocol, void *data, size_t length, web_port_t port);
static usb_error_t fetch_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst);
static usb_error_t fetch_udp_datagram(udp_datagram_t *datagram, size_t length, uint32_t ip_src, uint32_t ip_dst);
static usb_error_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src);
static usb_error_t fetch_IPv4_packet(ipv4_packet_t *pckt, size_t length);
static void fetch_arp_msg(eth_frame_t *ethernet_frame);
static usb_error_t fetch_ethernet_frame(eth_frame_t *frame, size_t length);
static usb_error_t packets_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data);
static usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *data);

/**
 * Assembly functions
 */
extern var_t *MoveToArc(const char* name);
extern var_t *MoveToRam(const char* name);
extern bool os_EnoughMem(size_t mem);
extern int os_DelVarArc(uint8_t type, const char *name);
extern int ResizeAppVar(const char* name, size_t new_size); /* 1=the resizing happened, 0 if not */

#endif // INTERNET
