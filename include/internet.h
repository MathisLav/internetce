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
#include <stdio.h>
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

/**
 * @enum device_state_t
 * A list of the different states of the device
 */
typedef enum device_state {
	STATE_UNKNOWN,
	STATE_USB_CONNECTED,
	STATE_USB_ENABLED,
	STATE_DHCP_CONFIGURING,
	STATE_NETWORK_CONFIGURED,
	STATE_USB_LOST
} device_state_t;

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
 * The callback used to notice the user a DNS reply has been received.
 */
typedef web_status_t (web_dns_callback_t)(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data);


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

typedef struct network_info {
	usb_device_t device;
	device_state_t state;
	uint8_t ep_cdc_in;
	uint8_t ep_cdc_out;
	uint8_t ep_wc_in;
	uint8_t router_MAC_addr[6];
	uint32_t DNS_IP_addr;
	uint32_t IP_addr;
	dhcp_state_t dhcp_cur_state;
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
	uint32_t waitingTime;	/**< Next time the msg will be sent (if 0 send once)	*/
	usb_endpoint_t endpoint;
	struct msg_queue *next;
	struct msg_queue *prev;
} msg_queue_t;

typedef struct http_data_list {
	char varname[9];
	struct http_data_list *next;
} http_data_list_t;

typedef struct pushed_seg_list {
	uint32_t next_rsn;					/**< Sequence number of the last byte of the segment+1	*/
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
	tcp_segment_list_t *segment_list;	/**< Received data													*/
	pushed_seg_list_t *pushed_seg;		/**< The segments pushed on the send queue that are waiting for an ack */
	uint32_t timeout_close;				/**< If in TIME_WAIT state: the time when closing and freeing the connection */
} tcp_exchange_t;

typedef struct http_exchange {
	tcp_exchange_t tcp_exch;
	uint32_t timeout;					/**< Timeout date, updated each time we receive an "interesting" segment */
	bool data_chunked;
	size_t content_length;
	size_t content_received;
	size_t header_length;
	size_t chunks_metadata_length;		/**< Size of all the characters encoding chunks metadata			*/
	size_t next_chunk_rsn;				/**< Relative SN of the next chunk									*/
	uint32_t rsn_end_chunk;				/**< If != 0, equal to the RSN where the end of the chunk metadata is */
	uint32_t next_hdrseg_check;			/**< Relative SN of the next header segment check (see 4th process)	*/
	http_data_t **data;					/**< Where to put the result										*/
	bool keep_http_header;
	web_status_t status;				/**< Set when the request is finished (successfuly or with an error) */
	bool dirty;							/**< Connection to delete as soon as possible						*/
} http_exchange_t;

typedef struct http_exchange_list {
	http_exchange_t *http_exch;
	struct http_exchange_list *next;
} http_exchange_list_t;


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

#define SEND_EVERY			2			/**< Hardcoded value but in theory this should be calculated		*/
#define TIMEOUT_WEB			30			/**< Maximum time of a web request (HTTP, DNS...)					*/
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
#define TCP_WINDOW_SIZE		MAX_SEGMENT_SIZE * 5  /**< Considering the calculator is pretty slow			*/

#define ETH_HEADERS_SIZE	(sizeof(rndis_packet_msg_t) + (sizeof(eth_frame_t) + 4))
#define IPV4_HEADERS_SIZE	(ETH_HEADERS_SIZE + sizeof(ipv4_packet_t))
#define ICMP_HEADERS_SIZE	(IPV4_HEADERS_SIZE + sizeof(icmpv4_echo_t))
#define TCP_HEADERS_SIZE	(IPV4_HEADERS_SIZE + sizeof(tcp_segment_t))
#define UDP_HEADERS_SIZE	(IPV4_HEADERS_SIZE + sizeof(udp_datagram_t))
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
 * DHCP General Constants
 */
#define DHCP_OP_REQUEST		0x01
#define DHCP_OP_REPLY		0x02
#define DHCP_HTYPE_MAC		0x01
#define DHCP_HLEN_MAC		0x06
#define DHCP_MAGIC_COOKIE	0x63538263

/**
 * DHCP Options
 */
#define DHCP_OPT_TYPE_ID	53
#define DHCP_OPT_TYPE_LEN	1
#define DHCP_OPT_V_DISCOVER 1
#define DHCP_OPT_V_OFFER	2
#define DHCP_OPT_V_REQUEST	3
#define DHCP_OPT_V_DECLINE	4
#define DHCP_OPT_V_ACK		5
#define DHCP_OPT_V_NAK		6
#define DHCP_OPT_V_RELEASE	7

#define DHCP_OPT_REQ_IP_ID	50
#define DHCP_OPT_SERVER_ID	54
#define DHCP_OPT_IP_LEN		4

#define DHCP_OPT_PARAM_REQ_LIST_ID	55
#define DHCP_OPT_SUBNET_MASK_ID	1
#define DHCP_OPT_ROUTER_ID	3
#define DHCP_OPT_DNS_ID		6

#define DHCP_OPT_END_OPTIONS	255

#define BASIC_HTTP_REQUEST "%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n"
#define POST_HTTP_INFO "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s"


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
 *	@brief	Performs a HTTP GET request to \c url and stores the address of the data in
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
 *	@brief	Performs a HTTP POST request to \c url and stores the address of the data in \c *data.
 			Waits until the transfer finishes.
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
 *	@returns A \c dns_exchange_t structure or \c NULL.
 */
dns_exchange_t *web_PushDNSRequest(const char *url, web_dns_callback_t *callback, web_callback_data_t *user_data);

/**
 * 
 */
msg_queue_t *web_PushDHCPMessage(size_t opt_size, const uint8_t *options, uint32_t dhcp_server_ip);

/**
 * 
 */
web_status_t web_SendDHCPMessage(size_t opt_size, const uint8_t *options, uint32_t dhcp_server_ip);

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
web_status_t web_SendTCPSegment(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
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
msg_queue_t *web_PushTCPSegment(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
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
 * 
 */
web_status_t web_SendICMPEchoRequest(uint32_t ip_dst);

/**
 * 
 */
web_status_t web_SendIPv4Packet(void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol);

/**
 *	@brief	Pushes a IPv4 packet on the sending queue. The packet will be re-sent every \c SEND_EVERY seconds
 *			until you call \c web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the IPv4 packet.
 *	@param	data The data that must be encapsulated in the IPv4 header.
 *	@param	length_data The length of the encapsulated data.
 *	@param	ip_dst The target IP address.
 *	@param	protocol The protocol of the encapsulated data (ICMP_PROTOCOL, TCP_PROTOCOL or UDP_PROTOCOL).
 *	@returns A structure that must be passed to \c web_popMessage() once a response has been received.
 */
msg_queue_t *web_PushIPv4Packet(void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol);

/**
 * 
 */
web_status_t web_SendEthernetFrame(void *data, size_t length_data, uint16_t protocol);

/**
 *	@brief	Pushes an ethernet frame on the sending queue. The frame will be re-sent every \c SEND_EVERY seconds
 *			until you call \c web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the frame.
 *	@param	data The data that must be encapsulated in the ethernet header.
 *	@param	length_data The length of the encapsulated data.
 *	@param	protocol The encapsulated protocol (ETH_ARP, ETH_IPV4, ...).
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
 */
void web_ListenPort(web_port_t port, web_port_callback_t *callback, web_callback_data_t *user_data);

/**
 *	@brief	Unbinds any function linked with a given port.  
 *	@param	port The port to "forget".
 */
void web_UnlistenPort(web_port_t port);

/**
 *	@brief	Pushes a message on the sending queue. The message will be re-sent every \c SEND_EVERY seconds
 *			until you call \c web_popMessage(msg).
 *	@note	Use \c web_WaitForEvents() to actually send the packet.
 *	@param	msg The data that must be sent.
 *	@param	length The length of the message.
 *	@returns A structure that must be passed to \c web_popMessage() once a response has been received.
 *	@note This function may not be useful for most users. You may want to use \c web_PushTCPSegment or
 *		  \c web_PushUDPDatagram instead.
 */
msg_queue_t *web_PushMessage(void *msg, size_t length);

/**
 *	@brief	Removes a message from the sending queue.
 *	@param	msg The structure returned by \c web_PushXXX after you called it.
 *	@note	Must be called once you receive a response of any pushed message.
 */
void web_popMessage(msg_queue_t *msg);


#endif // INTERNET
