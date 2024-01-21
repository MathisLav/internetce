#ifndef INTERNETSTATIC
#define INTERNETSTATIC


#include <internet.h>


/**
 * Debugging stuffs
 */

#define NO_DEBUG		0
#define DEBUG_ERRORS	1
#define DEBUG_WARNINGS	2
#define DEBUG_INFO		3
#define DEBUG_VERBOSE	4

#if DEBUG_LEVEL == NO_DEBUG
	#define debug(...)
	#define pause(...)
	#define printf_xy(...)
	#define print_tcp_info(...)
	#define dbg_err(...)
	#define dbg_warn(...)
	#define dbg_info(...)
	#define dbg_verb(...)
#elif DEBUG_LEVEL == DEBUG_ERRORS
	void debug(const void *addr, size_t len);
	void printf_xy(unsigned int xpos, unsigned int ypos, const char *txt);
	void print_tcp_info(const tcp_segment_t *seg, http_exchange_t *exch, size_t length);
	#define pause() while(!os_GetCSC()) {}
	#define dbg_err(...) printf("E: " __VA_ARGS__); printf("\n")
	#define dbg_warn(...)
	#define dbg_info(...)
	#define dbg_verb(...)
#elif DEBUG_LEVEL == DEBUG_WARNINGS
	void debug(const void *addr, size_t len);
	void printf_xy(unsigned int xpos, unsigned int ypos, const char *txt);
	void print_tcp_info(const tcp_segment_t *seg, http_exchange_t *exch, size_t length);
	#define pause() while(!os_GetCSC()) {}
	#define dbg_err(...) printf("E: " __VA_ARGS__); printf("\n")
	#define dbg_warn(...) printf("W: " __VA_ARGS__); printf("\n")
	#define dbg_info(...)
	#define dbg_verb(...)
#elif DEBUG_LEVEL == DEBUG_INFO
	void debug(const void *addr, size_t len);
	void printf_xy(unsigned int xpos, unsigned int ypos, const char *txt);
	void print_tcp_info(const tcp_segment_t *seg, http_exchange_t *exch, size_t length);
	#define pause() while(!os_GetCSC()) {}
	#define dbg_err(...) printf("E: " __VA_ARGS__); printf("\n")
	#define dbg_warn(...) printf("W: " __VA_ARGS__); printf("\n")
	#define dbg_info(...) printf("I: " __VA_ARGS__); printf("\n")
	#define dbg_verb(...)
#elif DEBUG_LEVEL == DEBUG_VERBOSE
	void debug(const void *addr, size_t len);
	void printf_xy(unsigned int xpos, unsigned int ypos, const char *txt);
	void print_tcp_info(const tcp_segment_t *seg, http_exchange_t *exch, size_t length);
	#define pause() while(!os_GetCSC()) {}
	#define dbg_err(...) printf("E: " __VA_ARGS__); printf("\n")
	#define dbg_warn(...) printf("W: " __VA_ARGS__); printf("\n")
	#define dbg_info(...) printf("I: " __VA_ARGS__); printf("\n")
	#define dbg_verb(...) printf("V: " __VA_ARGS__); printf("\n")
#endif


/**
 * Static functions
 */

static uint32_t ip_ascii_to_hex(const char *ipstr);
static void check_timeout(http_exchange_t *exch);
static web_status_t http_request(const char *request_type, const char* url, http_data_t **data, bool keep_http_header,
								 char *params);
static void close_tcp_connection(http_exchange_t *exch);
static int add_tcp_queue(char *data, size_t length, http_exchange_t *exchange, uint16_t flags, size_t opt_size,
						 const uint8_t *options);
static void fetch_ack(http_exchange_t *exchange, uint32_t ackn);
static size_t httpcpy(http_exchange_t *exch, size_t offset_dst, const void *src, size_t size, size_t *jump_chars);
static void _fill_window(char *window, size_t size_window, tcp_segment_list_t *cur_seg, size_t chunk_offset);
static web_status_t return_http_data(http_exchange_t *exch);
static void fetch_tcp_flags(const tcp_segment_t *tcp_seg, http_exchange_t *exch, bool has_data);
static inline const char *get_payload_addr(const tcp_segment_t *seg);
static char *lowercase(char *str);
static uint24_t search_in_window(tcp_segment_list_t *prev_seg, tcp_segment_list_t *cur_seg, const char *str,
								 uint24_t size_str);
static const char *search_field_header(char *data, size_t length, const char *str, size_t size_str);
static int search_content_size(http_exchange_t *exch);
static web_status_t fetch_http_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
								   web_callback_data_t *user_data);
static void wipe_http_exchange(http_exchange_t *exch);
static web_status_t dns_callback(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data);
static web_status_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
								  web_callback_data_t *user_data);
static void dhcp_init();
static web_status_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
								   web_callback_data_t *user_data);
static msg_queue_t *_recursive_PushTCPSegment(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
											  web_port_t port_src, web_port_t port_dst, uint32_t seq_number,
											  uint32_t ack_number, uint16_t flags, size_t opt_size,
											  const uint8_t *options);
static uint16_t transport_checksum(void *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol);
static msg_queue_t *_recursive_PushUDPDatagram(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
											   web_port_t port_src, web_port_t port_dst);
static msg_queue_t *_recursive_PushIPv4Packet(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
											  uint8_t protocol);
static uint16_t ipv4_checksum(void *header, size_t length);
static msg_queue_t *_recursive_PushEthernetFrame(void *buffer, void *data, size_t length_data, uint16_t protocol);
static uint32_t crc32b(void *data, size_t length);
static msg_queue_t *_recursive_PushRNDISPacket(void *buffer, void *data, size_t length_data);
static void *_alloc_msg_buffer(void *data, size_t length_data, size_t headers_total_size, bool has_eth_header);
static uint24_t get_chunk_size(const char *ascii, const char *max_ptr, uint24_t *chunk_chars);
static bool cmpbroadcast(const uint8_t *mac_addr);
static inline uint32_t htonl(uint32_t val);
static inline uint16_t htons(uint16_t val);
static web_status_t handle_send_msg_queue();
static web_status_t configure_usb_device();
static web_status_t call_callbacks(uint8_t protocol, void *data, size_t length, web_port_t port);
static web_status_t fetch_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst);
static web_status_t fetch_udp_datagram(udp_datagram_t *datagram, size_t length, uint32_t ip_src, uint32_t ip_dst);
static web_status_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src);
static web_status_t fetch_IPv4_packet(ipv4_packet_t *pckt, size_t length);
static void fetch_arp_msg(eth_frame_t *ethernet_frame);
static web_status_t fetch_ethernet_frame(eth_frame_t *frame, size_t length);
static web_status_t packets_callback(size_t transferred, void *data);
static usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *data);


/**
 * Assembly functions
 */

extern var_t *MoveToArc(const char* name);
extern var_t *MoveToRam(const char* name);
extern bool os_EnoughMem(size_t mem);
extern int os_DelVarArc(uint8_t type, const char *name);
extern int ResizeAppVar(const char* name, size_t new_size); /* 1=the resizing happened, 0 if not */


#endif // INTERNETSTATIC
