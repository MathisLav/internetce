/**
 * TCP related functions
 */

#ifndef INTERNET_TCP
#define INTERNET_TCP


#include <internet.h>
#include <stdint.h>


/**
 * Internal functions prototype
 */

int add_tcp_queue(char *data, size_t length, tcp_exchange_t *exchange, uint16_t flags, size_t opt_size,
				  const uint8_t *options);

void fetch_ack(tcp_exchange_t *exchange, uint32_t ackn);

msg_queue_t *_recursive_PushTCPSegment(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
									   web_port_t port_src, web_port_t port_dst, uint32_t seq_number,
									   uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options);

web_status_t add_in_segment(tcp_exchange_t *tcp_exch, tcp_segment_t *segment, size_t length);

web_status_t fetch_conntrack_tcp(web_port_t port, uint8_t protocol, void *data, size_t length,
								 web_callback_data_t *user_data);

web_status_t fetch_raw_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst);

void fetch_tcp_flags(const tcp_segment_t *tcp_seg, tcp_exchange_t *exch, bool has_data);

web_status_t time_wait_scheduler(web_callback_data_t *user_data);

void time_wait_destructor(web_callback_data_t *user_data);

inline char *get_payload_addr(const tcp_segment_t *seg) {
	return (char *)seg + 4 * (seg->dataOffset_flags >> 4 & 0x0f);
}


#endif // INTERNET_TCP
