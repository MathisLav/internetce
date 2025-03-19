/**
 * TCP related functions
 */

#ifndef INTERNET_TCP
#define INTERNET_TCP


#include <internet.h>
#include <stdint.h>
#include "core.h"

/**
 * Internal constants
 */

#define TCP_OPTION_MSS 0x02


/**
 * Internal functions prototype
 */

web_status_t internal_deliver_segment(tcp_exchange_t *tcp_exch, void *data, size_t length, uint16_t flags);

int add_tcp_queue(char *data, size_t length, tcp_exchange_t *exchange, uint16_t flags, size_t opt_size,
				  const uint8_t *options);

web_status_t fetch_ack(tcp_exchange_t *tcp_exch, uint32_t ackn);

msg_queue_t *_recursive_PushTCPSegment(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
									   web_port_t port_src, web_port_t port_dst, uint32_t seq_number,
									   uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options);

web_status_t add_in_segment(tcp_exchange_t *tcp_exch, tcp_segment_t *segment, size_t length);

web_status_t send_rst_segment(uint32_t ip_dst, tcp_segment_t *received, size_t length);

web_status_t fetch_conntrack_tcp(web_port_t port, uint8_t protocol, void *data, size_t length,
								 web_callback_data_t *user_data);

web_status_t fetch_raw_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst);

web_status_t fetch_tcp_flags(const tcp_segment_list_t *tcp_seg, tcp_exchange_t *tcp_exch);

void flush_tcp_connections();

void flush_sending_queue(tcp_exchange_t *tcp_exch);

void flush_receiving_queue(tcp_exchange_t *tcp_exch);

scheduler_status_t time_wait_scheduler(web_callback_data_t *user_data);

void time_wait_destructor(web_callback_data_t *user_data);

inline char *get_payload_addr(const tcp_segment_t *seg) {
	return (char *)seg + 4 * (seg->dataOffset_flags >> 4 & 0x0f);
}

inline uint32_t get_segment_sn_length(size_t payload_length, uint16_t flags) {
	return payload_length + (flags & htons(FLAG_TCP_RST | FLAG_TCP_FIN | FLAG_TCP_SYN) ? 1 : 0);
}

#define schedule_free_exchange(tcp_exch, x) delay_event(x * 1000, time_wait_scheduler, time_wait_destructor, tcp_exch)


#endif // INTERNET_TCP
