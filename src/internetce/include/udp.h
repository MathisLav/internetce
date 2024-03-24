/**
 * UDP related functions
 */

#ifndef INTERNET_UDP
#define INTERNET_UDP


#include <internet.h>
#include <stdint.h>


/**
 * Internal functions prototype
 */

msg_queue_t *_recursive_PushUDPDatagram(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
											   web_port_t port_src, web_port_t port_dst);

web_status_t fetch_udp_datagram(udp_datagram_t *datagram, size_t length, uint32_t ip_src, uint32_t ip_dst);


#endif // INTERNET_UDP
