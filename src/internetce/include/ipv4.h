/**
 * IPv4 related functions
 */

#ifndef INTERNET_IPV4
#define INTERNET_IPV4


#include <internet.h>
#include <stdint.h>


/**
 * Internal functions prototype
 */

msg_queue_t *_recursive_PushIPv4Packet(void *buffer, void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol);

uint16_t ipv4_checksum(void *header, size_t count);

web_status_t fetch_IPv4_packet(ipv4_packet_t *pckt, size_t length);


#endif // INTERNET_IPV4
