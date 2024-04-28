/**
 * Ethernet related functions
 */

#ifndef INTERNET_ETHERNET
#define INTERNET_ETHERNET


#include <internet.h>
#include <stdint.h>


/**
 * Internal functions prototype
 */

msg_queue_t *_recursive_PushEthernetFrame(void *buffer, void *data, size_t length_data, uint16_t protocol);

uint32_t crc32b(void *data, size_t length);

bool cmpbroadcast(const uint8_t *mac_addr);

web_status_t fetch_ethernet_frame(eth_frame_t *frame, size_t length);


#endif // INTERNET_ETHERNET
