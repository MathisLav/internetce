/**
 * Core functions
 */

#ifndef INTERNET_CORE
#define INTERNET_CORE


#include <stdint.h>
#include <internet.h>


#define DEFAULT_MAC_ADDRESS {0xEA, 0xA5, 0x59, 0x9C, 0xC1, 0x00}


/**
 * Exported global variables
 */

extern network_info_t netinfo;
extern uint8_t *src_mac_addr; /* For dhcp purposes (we need to acknowledge the router's mac address) */
extern msg_queue_t *send_queue;


/**
 * Private functions prototype
 */

void *_alloc_msg_buffer(void *data, size_t length_data, size_t headers_total_size, bool has_eth_header);

web_status_t handle_send_msg_queue();

inline uint32_t htonl(uint32_t val) {
	uint8_t *pval = (uint8_t *)&val;
	return (((uint32_t)pval[0] * ((uint32_t)1 << 24)) +
			((uint32_t)pval[1] * ((uint32_t)1 << 16)) +
			((uint32_t)pval[2] * ((uint32_t)1 << 8)) +
			 (uint32_t)pval[3]);
}

inline uint16_t htons(uint16_t val) {
	uint8_t *pval = (uint8_t *)&val;
	return ((uint16_t)pval[0] * 256) + pval[1];
}


#endif // INTERNET_CORE
