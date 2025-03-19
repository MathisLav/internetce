/**
 * Core functions
 */

#ifndef INTERNET_CORE
#define INTERNET_CORE


#include <stdint.h>
#include <internet.h>

#include "scheduler.h"


#define DEFAULT_MAC_ADDRESS {0xEA, 0xA5, 0x59, 0x9C, 0xC1, 0x00}

#define min(x, y) (x < y ? x : y)


/**
 * Enums & structs
 */

/* A list of the different states of the device */
typedef enum device_state {
	STATE_UNKNOWN,
	STATE_USB_INITIALIZED,
	STATE_USB_CONNECTED,
	STATE_USB_ENABLED,
	STATE_RNDIS_INIT,
	STATE_RNDIS_DATA_INIT,
	STATE_DHCP_CONFIGURING,
	STATE_NETWORK_CONFIGURED,
	STATE_USB_LOST
} device_state_t;

typedef struct network_info {
	usb_device_t device;
	device_state_t state;
	uint8_t ep_cdc_in;
	uint8_t ep_cdc_out;
	uint8_t ep_wc_in;
	uint8_t router_MAC_addr[6];
	uint8_t my_MAC_addr[6];
	uint32_t DNS_IP_addr;
	uint32_t IP_addr;
	dhcp_state_t dhcp_cur_state;
	size_t in_buffer_size;
	void *temp_usb_buffer;	/* Pointer to a temporary buffer, allocated to reassemble splitted USB packet */
	size_t received_size;	/* How many bytes in temp_usb_buffer are already received */
} network_info_t;

typedef struct allocated_memory {
	struct allocated_memory *next;
	uint8_t memory[];
} allocated_memory_t;


/**
 * Exported global variables
 */

extern network_info_t netinfo;
extern uint8_t *src_mac_addr; /* For dhcp purposes (we need to acknowledge the router's mac address) */


/**
 * Internal functions prototype
 */

void reset_netinfo_struct();

void *_alloc_msg_buffer(void *data, size_t length_data, size_t headers_total_size, bool has_eth_header);

scheduler_status_t send_packet_scheduler(web_callback_data_t *user_data);

void send_packet_destructor(web_callback_data_t *user_data);

void free_allocated_memory(allocated_memory_t **list, allocated_memory_t *allocated);

void free_allocated_memory_list(allocated_memory_t *memory_list);

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

inline uint24_t htonl24(uint24_t val) {
	uint8_t *pval = (uint8_t *)&val;
	return ((uint24_t)pval[0] << 16) + ((uint24_t)pval[1] << 8) + pval[2];
}

#define ntohl htonl
#define ntohs htons
#define ntohl24 htonl24

#define force_send_queue() dispatch_time_events()


#endif // INTERNET_CORE
