#include <internet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "include/ethernet.h"
#include "include/core.h"
#include "include/ipv4.h"
#include "include/debug.h"
#include "include/rndis.h"
#include "include/arp.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

msg_queue_t *web_PushEthernetFrame(void *data, size_t length_data, uint16_t protocol) {
	void *buffer = _alloc_msg_buffer(data, length_data, ETH_HEADERS_SIZE, true);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushEthernetFrame(buffer, buffer + ETH_HEADERS_SIZE - 4, length_data, protocol);
}

web_status_t web_SendEthernetFrame(void *data, size_t length_data, uint16_t protocol) {
	msg_queue_t *queued = web_PushEthernetFrame(data, length_data, protocol);
	if(queued != NULL) {
		queued->send_once = true;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

msg_queue_t *_recursive_PushEthernetFrame(void *buffer, void *data, size_t length_data, uint16_t protocol) {
	/* @Warning: 4 bytes must be reserved for CRC after the data */
	/* Ethernet frame must be at least 64B */
	const size_t min_payload_size = MIN_ETH_HDR_SIZE - (sizeof(eth_frame_t) + 4);  /* = 46 */
	if(length_data < min_payload_size) {
		/* Reallocating so it is 64B large */
		uint8_t *new_buffer = malloc(MIN_ETH_HDR_SIZE + sizeof(rndis_packet_msg_t));
		void *new_data = new_buffer + sizeof(rndis_packet_msg_t) + sizeof(eth_frame_t);
		memcpy(new_data, data, length_data);
		memset(new_data + length_data, 0, min_payload_size - length_data);
		free(buffer);
		buffer = new_buffer;
		data = new_data;
		length_data = min_payload_size;
	}
	if(data - sizeof(eth_frame_t) < buffer) {
		dbg_err("Can't push ethernet frame");
		free(buffer);
		return NULL;
	}

	size_t size = length_data + sizeof(eth_frame_t) + 4;
	eth_frame_t *frame = (eth_frame_t *)(data - sizeof(eth_frame_t));
	memcpy(frame->MAC_dst, netinfo.router_MAC_addr, 6);
	memcpy(frame->MAC_src, netinfo.my_MAC_addr, 6);
	frame->Ethertype = protocol;
	uint32_t crc = crc32b(frame, size - 4);
	memcpy((void *)frame + size - 4, &crc, 4);

	return _recursive_PushRNDISPacket(buffer, frame, size);
}

uint32_t crc32b(void *data, size_t length) {
	/**
	 *	Computes ethernet crc32.
	 *	Code found on stackoverflow.com (no licence was given to the code)
	 */
	const uint32_t crc_poly = 0xEDB88320;
    uint32_t crc;
	unsigned int i, j;

    if(!data || !length) {
        return 0;
	}
    crc = 0xFFFFFFFF;
    for(j = 0; j < length; j++) {
		crc ^= ((uint8_t *)data)[j];
		for(i = 0; i < 8; i++) {
        	crc = (crc & 1) ? ((crc >> 1) ^ crc_poly) : (crc >> 1);
		}
    }
    return ~crc;
}

bool cmpbroadcast(const uint8_t *mac_addr) {
	const uint24_t *mac24b = (uint24_t *)mac_addr;
	return (mac24b[0] & mac24b[1]) == 0xffffff;
}

web_status_t fetch_ethernet_frame(eth_frame_t *frame, size_t length) {
	if(frame->Ethertype == ETH_IPV4 && !memcmp(frame->MAC_dst, netinfo.my_MAC_addr, 6)) {
		src_mac_addr = frame->MAC_src;
		ipv4_packet_t *ipv4_pckt = (ipv4_packet_t *)((uint8_t *)frame + sizeof(eth_frame_t));
		return fetch_IPv4_packet(ipv4_pckt, length - sizeof(eth_frame_t));
	} else if(frame->Ethertype == ETH_ARP &&
			  (!memcmp(frame->MAC_dst, netinfo.my_MAC_addr, 6) || cmpbroadcast(frame->MAC_dst))) {
		fetch_arp_msg(frame);
	}

	return WEB_SUCCESS;
}
