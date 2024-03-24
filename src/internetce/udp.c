#include <internet.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "include/udp.h"
#include "include/core.h"
#include "include/transport_layer.h"
#include "include/ipv4.h"
#include "include/debug.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

msg_queue_t *web_PushUDPDatagram(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								 web_port_t port_dst) {
	void *buffer = _alloc_msg_buffer(data, length_data, UDP_HEADERS_SIZE, true);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushUDPDatagram(buffer, buffer + UDP_HEADERS_SIZE - 4, length_data, ip_dst, port_src, port_dst);
}

web_status_t web_SendUDPDatagram(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								 web_port_t port_dst) {
	msg_queue_t *queued = web_PushUDPDatagram(data, length_data, ip_dst, port_src, port_dst);
	if(queued != NULL) {
		queued->send_once = true;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

msg_queue_t *_recursive_PushUDPDatagram(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
											   web_port_t port_src, web_port_t port_dst) {
	if(data - sizeof(udp_datagram_t) < buffer) {
		dbg_err("Can't push UDP datagram");
		free(buffer);
		return NULL;
	}

	/* Filling the UDP datagram header */
	size_t size = length_data + sizeof(udp_datagram_t);
	udp_datagram_t *datagram = (udp_datagram_t *)(data - sizeof(udp_datagram_t));
	datagram->port_src = htons(port_src);
	datagram->port_dst = htons(port_dst);
	datagram->length = htons(size);
	datagram->checksum = 0x0000;

	/* Computing the header & data checksum */
	uint16_t chksm = transport_checksum(datagram, size, netinfo.IP_addr, ip_dst, UDP_PROTOCOL);
	datagram->checksum = chksm;

	return _recursive_PushIPv4Packet(buffer, datagram, size, ip_dst, UDP_PROTOCOL);
}

web_status_t fetch_udp_datagram(udp_datagram_t *datagram, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	if(!datagram->checksum || !transport_checksum((uint8_t*)datagram, length, ip_src, ip_dst, UDP_PROTOCOL)) {
		return call_callbacks(UDP_PROTOCOL, datagram, length, datagram->port_dst / 256 + datagram->port_dst * 256);
	} else {
		dbg_warn("Received bad checksumed UDP packet");
		return WEB_ERROR_FAILED;
	}
}
