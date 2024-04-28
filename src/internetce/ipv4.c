#include <internet.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "include/ipv4.h"
#include "include/core.h"
#include "include/debug.h"
#include "include/ethernet.h"
#include "include/tcp.h"
#include "include/udp.h"
#include "include/icmpv4.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

msg_queue_t *web_PushIPv4Packet(void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol) {
	void *buffer = _alloc_msg_buffer(data, length_data, IPV4_HEADERS_SIZE, true);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushIPv4Packet(buffer, buffer + IPV4_HEADERS_SIZE - 4, length_data, ip_dst,
									 protocol);
}

web_status_t web_SendIPv4Packet(void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol) {
	msg_queue_t *queued = web_PushIPv4Packet(data, length_data, ip_dst, protocol);
	if(queued != NULL) {
		queued->send_once = true;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

msg_queue_t *_recursive_PushIPv4Packet(void *buffer, void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol){
	static unsigned int nbpacket = 0;
	if(data - sizeof(ipv4_packet_t) < buffer) {
		dbg_err("Can't push IPv4 packet");
		free(buffer);
		return NULL;
	}

	/* Filling the IPv4 header */
	size_t size = length_data + sizeof(ipv4_packet_t);
	ipv4_packet_t *ipv4_pckt = (ipv4_packet_t *)(data - sizeof(ipv4_packet_t));
	ipv4_pckt->VerIHL = 0x45;
	ipv4_pckt->ToS = 0x00;
	ipv4_pckt->TotalLength = htons(size);
	ipv4_pckt->Id = htons(nbpacket++);
	ipv4_pckt->FlagsFragmentOffset = htons(0x4000);
	ipv4_pckt->TTL = 0x80;
	ipv4_pckt->Protocol = protocol;
	ipv4_pckt->HeaderChecksum = 0x0000;
	ipv4_pckt->IP_addr_src = netinfo.IP_addr;
	ipv4_pckt->IP_addr_dst = ip_dst;

	/* Computing the header checksum */
	uint16_t chksm = ipv4_checksum(ipv4_pckt, sizeof(ipv4_packet_t));
	ipv4_pckt->HeaderChecksum = chksm;

	return _recursive_PushEthernetFrame(buffer, ipv4_pckt, size, ETH_IPV4);
}

uint16_t ipv4_checksum(void *header, size_t count) {
	uint32_t sum = 0;
	uint16_t *data = (uint16_t *)header;

    while(count > 1) {
        sum += *(uint16_t *)data++;
        count -= 2;
    }

    if(count > 0) {
        sum += *(uint8_t *)data;
	}

    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
	}

    return (uint16_t)~sum;
}

web_status_t fetch_IPv4_packet(ipv4_packet_t *pckt, size_t length) {
	const size_t header_size = (pckt->VerIHL & 0x0F) * 4;
	void *payload = (void *)pckt + header_size;
	web_status_t ret_val;

	if(ipv4_checksum(pckt, header_size) != 0) {
		dbg_warn("Received bad checksumed IPv4 packet");
		return WEB_ERROR_FAILED;
	}
	if(pckt->FlagsFragmentOffset != 0 && pckt->FlagsFragmentOffset != 0x40) {
		dbg_warn("Received fragmented IPv4 packet");
	}

	switch(pckt->Protocol) {
		case TCP_PROTOCOL: {
			tcp_segment_t *tcp_seg = (tcp_segment_t *)payload;
			ret_val = fetch_raw_tcp_segment(tcp_seg, length - header_size, pckt->IP_addr_src, pckt->IP_addr_dst);
			break;
		} case UDP_PROTOCOL: {
			udp_datagram_t *udp_dtgm = (udp_datagram_t *)payload;
			ret_val = fetch_udp_datagram(udp_dtgm, length - header_size, pckt->IP_addr_src, pckt->IP_addr_dst);
			break;
		} case ICMP_PROTOCOL: {
			icmpv4_echo_t *msg = (icmpv4_echo_t *)payload;
			ret_val = fetch_icmpv4_msg(msg, length - header_size, pckt->IP_addr_src);
			break;
		} default:
			ret_val = WEB_SUCCESS;
	}
	return ret_val;
}
