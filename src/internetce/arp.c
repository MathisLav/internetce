#include <internet.h>
#include <string.h>

#include "include/arp.h"
#include "include/core.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_status_t web_SendARPRequest(uint8_t MAC_dst[6]) {
	arp_message_t arp_msg = {
		.HwType = 0x01,
		.ProtocolType = ETH_IPV4,
		.HwAddrLength = 0x06,
		.ProtocolAddrLength = 0x04,
		.Operation = 0x01,
		.MAC_src = {},
		.IP_src = 0x00,
		.MAC_dst = {},
		.IP_dst = 0x00,
	};
	memcpy(arp_msg.MAC_src, netinfo.my_MAC_addr, 6);
	memcpy(arp_msg.MAC_dst, MAC_dst, 6);
	return web_SendEthernetFrame(&arp_msg, sizeof(arp_message_t), ETH_ARP);
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

void fetch_arp_msg(eth_frame_t *ethernet_frame) {
	arp_message_t *arp_msg = (arp_message_t *)((uint8_t *)ethernet_frame + sizeof(eth_frame_t));

	if(ethernet_frame->Ethertype != ETH_ARP || arp_msg->HwType != 0x0100 || arp_msg->Operation != 0x0100 ||
	   arp_msg->ProtocolType != ETH_IPV4 || arp_msg->IP_dst != netinfo.IP_addr) {
		return;
	}

	arp_message_t resp;
	resp.HwType = 0x0100;
	resp.ProtocolType = ETH_IPV4;
	resp.HwAddrLength = 0x06;
	resp.ProtocolAddrLength = 0x04;
	resp.Operation = 0x0200;
	memcpy(resp.MAC_src, netinfo.my_MAC_addr, 6);
	resp.IP_src = netinfo.IP_addr;
	memcpy(resp.MAC_dst, arp_msg->MAC_src, 6);
	resp.IP_dst = arp_msg->IP_src;

	web_SendEthernetFrame(&resp, sizeof(arp_message_t), ETH_ARP);
}
