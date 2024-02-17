#include <internet.h>

#include "include/icmpv4.h"
#include "include/ipv4.h"
#include "include/debug.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_status_t web_SendICMPEchoRequest(uint32_t ip_dst) {
	icmpv4_echo_t icmp_echo = {
		.type = ICMP_ECHO_REQUEST,
		.code = 0x00,
		.checksum = 0x00,
		.identifier = 0x00,
		.seq_number = 0x00,
	};
	icmp_echo.checksum = ipv4_checksum(&icmp_echo, sizeof(icmp_echo));
	return web_SendIPv4Packet(&icmp_echo, sizeof(icmpv4_echo_t), ip_dst, ICMP_PROTOCOL);
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

web_status_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src) {
	if(msg->type != ICMP_ECHO_REQUEST || msg->code != 0) {
		return WEB_SUCCESS;
	}
	dbg_info("Received ping");

	msg->type = ICMP_ECHO_REPLY;
	msg->checksum += ICMP_ECHO_REQUEST - ICMP_ECHO_REPLY; /* Difference between the two messages */
	/* Send IPv4 packet */
	return web_SendIPv4Packet((uint8_t*)msg, length, ip_src, ICMP_PROTOCOL);
}
