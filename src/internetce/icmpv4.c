#include <internet.h>
#include <stdio.h>

#include "include/icmpv4.h"
#include "include/ipv4.h"
#include "include/debug.h"
#include "include/scheduler.h"


/**********************************************************************************************************************\
 *                                                  Global Variables                                                  *
\**********************************************************************************************************************/

/*
	IP address from which is expected a ping reply, or 0 if there is no ping waiting.
	For now, only 1 address can be expected as web_Ping is blocking.
*/
uint32_t waiting_ping = 0;


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_status_t web_Ping(uint32_t ip_dst) {
	icmpv4_echo_t icmp_echo = {
		.type = ICMP_ECHO_REQUEST,
		.code = 0x00,
		.checksum = 0x00,
		.identifier = 0x00,
		.seq_number = 0x00,
	};
	icmp_echo.checksum = ipv4_checksum(&icmp_echo, sizeof(icmp_echo));
	if(web_SendIPv4Packet(&icmp_echo, sizeof(icmpv4_echo_t), ip_dst, ICMP_PROTOCOL) != WEB_SUCCESS) {
		return WEB_ERROR_FAILED;
	}

	bool is_timeout = false;
	delay_event(TIMEOUT_PING * 1000, boolean_scheduler, boolean_destructor, &is_timeout);
	waiting_ping = ip_dst;
	while(waiting_ping == ip_dst) {
		web_WaitForEvents();
		if(is_timeout) {
			waiting_ping = 0;
			return WEB_TIMEOUT;
		}
	}
	remove_event(&is_timeout);

	return WEB_SUCCESS;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

web_status_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src) {
	if(msg->type == ICMP_ECHO_REQUEST && msg->code == 0) {
		dbg_info("Received ping request from 0x%lx", ip_src);
		msg->type = ICMP_ECHO_REPLY;
		msg->checksum += ICMP_ECHO_REQUEST - ICMP_ECHO_REPLY;  /* Difference between the two messages */
		return web_SendIPv4Packet((uint8_t*)msg, length, ip_src, ICMP_PROTOCOL);
	} else if(msg->type == ICMP_ECHO_REPLY && msg->code == 0) {
		dbg_info("Received ping reply from 0x%lx", ip_src);
		if(ip_src == waiting_ping) {
			waiting_ping = 0;
		}
	}
	return WEB_SUCCESS;
}
