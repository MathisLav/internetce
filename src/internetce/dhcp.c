#include <internet.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "include/dhcp.h"
#include "include/core.h"
#include "include/debug.h"


/**********************************************************************************************************************\
 *                                                  Global Variables                                                  *
\**********************************************************************************************************************/

static msg_queue_t *dhcp_last_msg_queue = NULL;


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

/* Note: This file has only internal functions */

msg_queue_t *push_dhcp_message(size_t opt_size, const uint8_t *options, uint32_t dhcp_server_ip) {
	static uint32_t xid = 0;
	if(xid == 0) {  /* If not initialized yet */
		xid = random();
	}

	const size_t size = sizeof(dhcp_message_t) + opt_size;
	uint8_t buffer[size];
	memset(buffer, 0, size);
	dhcp_message_t *dhcp_query = (dhcp_message_t *)buffer;
	dhcp_query->op = DHCP_OP_REQUEST;
	dhcp_query->htype = DHCP_HTYPE_MAC;
	dhcp_query->hlen = DHCP_HLEN_MAC;
	dhcp_query->hops = 0x00;
	dhcp_query->xid = xid;
	memcpy(dhcp_query->chaddr, netinfo.my_MAC_addr, 6);
	/* 192 zeros */
	dhcp_query->magicCookie = DHCP_MAGIC_COOKIE;
	memcpy(dhcp_query->options, options, opt_size);
	dhcp_query->siaddr = dhcp_server_ip;  /* = 0 at first */

	return web_PushUDPDatagram(dhcp_query, sizeof(dhcp_message_t) + opt_size, 0xffffffff, CLIENT_DHCP_PORT,
							   SERVER_DHCP_PORT);
}

void dhcp_init() {
	const uint8_t options_disc[] = {
		DHCP_OPT_TYPE_ID, DHCP_OPT_TYPE_LEN, DHCP_OPT_V_DISCOVER,
		DHCP_OPT_END_OPTIONS};
	dhcp_last_msg_queue = push_dhcp_message(sizeof(options_disc), options_disc, 0x00);
	web_ListenPort(CLIENT_DHCP_PORT, fetch_dhcp_msg, NULL);
	netinfo.dhcp_cur_state = DHCP_STATE_INIT;
}

web_status_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
                            web_callback_data_t *user_data) {
	(void)port; (void)length; (void)user_data;  /* Unused parameters */
	if(protocol != UDP_PROTOCOL)
		return WEB_SUCCESS;

	const dhcp_message_t *dhcp_msg = (dhcp_message_t *)((uint8_t *)msg + sizeof(udp_datagram_t));

	if(dhcp_msg->op == DHCP_OP_REPLY) {
		const uint8_t *cur_opt = (uint8_t *)((uint8_t *)dhcp_msg + sizeof(dhcp_message_t));
		while(cur_opt[0] != DHCP_OPT_END_OPTIONS) {
			switch(cur_opt[0]) {
				case DHCP_OPT_TYPE_ID:
					if(cur_opt[2] == DHCP_OPT_V_OFFER && netinfo.dhcp_cur_state == DHCP_STATE_INIT) {
						if(dhcp_last_msg_queue != NULL) {
							web_PopMessage(dhcp_last_msg_queue);
						}
						uint8_t options_req[] = {
							DHCP_OPT_TYPE_ID, DHCP_OPT_TYPE_LEN, DHCP_OPT_V_REQUEST,
							DHCP_OPT_PARAM_REQ_LIST_ID, 1, DHCP_OPT_DNS_ID,
							DHCP_OPT_SERVER_ID, DHCP_OPT_IP_LEN, 0, 0, 0, 0,
							DHCP_OPT_REQ_IP_ID, DHCP_OPT_IP_LEN, 0, 0, 0, 0,
							DHCP_OPT_END_OPTIONS};

						*(uint32_t *)(options_req + 8) = dhcp_msg->siaddr;
						*(uint32_t *)(options_req + 14) = dhcp_msg->yiaddr;
						dhcp_last_msg_queue = push_dhcp_message(sizeof(options_req), options_req, dhcp_msg->siaddr);
						if(dhcp_last_msg_queue != NULL) {
							netinfo.dhcp_cur_state = DHCP_STATE_SELECTING;
						}
					} else if(cur_opt[2] == DHCP_OPT_V_ACK && netinfo.dhcp_cur_state == DHCP_STATE_SELECTING) {
						if(dhcp_last_msg_queue != NULL) {
							web_PopMessage(dhcp_last_msg_queue);
							dhcp_last_msg_queue = NULL;
						}
						netinfo.IP_addr = dhcp_msg->yiaddr;
						memcpy(netinfo.router_MAC_addr, src_mac_addr, 6);
						netinfo.dhcp_cur_state = DHCP_STATE_BIND;
						netinfo.state = STATE_NETWORK_CONFIGURED;
					} else if(cur_opt[2] == DHCP_OPT_V_NAK && netinfo.dhcp_cur_state == DHCP_STATE_SELECTING) {
						dbg_warn("DHCP NACK");
						if(dhcp_last_msg_queue != NULL) {
							web_PopMessage(dhcp_last_msg_queue);
							dhcp_last_msg_queue = NULL;
						}
						web_UnlistenPort(CLIENT_DHCP_PORT);
						dhcp_init();
					}
					break;
				case DHCP_OPT_DNS_ID:
					if(netinfo.dhcp_cur_state != DHCP_STATE_BIND) {
						netinfo.DNS_IP_addr = *((uint32_t *)(cur_opt + 2)); /* we only take the first entry */
					}
					break;
				case 58: /* T1 Lease time */
					// TODO t1_leasetime = rtc_Time() + htonl(*(cur_opt + 2));
					break;
				default:
					break;
			}
			cur_opt += *(cur_opt + 1) + 2;
		}
	}
	return WEB_SUCCESS;
}
