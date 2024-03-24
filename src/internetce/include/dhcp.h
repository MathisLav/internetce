/**
 * DHCP related functions
 */

#ifndef INTERNET_DHCP
#define INTERNET_DHCP


#include <internet.h>
#include <stdint.h>


/**
 * Constants
 */

/* General */
#define DHCP_OP_REQUEST		0x01
#define DHCP_OP_REPLY		0x02
#define DHCP_HTYPE_MAC		0x01
#define DHCP_HLEN_MAC		0x06
#define DHCP_MAGIC_COOKIE	0x63538263

/* DHCP Options */
#define DHCP_OPT_TYPE_ID	53
#define DHCP_OPT_TYPE_LEN	1
#define DHCP_OPT_V_DISCOVER 1
#define DHCP_OPT_V_OFFER	2
#define DHCP_OPT_V_REQUEST	3
#define DHCP_OPT_V_DECLINE	4
#define DHCP_OPT_V_ACK		5
#define DHCP_OPT_V_NAK		6
#define DHCP_OPT_V_RELEASE	7

#define DHCP_OPT_REQ_IP_ID	50
#define DHCP_OPT_SERVER_ID	54
#define DHCP_OPT_IP_LEN		4

#define DHCP_OPT_PARAM_REQ_LIST_ID	55
#define DHCP_OPT_SUBNET_MASK_ID	1
#define DHCP_OPT_ROUTER_ID	3
#define DHCP_OPT_DNS_ID		6

#define DHCP_OPT_END_OPTIONS	255


/**
 * Internal functions prototype
 */

void dhcp_init();

web_status_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
                            web_callback_data_t *user_data);


#endif // INTERNET_DHCP
