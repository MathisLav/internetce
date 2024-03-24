#include <internet.h>
#include <string.h>
#include <stdlib.h>

#include "include/core.h"
#include "include/usb.h"
#include "include/dhcp.h"
#include "include/tcp.h"
#include "include/debug.h"
#include "include/utils.h"
#include "include/http.h"
#include "include/rndis.h"
#include "include/transport_layer.h"


/**********************************************************************************************************************\
 *                                                  Global variables                                                  *
\**********************************************************************************************************************/

network_info_t netinfo;
uint8_t *src_mac_addr;
msg_queue_t *send_queue = NULL;


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

void web_Init() {
	srand(rtc_Time());
	uint8_t default_mac[6] = DEFAULT_MAC_ADDRESS;
	default_mac[5] = randInt(0, 0xFF);
	memcpy(netinfo.my_MAC_addr, default_mac, 6);
	netinfo.ep_wc_in = 0;
	netinfo.ep_cdc_in = 0;
	netinfo.ep_cdc_out = 0;
	netinfo.state = STATE_UNKNOWN;
	netinfo.device = NULL;
	netinfo.IP_addr = 0;
	memset(netinfo.router_MAC_addr, 0xFF, 6);

	usb_Init(usbHandler, NULL, NULL, USB_DEFAULT_INIT_FLAGS);
}

void web_Cleanup() {
	/* Freeing listened_ports */
	port_list_t *cur_port = listened_ports;
	port_list_t *next_port = NULL;
	while(cur_port) {
		next_port = cur_port->next;
		free(cur_port);
		cur_port = next_port;
	}

	/* Freeing send_queue */
	msg_queue_t *cur_queue = send_queue;
	msg_queue_t *next_queue = NULL;
	while(cur_queue) {
		next_queue = cur_queue->next;
		web_popMessage(cur_queue);
		cur_queue = next_queue;
	}

	/* Freeing the appvars used for saving what the lib receives */
	http_data_list_t *cur_data = http_data_list;
	http_data_list_t *next_data = NULL;
	while(cur_data) {
		next_data = cur_data->next;
		os_DelVarArc(OS_TYPE_APPVAR, cur_data->varname);
		free(cur_data);
		cur_data = next_data;
	}

	usb_Cleanup();
}

uint32_t web_getMyIPAddr() {
	return netinfo.IP_addr;
}

bool web_Connected() {
	return netinfo.state == STATE_NETWORK_CONFIGURED;
}

web_status_t web_WaitForEvents() {
	size_t transferred = 0;
	web_status_t ret_val = WEB_SUCCESS;

	switch(netinfo.state) {
		case STATE_USB_LOST:
			web_Cleanup();
			web_Init();
			break;  /* WEB_SUCCESS */
		
		case STATE_USB_ENABLED:
			if(configure_usb_device() != WEB_SUCCESS) {
				netinfo.state = STATE_UNKNOWN;
			} else {
				netinfo.state = STATE_RNDIS_INIT;
			}
			break;  /* WEB_SUCCESS */

		case STATE_RNDIS_DATA_INIT:
			dhcp_init();
			netinfo.state = STATE_DHCP_CONFIGURING;
			break;  /* WEB_SUCCESS */
		
		case STATE_DHCP_CONFIGURING:
		case STATE_NETWORK_CONFIGURED: {
			/* Close TCP connections after a timeout */
			handle_tcp_connections();

			/* Sending messages in the queue */
			if(handle_send_msg_queue() != WEB_SUCCESS) {
				return WEB_USB_ERROR;  /* At least one message couldn't be sent through USB */
			}

			/* Retrieving potential messages */
			uint8_t msg_buffer[MAX_RNDIS_TRANSFER_SIZE];  /* All the headers should take max 102B */
			usb_error_t err = usb_Transfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc_in), msg_buffer,
										   MAX_RNDIS_TRANSFER_SIZE, 0, &transferred);
			if(err != USB_SUCCESS) {
				dbg_warn("USB err: %u", err);
				ret_val = WEB_USB_ERROR;
			} else if(transferred != 0) {
				ret_val = packets_callback(transferred, msg_buffer);
			} else {
				ret_val = WEB_NO_DATA;
			}

		} default:
			break; /* nothing */
	}

	/* Handling USB events */
	usb_error_t err = usb_HandleEvents();
	if(err != USB_SUCCESS) {
		ret_val = WEB_USB_ERROR;
	}

	return ret_val;
}

msg_queue_t *web_PushMessage(void *msg, size_t length) {
	msg_queue_t *new_msg = malloc(sizeof(msg_queue_t));
	if(new_msg == NULL) {
		free(msg);
		return NULL;
	}
	new_msg->length = length;
	new_msg->msg = msg;
	new_msg->waitingTime = rtc_Time();
	new_msg->endpoint = usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc_out);
	new_msg->prev = NULL;
	new_msg->next = send_queue;
	if(send_queue) {
		send_queue->prev = new_msg;
	}
	send_queue = new_msg;
	return new_msg;
}

void web_popMessage(msg_queue_t *msg) {
	if(msg->prev)
		msg->prev->next = msg->next;
	else
		send_queue = msg->next;
	if(msg->next)
		msg->next->prev = NULL;
	free(msg->msg);
	free(msg);
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                  *
\**********************************************************************************************************************/

void *_alloc_msg_buffer(void *data, size_t length_data, size_t headers_total_size, bool has_eth_header) {
	const size_t size = length_data + headers_total_size;
	void *buffer = malloc(size);
	if(buffer == NULL) {
		dbg_err("No memory left");
		return NULL;
	}
	memcpy(buffer + headers_total_size - (has_eth_header ? 4 : 0), data, length_data);
	return buffer;
}

web_status_t handle_send_msg_queue() {
	// TODO send the messages as a queue, and not as a stack (FIFO)
	const uint32_t current_time = rtc_Time();
	msg_queue_t *cur_msg = send_queue;
	while(cur_msg) {
		if(cur_msg->waitingTime == 0) {  /* send once */
			msg_queue_t *remove_queue = cur_msg;
			if(usb_Transfer(cur_msg->endpoint, cur_msg->msg, cur_msg->length, 0, NULL) != USB_SUCCESS) {
				dbg_warn("Failed to send packet");
				return WEB_ERROR_FAILED;
			}
			cur_msg = cur_msg->next;
			web_popMessage(remove_queue);
		} else if(cur_msg->waitingTime <= current_time) {
			cur_msg->waitingTime = current_time + SEND_EVERY;
			if(usb_Transfer(cur_msg->endpoint, cur_msg->msg, cur_msg->length, 0, NULL) != USB_SUCCESS) {
				dbg_warn("Failed to send packet");
				return WEB_ERROR_FAILED;
			}
			cur_msg = cur_msg->next;
		} else {
			cur_msg = cur_msg->next;
		}
	}
	return WEB_SUCCESS;
}
