#include <internet.h>
#include <fileioc.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "include/core.h"
#include "include/usb.h"
#include "include/dhcp.h"
#include "include/tcp.h"
#include "include/debug.h"
#include "include/utils.h"
#include "include/http.h"
#include "include/rndis.h"
#include "include/scheduler.h"
#include "include/transport_layer.h"
#include "include/crypto.h"


/**********************************************************************************************************************\
 *                                                  Global variables                                                  *
\**********************************************************************************************************************/

network_info_t netinfo;
uint8_t *src_mac_addr;
static void *msg_buffer = NULL;


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

void web_Init() {
	srand(rtc_Time());
	reset_netinfo_struct();
	netinfo.state = STATE_USB_INITIALIZED;
	netinfo.temp_usb_buffer = NULL;
	uint8_t default_mac[6] = DEFAULT_MAC_ADDRESS;
	default_mac[5] = randInt(0, 0xFF);
	memcpy(netinfo.my_MAC_addr, default_mac, 6);
	memset(netinfo.router_MAC_addr, 0xFF, 6);
	flash_setup();
	rng_Init();

	usb_Init(usbHandler, NULL, NULL, USB_DEFAULT_INIT_FLAGS);
}

void web_Cleanup() {
	/**
	 * If no connection is ingoing, there should be 3 allocated memories:
	 * 	- msg_buffer (used to receive the incoming packets)
	 * 	- The listen structure for port 0x44 (DHCP)
	 * 	- The event structure for RNDIS keepalives
	 * There might be more memory allocated if:
	 *  - An HTTP request was made (and created a http_data_list_t structure)
	 * 	- A TCP connection is still active
	 */

	/* Freeing the appvars used for saving what the lib receives */
	http_data_list_t *cur_data = http_data_list;
	http_data_list_t *next_data = NULL;
	while(cur_data) {
		next_data = cur_data->next;
		ti_Delete(cur_data->varname);
		_free(cur_data);
		cur_data = next_data;
	}
	http_data_list = NULL;

	/* Freeing the TLS session ticket list */
	free_session_tickets();

	/* Removing all pending TCP connections */
	flush_tcp_connections();

	/* Freeing scheduled events */
	flush_event_list();

	/* Freeing listened_ports */
	port_list_t *cur_port = listened_ports;
	port_list_t *next_port = NULL;
	while(cur_port) {
		next_port = cur_port->next;
		_free(cur_port);
		cur_port = next_port;
	}
	listened_ports = NULL;

	reset_netinfo_struct();

	if(msg_buffer != NULL) {
		_free(msg_buffer);
		msg_buffer = NULL;
	}

	if(netinfo.temp_usb_buffer != NULL) {
		_free(netinfo.temp_usb_buffer);
	}

	free_rndis_data();

	usb_Cleanup();

	/* Debugging feature, more or less a valgrind for calculator */
	print_allocated_memory();
}

uint32_t web_getMyIPAddr() {
	return netinfo.IP_addr;
}

bool web_Connected() {
	return netinfo.state == STATE_NETWORK_CONFIGURED;
}

web_status_t web_WaitForEvents() {
	web_status_t ret_val = WEB_SUCCESS;

	switch(netinfo.state) {
		case STATE_UNKNOWN:
			/* Nothing to do */
			return WEB_SUCCESS;
		case STATE_USB_LOST:
			web_Cleanup();
			web_Init();
			break;  /* WEB_SUCCESS */
		
		case STATE_USB_ENABLED:
			if(configure_usb_device() != WEB_SUCCESS) {
				netinfo.state = STATE_USB_INITIALIZED;
			} else {
				netinfo.state = STATE_RNDIS_INIT;
			}
			break;  /* WEB_SUCCESS */

		case STATE_RNDIS_DATA_INIT:
			/* We need sufficent entropy to continue (otherwise the RNG will not work) */
			if(dhcp_init() == 0) {
				netinfo.state = STATE_DHCP_CONFIGURING;
			}
			break;  /* WEB_SUCCESS */
		
		case STATE_DHCP_CONFIGURING:
		case STATE_NETWORK_CONFIGURED: {
			/* Retrieving potential messages */
			if(msg_buffer == NULL) {
				msg_buffer = _malloc(netinfo.in_buffer_size, "input");
				if(msg_buffer == NULL) {
					dbg_err("No memory left");
					return WEB_NOT_ENOUGH_MEM;
				}
				usb_error_t err = usb_ScheduleTransfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc_in),
													   msg_buffer, netinfo.in_buffer_size, packets_callback, &msg_buffer);
				if(err != USB_SUCCESS) {
					dbg_warn("USB err: %u", err);
					_free(msg_buffer);
					return WEB_USB_ERROR;
				}
			}

		} default:
			break; /* nothing */
	}

	/* Handling time events */
	dispatch_time_events();

	/* Handling USB events */
	usb_error_t err = usb_HandleEvents();
	if(err != USB_SUCCESS) {
		ret_val = WEB_USB_ERROR;
	}

	return ret_val;
}

msg_queue_t *web_PushMessage(void *msg, size_t length) {
	msg_queue_t *new_msg = _malloc(sizeof(msg_queue_t), "push");
	if(new_msg == NULL) {
		_free(msg);
		return NULL;
	}
	new_msg->length = length;
	new_msg->msg = msg;
	new_msg->send_once = false;  /* Modified in upper layers if needed */
	new_msg->endpoint = usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc_out);
	web_status_t ret_val = schedule(SEND_EVERY, send_packet_scheduler, send_packet_destructor, new_msg);
	if(ret_val != WEB_SUCCESS) {
		_free(msg);
		_free(new_msg);
		dbg_err("Failed to schedule message");
		return NULL;
	}
	return new_msg;
}

void web_PopMessage(msg_queue_t *msg) {
	remove_event(msg);
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                  *
\**********************************************************************************************************************/

void reset_netinfo_struct() {
	netinfo.ep_wc_in = 0;
	netinfo.ep_cdc_in = 0;
	netinfo.ep_cdc_out = 0;
	netinfo.state = STATE_UNKNOWN;
	netinfo.dhcp_cur_state = DHCP_STATE_BIND;
	netinfo.device = NULL;
	netinfo.IP_addr = 0;
}

void *_alloc_msg_buffer(void *data, size_t length_data, size_t headers_total_size, bool has_eth_header) {
	const size_t size = length_data + headers_total_size;
	void *buffer = _malloc(size, "alloc");
	if(buffer == NULL) {
		dbg_err("No memory left");
		return NULL;
	}
	memcpy(buffer + headers_total_size - (has_eth_header ? 4 : 0), data, length_data);
	return buffer;
}

scheduler_status_t send_packet_scheduler(web_callback_data_t *user_data) {
	msg_queue_t *cur_msg = (msg_queue_t *)user_data;

	const usb_error_t status = usb_ScheduleTransfer(cur_msg->endpoint, cur_msg->msg, cur_msg->length, NULL, NULL);
	if(status != USB_SUCCESS) {
		dbg_warn("Failed to send packet");
		return SCHEDULER_AGAIN;
	}

	return cur_msg->send_once ? SCHEDULER_DESTROY : SCHEDULER_AGAIN;
}

void send_packet_destructor(web_callback_data_t *user_data) {
	msg_queue_t *msg = (msg_queue_t *)user_data;
	_free(msg->msg);
	_free(msg);
}

void free_allocated_memory(allocated_memory_t **list, allocated_memory_t *allocated) {
	allocated_memory_t *current = *list;
	allocated_memory_t *previous = NULL;
	while(current != NULL) {
		if(current == allocated) {
			if(previous == NULL) {
				*list = current->next;
			} else {
				previous->next = current->next;
			}
			_free(current);
			return;
		}
		previous = current;
		current = current->next;
	}
	dbg_warn("Loose free");
}

void free_allocated_memory_list(allocated_memory_t *memory_list) {
	while(memory_list != NULL) {
		allocated_memory_t *next = memory_list->next;
		_free(memory_list);
		memory_list = next;
	}
}
