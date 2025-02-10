#include <internet.h>
#include <stdlib.h>
#include <string.h>

#include "include/transport_layer.h"
#include "include/core.h"
#include "include/ipv4.h"
#include "include/debug.h"


/**********************************************************************************************************************\
 *                                                  Global Variables                                                  *
\**********************************************************************************************************************/

port_list_t *listened_ports = NULL;


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_port_t web_RequestPort() {
	static web_port_t next_port = 0xC000;
	return next_port ? next_port++ : 0;
}

web_status_t web_ListenPort(web_port_t port, web_port_callback_t *callback, web_callback_data_t *user_data) {
	port_list_t *new_port = _malloc(sizeof(port_list_t));
	if(new_port == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	new_port->port = port;
	new_port->callback = callback;
	new_port->callback_data = user_data;
	new_port->next = listened_ports;
	listened_ports = new_port;
	return WEB_SUCCESS;
}

web_status_t web_UnlistenPort(web_port_t port) {
	web_status_t ret_val = WEB_ERROR_FAILED;
	port_list_t *cur_port = listened_ports;
	port_list_t *prev_port = NULL;
	port_list_t *next_port = NULL;
	while(cur_port) {
		next_port = cur_port->next;
		if(cur_port->port == port) {
			if(prev_port) {
				prev_port->next = cur_port->next;
			} else {
				listened_ports = cur_port->next;
			}
			_free(cur_port);
			ret_val = WEB_SUCCESS;
		}
		prev_port = cur_port;
		cur_port = next_port;
	}
	return ret_val;
}

/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

int call_callbacks(uint8_t protocol, void *data, size_t length, web_port_t port) {
	int nb_matches = 0;
	port_list_t *cur_listenedPort = listened_ports;
	while(cur_listenedPort) {
		if(port == cur_listenedPort->port) {
			nb_matches++;
			if(cur_listenedPort->callback(port, protocol, data, length, cur_listenedPort->callback_data) != WEB_IGNORE){
				break;
            }
		}
		cur_listenedPort = cur_listenedPort->next;
	}
	return nb_matches;
}

uint16_t transport_checksum(void *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol) {
	uint8_t checksum_hdr[sizeof(network_pseudo_hdr_t) + length];
	network_pseudo_hdr_t *pseudo_hdr = (network_pseudo_hdr_t *)checksum_hdr;
	pseudo_hdr->ip_src = ip_src;
	pseudo_hdr->ip_dst = ip_dst;
	pseudo_hdr->zero = 0x00;
	pseudo_hdr->protocol = protocol;
	pseudo_hdr->length = htons(length);
	memcpy(checksum_hdr + sizeof(network_pseudo_hdr_t), data, length);
	return ipv4_checksum(checksum_hdr, length + sizeof(network_pseudo_hdr_t));
}
