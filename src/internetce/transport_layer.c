#include <internet.h>
#include <stdlib.h>
#include <string.h>

#include "include/transport_layer.h"
#include "include/core.h"
#include "include/ipv4.h"


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

void web_ListenPort(web_port_t port, web_port_callback_t *callback, web_callback_data_t *user_data) {
	port_list_t *new_port = malloc(sizeof(port_list_t));
	new_port->port = port;
	new_port->callback = callback;
	new_port->callback_data = user_data;
	new_port->next = listened_ports;
	listened_ports = new_port;
}

void web_UnlistenPort(web_port_t port) {
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
			free(cur_port);
		}
		prev_port = cur_port;
		cur_port = next_port;
	}
}

/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

web_status_t call_callbacks(uint8_t protocol, void *data, size_t length, web_port_t port) {
	port_list_t *cur_listenedPort = listened_ports;
	while(cur_listenedPort) {
		if(port == cur_listenedPort->port) {
			if(cur_listenedPort->callback(port, protocol, data, length, cur_listenedPort->callback_data) != WEB_IGNORE){
				break;
            }
		}
		cur_listenedPort = cur_listenedPort->next;
	}
	return WEB_SUCCESS;
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
