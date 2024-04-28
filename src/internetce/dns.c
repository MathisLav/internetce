#include <internet.h>
#include <stdlib.h>
#include <string.h>

#include "include/dns.h"
#include "include/core.h"
#include "include/scheduler.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

uint32_t web_SendDNSRequest(const char *url) {
	uint32_t res_ip = 0;
	web_status_t status = web_PushDNSRequest(url, &dns_callback, &res_ip);
	if(status != WEB_SUCCESS) {
		return 0xffffffff;
	}

	while(!res_ip) {
		web_WaitForEvents();
	}
	return res_ip;
}

web_status_t web_PushDNSRequest(const char *url, web_dns_callback_t *callback, web_callback_data_t *user_data) {
	static unsigned int id_request = 0x01;
	/* 2=length byte at the begining of the string+0 terminated string */
	size_t length_data = sizeof(dns_message_t) + strlen(url) + 2 + 4;
	uint8_t buffer[length_data];
	memset(buffer, 0, length_data);
	dns_message_t *query = (dns_message_t *)buffer;

	query->id = id_request++;  /* osef endianness */
	query->flags = htons(0x0100);  /* Recursion allowed */
	query->questions = htons(0x0001);

	/* formating address for dns purposes */
	char *cursor_qry = (char *)(buffer + sizeof(dns_message_t) + 1);
	char *cursor_str = (char *)url;
	uint8_t i = 1;
	while(*cursor_str) {
		if(*cursor_str == '.') {
			*(cursor_qry - i) = i - 1;
			i = 0;
		} else {
			*cursor_qry = *cursor_str;
		}
		i++;
		cursor_str++;
		cursor_qry++;
	}
	*(cursor_qry - i) = i - 1;
	*(cursor_qry + 2) = 1; /* A (IPv4) */
	*(cursor_qry + 4) = 1; /* IN (internet) */

	dns_exchange_t *dns_exch = malloc(sizeof(dns_exchange_t));
	if(dns_exch == NULL) {
		return WEB_ERROR_FAILED;
	}
	web_port_t client_port = web_RequestPort();
	dns_exch->port_src = client_port;
	dns_exch->callback = callback;
	dns_exch->user_data = user_data;
	dns_exch->queued_request = web_PushUDPDatagram(query, length_data, netinfo.DNS_IP_addr, client_port, DNS_PORT);
	if(dns_exch->queued_request == NULL) {
		free(dns_exch);
		return WEB_ERROR_FAILED;
	}
	web_ListenPort(client_port, fetch_dns_msg, dns_exch);

	delay_event(TIMEOUT_NET * 1000, dns_timeout_scheduler, dns_timeout_destructor, dns_exch);
	return WEB_SUCCESS;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

web_status_t dns_callback(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data) {
	(void)port;
	*((uint32_t*)user_data) = res_ip;
	return WEB_SUCCESS;
}

web_status_t dns_timeout_scheduler(web_callback_data_t *user_data) {
	dns_exchange_t *dns_exch = (dns_exchange_t *)user_data;
	dns_exch->callback(dns_exch->port_src, 0xffffffff, dns_exch->user_data);
	return WEB_SUCCESS;
}

void dns_timeout_destructor(web_callback_data_t *user_data) {
	dns_exchange_t *dns_exch = (dns_exchange_t *)user_data;
	web_PopMessage(dns_exch->queued_request);
	web_UnlistenPort(dns_exch->port_src);
	free(dns_exch);
}

web_status_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data){
	(void)port; (void)length; /* Unused parameters */
	dns_exchange_t *exch = (dns_exchange_t *)user_data;
	const udp_datagram_t *udp_dtgm = (udp_datagram_t *)msg;
	if(protocol != UDP_PROTOCOL || htons(udp_dtgm->port_src) != DNS_PORT) {
		return WEB_SUCCESS;
	}

	web_status_t ret_val = WEB_SUCCESS;
	uint32_t found_ip = 0xffffffff;
	const dns_message_t *dns_msg = (dns_message_t*)((uint8_t*)udp_dtgm + sizeof(udp_datagram_t));

	/* if -> it isn't a response OR the recursion wasn't available OR an error occurred */
	if((dns_msg->flags & 0x8000) && (dns_msg->flags & 0x0080) && !(dns_msg->flags & 0x0F00)) {
		const uint8_t nb_answers = dns_msg->answerRRs >> 8;
		const uint8_t nb_queries = dns_msg->questions >> 8;

		const uint8_t *ptr = (uint8_t *)dns_msg + sizeof(dns_message_t);
		for(int i = 0; i < nb_queries; i++) {
			while(*(ptr++)) {}
			ptr += 4;
		}

		int i = 0;
		while(i < nb_answers && (*((uint16_t *)(ptr + 2)) != 0x0100 || *((uint16_t *)(ptr + 4)) != 0x0100)) {
			ptr += 11;
			ptr += *ptr + 1;
			i++;
		}

		if(i != nb_answers) {
			ptr += 12;
			found_ip = *((uint32_t *)ptr);
		}
	}

	ret_val = (*exch->callback)(port, found_ip, exch->user_data);
	remove_event(exch);  // Deletes all data structures allocated
	return ret_val;
}
