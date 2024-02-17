#include <internet.h>
#include <stdlib.h>
#include <string.h>

#include "include/dns.h"
#include "include/core.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

uint32_t web_SendDNSRequest(const char *url) {
	const uint32_t timeout = rtc_Time() + TIMEOUT_WEB;
	uint32_t res_ip = 0;
	dns_exchange_t *dns_exch = web_PushDNSRequest(url, &dns_callback, &res_ip);
	if(dns_exch != NULL) {
		while(!res_ip) {
			web_WaitForEvents();
			if(timeout <= rtc_Time()) {
				web_popMessage(dns_exch->queued_request);
				web_UnlistenPort(dns_exch->port_src);
				free(dns_exch);
				return 0xffffffff;
			}
		}
	}
	return res_ip;
}

dns_exchange_t *web_PushDNSRequest(const char *url, web_dns_callback_t *callback, web_callback_data_t *user_data) {
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
		return NULL;
	}
	web_port_t client_port = web_RequestPort();
	dns_exch->port_src = client_port;
	dns_exch->callback = callback;
	dns_exch->user_data = user_data;
	dns_exch->queued_request = web_PushUDPDatagram(query, length_data, netinfo.DNS_IP_addr, client_port, DNS_PORT);
	if(dns_exch->queued_request == NULL) {
		free(dns_exch);
		return NULL;
	}
	web_ListenPort(client_port, fetch_dns_msg, dns_exch);
	return dns_exch;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

web_status_t dns_callback(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data) {
	(void)port;
	*((uint32_t*)user_data) = res_ip;
	return WEB_SUCCESS;
}

web_status_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data){
	(void)port; (void)length; /* Unused parameters */
	if(protocol != UDP_PROTOCOL)
		return WEB_SUCCESS;

	dns_exchange_t *exch = (dns_exchange_t *)user_data;
	web_popMessage(exch->queued_request);
	web_UnlistenPort(port);

	const udp_datagram_t *udp_dtgm = (udp_datagram_t *)msg;
	if(htons(udp_dtgm->port_src) == DNS_PORT) {
		const dns_message_t *dns_msg = (dns_message_t*)((uint8_t*)udp_dtgm + sizeof(udp_datagram_t));

		/* if -> it isn't a response OR the recursion wasn't available OR an error occurred */
		if(!(dns_msg->flags & 0x8000) || !(dns_msg->flags & 0x0080) || (dns_msg->flags & 0x0F00)) {
			web_status_t ret_err = (*exch->callback)(port, 0xffffffff, exch->user_data);
			free(exch);
			return ret_err;
		}
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
		if(i == nb_answers) {
			web_status_t ret_err = (*exch->callback)(port, 0xffffffff, exch->user_data);
			free(exch);
			return ret_err;
		}

		ptr += 12;
		web_status_t ret_err = (*exch->callback)(port, *((uint32_t *)ptr), exch->user_data);
		free(exch);
		return ret_err;
	}

	free(exch);
	return WEB_SUCCESS;
}
