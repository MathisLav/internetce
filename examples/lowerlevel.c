/**
 *	Sends a DNS request to Google DNS server (8.8.8.8). Used features :
 *		- Listening a port.
 *		- Using callbacks.
 *		- Sending UDP datagrams.
 */


#include <internet.h>
#include <stdlib.h>
#include <string.h>

static bool ended = false;

void disp_hex(const void *addr, size_t len) {
	uint8_t *content = (uint8_t *)addr;
	for(size_t i = 0; i < len; i++) {
		if(i && i % 8 == 0) {
			printf("\n");
		}
		printf("%.2X ", *(content + i));
	}
	printf("\n");
}


usb_error_t dns_callback(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data) {
	(void)protocol; (void)length;
	msg_queue_t *queued = (msg_queue_t *)user_data;
	web_popMessage(queued);

	disp_hex(msg, length);
	while(!os_GetCSC()) {}

	web_UnlistenPort(port);
	ended = true;
	return USB_SUCCESS;
}


int main(void)
{
	os_ClrHome();
	printf("WEB Connection... ");
	
	web_Init();
	while(!web_Connected() && !os_GetCSC()) {
		web_WaitForEvents();
	}
	if(!web_Connected()) {
		printf("\nCanceled!\n");
		while(!os_GetCSC()) {}
		goto _end;
	}
	printf("Done!\n");

	/* Beginning of the DNS stuffs */
	const char url[] = "www.perdu.com";
	size_t length = sizeof(dns_message_t) + strlen(url) + 2 + 4; /* dns_message_t : CF internet.h */
	uint8_t *query = calloc(length, 1);

	query[2] = 0x01;
	query[5] = 0x01;

	/* formating address for dns purposes */
	char *cursor_qry = (char *)(query + sizeof(dns_message_t) + 1);
	const char *cursor_str = url;
	uint8_t i = 1;
	while(*cursor_str) {
		if(*cursor_str == '.') {
			*(cursor_qry - i) = i - 1;
			i = 0;
		} else
			*cursor_qry = *cursor_str;
		i++;
		cursor_str++;
		cursor_qry++;
	}
	*(cursor_qry - i) = i - 1;
	*cursor_qry = 0;
	*(cursor_qry + 2) = 1; /* A (IPv4) */
	*(cursor_qry + 4) = 1; /* IN (internet) */

	web_port_t client_port = web_RequestPort();
	msg_queue_t *queued = web_PushUDPDatagram(query, length, 0x08080808, client_port, DNS_PORT);
	free(query);
	web_ListenPort(client_port, dns_callback, queued);

	while(!os_GetCSC() && !ended) { // ended : global variable
		web_WaitForEvents();
	}

	_end:
	web_Cleanup();
	return 0;
}
