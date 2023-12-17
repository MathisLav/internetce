// #define DEBUG

#ifndef DEBUG
#define debug(...)
#define disp(...)
#define pause(...)
#define printf_xy(...)
#endif

#include "../include/internetstatic.h"
#include <tice.h>
#include <keypadc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <usbdrvce.h>
#include <fileioc.h>
#include <stdarg.h>


#ifdef DEBUG
void debug(const void *addr, size_t len);
void disp(unsigned int val);
void printf_xy(unsigned int xpos, unsigned int ypos, const char *txt);
#define pause() while(!os_GetCSC()) {}
#endif // DEBUG


/**
 * Global variables
 */
network_info_t netinfo;
static uint8_t MAC_ADDR[6] = {0xEA, 0xA5, 0x59, 0x9C, 0xC1, 0x1E};
static uint32_t IP_ADDR = 0;
static uint8_t *src_mac_addr; /* For dhcp purposes (we need to acknowledge the router's mac address) */
static http_data_list_t *http_data_list = NULL;
static msg_queue_t *send_queue = NULL;
static port_list_t *listened_ports = NULL;
static uint8_t msg_buffer[MAX_SEGMENT_SIZE+100];



/*******************************************************************************\
 * Pour la version 2.0 :
 *			 - Faire une version non-bloquante de send_http_request
 *				-> dans ce cas, pourquoi pas faire un système de http-callback ?
 *			 - Gérer TLS et donc HTTPS
 *			 - Gérer la fusion des packets ipv4 (= meilleures perfs)
 *			 - Si y'a moyen d'utiliser les interruptions USB (intce.h)...
\*******************************************************************************/


// Fait :		USB - RNDIS - Ethernet - IPv4 - UDP - DHCP - DNS - ARP - TCP - HTTP - ICMPv4
// Protocoles auxiliaires : TLS->HTTPS - IRC - SSH
// MORALE : NE PAS UTILISER DE USB_HANDLEEVENTS/WAITFOREVENTS/WAITFORINTERRUPTS DANS UN CALLBACK !!!! (donc usb_transfer non plus)
// MORALE : NE PAS UTILISER OS_PUTSTRFULL À OUTRANCE (FAUT PAS QUE ÇA SCROLLE)
// BUGS :
//	- www.fcstream.cc se charge que jusqu'à 14000 environ : surement un problème avec les chunks
//		-> Cause : les chunks sont en effet mal configurés par le serveur qui a l'air d'envoyer la taille du chunk + le "chunk header" (taille du chunk+2*0d0a)
//			Il semblerait que ça n'arrive pas quand on travaille en gzip : l'admin du site n'a pas du vérifier que le site marchait sur des vieux navigateurs.
//		-> Solution : Traiter le gzip : c'est pas pour tout de suite donc pour le moment je laisse ça comme ça
//
//	- Avant, après un transfert au niveau de web_LockData ça RC. Et du jour au lendemain plus (y'a juste eu un Garbage Collect entre)
//	- Des fois, le transfert (HTTP) s'arrête en plein milieu et la calc freeze (plus d'events/boucle infinie ?)
//	- Des fois, WLCE0000 n'est pas effacé



http_status_t web_HTTPGet(const char* url, http_data_t **data, bool keep_http_header) {
	char null_pointer = 0x00;
	return http_request("GET", url, data, keep_http_header, &null_pointer);
}

http_status_t web_HTTPPost(const char* url, http_data_t **data, bool keep_http_header, int nb_params, ...) {
	if(nb_params == 0) {
		char null_pointer = 0x00;
		return http_request("POST", url, data, keep_http_header, &null_pointer);
	}
	size_t param_len = 0;
	char *params = malloc(1); /* To be reallocated */
	va_list list_params;
	va_start(list_params, nb_params);
	for(uint8_t i=0; i<nb_params*2; i+=2) {
		const char *arg_name = va_arg(list_params, const char*);
		const char *arg_value = va_arg(list_params, const char*);
		void *tmp = realloc(params, param_len+strlen(arg_name)+strlen(arg_value)+4+1); /* +1 for 0 terminated string */
		if(!tmp) {
			free(params);
			return -1;
		}
		params = tmp;
		if(i) {
			sprintf(params+param_len, "&%s=%s", arg_name, arg_value);
			param_len += strlen(arg_name)+strlen(arg_value)+2;
		} else {
			sprintf(params+param_len, "%s=%s", arg_name, arg_value);
			param_len += strlen(arg_name)+strlen(arg_value)+1;
		}
	}
	va_end(list_params);

	char *add_req = malloc(param_len+16+12+49);
	sprintf(add_req, "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", param_len, params);

	http_status_t status = http_request("POST", url, data, keep_http_header, add_req);
	free(params);
	free(add_req);
	return status;
}

static http_status_t http_request(const char *request_type, const char* url, http_data_t **data, bool keep_http_header, char *params) {
	bool uri;
	const char *http_str = "http://";
	if(!memcmp(url, http_str, 7)) /* Ignoring http:// */
		url += 7;

	size_t websitelen = 0;
	while(*(url+websitelen) != '/' && *(url+websitelen) != 0x00)
		websitelen++;

	uri = (bool)*(url+websitelen); /* '/' or 0x00 ? */

	/* Formatting website name */
	char *websitename = malloc(websitelen+1);
	memcpy(websitename, url, websitelen);
	websitename[websitelen] = 0x00;

	/* Configuring request information */
	uint32_t ip = web_SendDNSRequest(websitename);
	http_exchange_t *exch = calloc(1, sizeof(http_exchange_t));
	exch->ip_dst = ip;
	if(exch->ip_dst == 0xffffffff)
		return DNS_ERROR;
	exch->port_src = web_RequestPort();
	exch->port_dst = HTTP_PORT;
	exch->cur_sn = random();
	exch->beg_sn = exch->cur_sn;
	exch->chunk_counter = 0xffffff;
	exch->data = data;
	exch->keep_http_header = keep_http_header;
	exch->timeout = rtc_Time() + TIMEOUT;

	/* Initiating connection */
	web_ListenPort(exch->port_src, fetch_http_msg, exch);
	const uint8_t options[] = {0x02, 0x04, MAX_SEGMENT_SIZE/256, MAX_SEGMENT_SIZE%256};
	add_tcp_queue(NULL, 0, exch, FLAG_TCP_SYN, sizeof(options), options);
	exch->cur_sn++;
	while(!exch->connected)
		web_WaitForEvents(); // Timeout ?
	web_WaitForEvents();

	/* Building HTTP request */
	size_t length = strlen(request_type) + 1 + !uri + 11 + 6 + strlen(url) + 4 + strlen(params); /* 10=" HTTP/1.1\r\n", 6="Host: ", 4="\r\n\r\n" */
	
	char *request = malloc(length+1);
	sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", request_type, uri ? url+websitelen : "/", websitename, params);	
	free(websitename);

	/* Sending HTTP request */
	add_tcp_queue(request, length, exch, FLAG_TCP_ACK|FLAG_TCP_PSH, 0, NULL);
	free(request);

	/* Waiting for the end of the request */
	while(!exch->status) {
		web_WaitForEvents();
		if(exch->timeout <= rtc_Time()) {
			web_UnlistenPort(exch->port_src);
			wipe_data(exch);
			free(exch);
			return SYSTEM_TIMEOUT;
		}
	}
	http_status_t status = exch->status;

	add_tcp_queue(NULL, 0, exch, FLAG_TCP_FIN|FLAG_TCP_ACK, 0, NULL);
	exch->fin_sent = true;
	web_WaitForEvents();
	return status;
}

static void add_tcp_queue(char *data, size_t length, http_exchange_t *exchange, uint16_t flags, size_t opt_size, const uint8_t *options) {
	/**
	 *	- Add segment to send_queue (call web_PushTCPSegment)
	 *	- Add segment to http queue (http_exchange_t pushed_seg field)
	 *	- Increase the sequence number
	 */
	msg_queue_t *queued = web_PushTCPSegment(data, length, exchange->ip_dst, exchange->port_src, exchange->port_dst, exchange->cur_sn, exchange->cur_ackn, flags, opt_size, options);
	exchange->cur_sn += length;
	pushed_seg_list_t *new_seg = malloc(sizeof(pushed_seg_list_t));
	new_seg->relative_sn = (exchange->cur_sn) - exchange->beg_sn;
	new_seg->seg = queued;
	new_seg->next = exchange->pushed_seg;
	exchange->pushed_seg = new_seg;
}

static void fetch_ack(http_exchange_t *exchange, uint32_t ackn) {
	/**
	 *	Unofficial name: remove_tcp_segments_that_are_acked_by_ackn
	 *	Note: The segments in pushed_seg list are in descending order.
	 */
	pushed_seg_list_t *cur_seg = exchange->pushed_seg;
	pushed_seg_list_t *prev_seg = NULL;
	while(cur_seg && cur_seg->relative_sn > ackn-exchange->beg_sn) {
		prev_seg = cur_seg;
		cur_seg = cur_seg->next;
	}

	if(!cur_seg)
		return;

	pushed_seg_list_t *next_seg = NULL;
	if(prev_seg)
		prev_seg->next = NULL;
	else
		exchange->pushed_seg = NULL;

	while(cur_seg) {
		next_seg = cur_seg->next;
		web_popMessage(cur_seg->seg);
		free(cur_seg);
		cur_seg = next_seg;
	}

	exchange->relative_seqacked = ackn-exchange->beg_sn;
}

static usb_error_t fetch_http_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data) {
	(void)port; /* Unused parameter */
	if(protocol != TCP_PROTOCOL)
		return USB_IGNORE;
	const tcp_segment_t *tcp_seg = (tcp_segment_t*)msg;
	http_exchange_t *exch = (http_exchange_t*)user_data;

	exch->timeout = rtc_Time() + TIMEOUT;

	/* If SYN */
	if(tcp_seg->dataOffset_flags&0x0200) {
		exch->beg_ackn = getBigEndianValue((uint8_t*)&tcp_seg->seq_number)+1;
		exch->cur_ackn = exch->beg_ackn;
		exch->connected = true;
		web_SendTCPSegment(NULL, 0, exch->ip_dst, exch->port_src, exch->port_dst, exch->cur_sn, exch->cur_ackn, FLAG_TCP_ACK, 0, NULL);
	}

	/* If ACK */
	const uint32_t ack_number = getBigEndianValue((uint8_t*)&tcp_seg->ack_number);
	if(ack_number-exch->beg_sn > exch->relative_seqacked && tcp_seg->dataOffset_flags&0x1000) {
		fetch_ack(exch, ack_number);
		if(!exch->connected && exch->fin_sent) {
			web_UnlistenPort(exch->port_src);
			free(exch);
		}
	}

	/* If FIN */
	if(tcp_seg->dataOffset_flags&0x0100) {
		exch->connected = false;
		if(exch->fin_sent) {
			web_SendTCPSegment(NULL, 0, exch->ip_dst, exch->port_src, exch->port_dst, exch->cur_sn, exch->cur_ackn, FLAG_TCP_ACK, 0, NULL);
			web_UnlistenPort(exch->port_src);
			free(exch);
		} else {
			add_tcp_queue(NULL, 0, exch, FLAG_TCP_FIN|FLAG_TCP_ACK, 0, NULL);
			exch->fin_sent = true;
		}
		return USB_SUCCESS;
	}

	const char *payload_response = (char*)msg + 4*(((tcp_segment_t*)msg)->dataOffset_flags>>4&0x0f);
	if((char*)msg+length == payload_response) /* If there's no payload */
		return USB_SUCCESS;

	tcp_segment_t *response = malloc(length); /* The MAX_SEGMENT_SIZE does not take into account the TCP header (which is at most 0x40 bytes */
	if(!response) {
		wipe_data(exch);
		exch->status = SYSTEM_NOT_ENOUGH_MEM;
		return USB_ERROR_NO_MEMORY;
	}
	memcpy(response, msg, length);

	/* First process : chaining data */
	tcp_segment_list_t *new_segment_list = malloc(sizeof(tcp_segment_list_t));
	if(!new_segment_list) {
		wipe_data(exch);
		exch->status = SYSTEM_NOT_ENOUGH_MEM;
		return USB_ERROR_NO_MEMORY;
	}

	new_segment_list->relative_sn = getBigEndianValue((uint8_t*)&response->seq_number)-exch->beg_ackn;
	new_segment_list->pl_length = length - 4*(response->dataOffset_flags>>4&0x0f);
	new_segment_list->segment = response;

	if(!exch->segment_list) {
		new_segment_list->next = NULL;
		exch->segment_list = new_segment_list;
		exch->content_received += new_segment_list->pl_length;
	} else {
		tcp_segment_list_t *cur_el = exch->segment_list;
		tcp_segment_list_t *prev_el = NULL;
		while(cur_el && cur_el->relative_sn < new_segment_list->relative_sn) {
			prev_el = cur_el;
			cur_el = cur_el->next;
		}
		if(cur_el && cur_el->relative_sn == new_segment_list->relative_sn) { /* deja vue */
			web_SendTCPSegment(NULL, 0, exch->ip_dst, exch->port_src, exch->port_dst, exch->cur_sn, exch->cur_ackn, FLAG_TCP_ACK, 0, NULL);
			return USB_SUCCESS;
		} else {
			new_segment_list->next = cur_el;
			if(prev_el)
				prev_el->next = new_segment_list;
			else
				exch->segment_list = new_segment_list;
			exch->content_received += new_segment_list->pl_length;
		}
	}

	/* Second process : acking data */
	if(exch->segment_list->relative_sn != 0) /* If we haven't received the first segment yet... */
		return USB_SUCCESS;

	tcp_segment_list_t *cur_el = exch->segment_list;
	while(cur_el->next && cur_el->relative_sn+cur_el->pl_length == cur_el->next->relative_sn)
		cur_el = cur_el->next;
	if(exch->cur_ackn-exch->beg_ackn != cur_el->relative_sn+cur_el->pl_length) {
		exch->cur_ackn = exch->beg_ackn + cur_el->relative_sn + cur_el->pl_length;
		web_SendTCPSegment(NULL, 0, exch->ip_dst, exch->port_src, exch->port_dst, exch->cur_sn, exch->cur_ackn, FLAG_TCP_ACK, 0, NULL);
	}

	/* Third process : trying to find what the Content-Length value is */
	if(!exch->header_length && exch->ackn_next_header_segment == new_segment_list->relative_sn) {
		tcp_segment_list_t *cur_seg_list = new_segment_list;
		tcp_segment_t *seg_processing;
		char *payload_processing;

		third_process:

		seg_processing = new_segment_list->segment;
		payload_processing = (char*)seg_processing + 4*(seg_processing->dataOffset_flags>>4&0x0f);

		/* Searching for the Content-Length or Transfer-Encoding fields */
		const char *ptr = payload_processing;
		const char cont_len[] = "Content-Length:";
		const char cont_enc[] = "Transfer-Encoding: chunked\r\n";
		while(*((uint32_t*)ptr) != 0x0a0d0a0d && ptr-(char*)seg_processing<(int)length) {
			ptr += 2;
			if(!memcmp(ptr, cont_len, 15)) { /* If we found it, we update the content_length value */
				ptr += 15;
				while(*ptr == ' ') ptr++; /* Ignoring whitespaces */
				while(*ptr >= 0x30 && *ptr <= 0x39) {
					exch->content_length = exch->content_length*10 + (*ptr-0x30);
					ptr++;
				}
			} else if(!memcmp(ptr, cont_enc, 28))
				exch->data_chunked = true;
			while(ptr-(char*)seg_processing<(int)length && (*ptr != 0x0d || *(ptr+1) != 0x0a)) ptr++;
		}
		/* If the payload is more large than we can handle, returning. */
		if(exch->content_length>OS_VAR_MAX_SIZE) {
			wipe_data(exch);
			exch->status = SYSTEM_NOT_ENOUGH_MEM;
			return USB_ERROR_NO_MEMORY;
		}

		if(ptr-(char*)seg_processing>=(int)length) {
			/* If we came at the end of the segment without reaching the end of the HTTP Header... */
			exch->ackn_next_header_segment += cur_seg_list->pl_length;
			if(cur_seg_list->next && cur_seg_list->relative_sn+cur_seg_list->pl_length == cur_seg_list->next->relative_sn) {
				cur_seg_list = cur_seg_list->next;
				goto third_process;
			} else
				return USB_SUCCESS;
		}
		ptr += 4;
		exch->header_length = exch->ackn_next_header_segment + (ptr-payload_processing);
		if(!exch->data_chunked)
			exch->content_length += exch->header_length;
		else /* Cheating a little bit (by considering that the header is a chunk) */
			exch->chunk_counter = (cur_seg_list->relative_sn - new_segment_list->relative_sn) + (ptr - payload_processing);
	}

	/* Fourth process : if the content is chunked... */
	if(exch->chunk_counter != 0xffffff && exch->cur_ackn-exch->beg_ackn == new_segment_list->relative_sn+new_segment_list->pl_length) {
		tcp_segment_list_t *cur_seg_list = new_segment_list;
		tcp_segment_t *seg_processing;
		const char *payload_processing;

		fourth_process:
		seg_processing = new_segment_list->segment;
		payload_processing = (const char*)seg_processing + 4*(seg_processing->dataOffset_flags>>4&0x0f);

		if(cur_seg_list->pl_length <= exch->chunk_counter)
			exch->chunk_counter -= cur_seg_list->pl_length;
		else {
			const char *ptr = payload_processing;

			recursive_chunk:
			ptr += exch->chunk_counter;
			exch->chunk_counter = getChunkSize(&ptr)+4;

			if(exch->chunk_counter == 4)
				goto end_http_message;

			if(cur_seg_list->pl_length - (ptr-payload_processing) <= exch->chunk_counter)
				exch->chunk_counter -= cur_seg_list->pl_length - (ptr-payload_processing);
			else
				goto recursive_chunk; /* There is another chunk in the same tcp segment */
		}
			
		if(cur_seg_list->next && cur_seg_list->relative_sn+cur_seg_list->pl_length == cur_seg_list->next->relative_sn) {
			cur_seg_list = cur_seg_list->next;
			goto fourth_process;
		}
	}

	if(!exch->content_length || (exch->content_length && exch->content_length>exch->content_received))
		return USB_SUCCESS;

	end_http_message:

	/* We store the data in an appvar, in order to relieve the heap */
	if(exch->content_received > OS_VAR_MAX_SIZE) {
		wipe_data(exch);
		exch->status = SYSTEM_NOT_ENOUGH_MEM;
		return USB_ERROR_NO_MEMORY;
	}
	http_data_list_t *new_http_data_el = calloc(1, sizeof(http_data_list_t));
	char varstorage_name[9] = "WLCE0000";
	/* Trying to find a name that is not already in used */
	uint16_t n=0;
	while(n<9999 && os_ChkFindSym(OS_TYPE_APPVAR, varstorage_name, NULL, NULL)) {
		n++;
		varstorage_name[7] = (n%10)+'0';
		varstorage_name[6] = (n/10)+'0';
		varstorage_name[5] = (n/100)+'0';
		varstorage_name[4] = (n/1000)+'0';
	}
	if(n>=9999) {
		wipe_data(exch);
		free(new_http_data_el);
		exch->status = SYSTEM_NOT_ENOUGH_MEM;
		return USB_ERROR_NO_MEMORY;
	}
	*exch->data = os_CreateAppVar(varstorage_name, exch->content_received);
	if(!(*exch->data)) {
		wipe_data(exch);
		free(new_http_data_el);
		exch->status = SYSTEM_NOT_ENOUGH_MEM;
		return USB_ERROR_NO_MEMORY;
	}

	tcp_segment_list_t *cur_seg = exch->segment_list;
	tcp_segment_list_t *next_seg = NULL;
	size_t cur_size = 0;
	while(cur_seg) {
		next_seg = cur_seg->next;
		memcpy((*exch->data)->data+cur_size, (uint8_t*)cur_seg->segment+4*(cur_seg->segment->dataOffset_flags>>4&0x0f), cur_seg->pl_length);
		cur_size += cur_seg->pl_length;
		free(cur_seg->segment);
		free(cur_seg);
		cur_seg = next_seg;
	}

	/* HTTP status */
	exch->status = (((char*)*exch->data)[11]-'0')*100 + (((char*)*exch->data)[12]-'0')*10 + (((char*)*exch->data)[13]-'0');

	/* Removing header (if keep_http_header==false) and removing chunks info (if data_chunked==true) */
	uint16_t new_size = (*exch->data)->size;
	if(exch->data_chunked) {
		char *ptr = (char*)(*exch->data)->data;
		char *before_ptr = ptr;
		uint16_t chunk_size = exch->header_length;
		do {
			ptr += chunk_size;
			before_ptr += chunk_size;
			chunk_size = getChunkSize((const char**)&ptr);
			ptr += 2;
			memcpy(before_ptr, ptr, (char*)(*exch->data)->data+new_size-ptr);
			new_size -= ptr-before_ptr;
			ptr = before_ptr+2;

		} while(chunk_size);
	}
	if(!exch->keep_http_header) {
		new_size -= exch->header_length;
		memcpy((*exch->data)->data, (*exch->data)->data+exch->header_length, new_size);
	}

	ResizeAppVar(varstorage_name, new_size);

	/* Chaining... */
	strncpy(new_http_data_el->varname, varstorage_name, 9);
	if(http_data_list)
		new_http_data_el->next = http_data_list;
	http_data_list = new_http_data_el;

	web_LockData(exch->data);
	return USB_SUCCESS;
}

static void wipe_data(http_exchange_t *exch) {
	tcp_segment_list_t *cur_seg = exch->segment_list;
	tcp_segment_list_t *next_seg = NULL;
	while(cur_seg) {
		next_seg = cur_seg->next;
		free(cur_seg->segment);
		free(cur_seg);
		cur_seg = next_seg;
	}
}


int web_UnlockData(http_data_t **http_data) {
	if(!os_EnoughMem((*http_data)->size))
		return 0;

	void *cur_entry = os_GetSymTablePtr();
	uint24_t type;
	char name[9];
	void *data = NULL;
	while(cur_entry && *http_data != data)
		cur_entry = os_NextSymEntry(cur_entry, &type, NULL, name, &data);

	if(!cur_entry)
		return 0;

	http_data_t *tmp;
	tmp = MoveToRam(name);
	if(tmp)
		*http_data = tmp;
	return 1;
}

int web_LockData(http_data_t **http_data) {
	os_ArcChk();
	if((*http_data)->size >= os_TempFreeArc)
		return 0;

	void *cur_entry = os_GetSymTablePtr();
	char name[9];
	void *data = NULL;
	while(cur_entry && *http_data != data)
		cur_entry = os_NextSymEntry(cur_entry, NULL, NULL, name, &data);

	if(*http_data!=data)
		return 0;

	http_data_t *tmp;
	tmp = MoveToArc(name);

	if(tmp)
		*http_data = (http_data_t*)((char*)tmp+18);
	return 1;
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


void web_SendARPQuery(uint32_t ip) {
	eth_frame_t *frame = calloc(1, sizeof(eth_frame_t)-4 + sizeof(arp_message_t));
	arp_message_t *arp_msg = (arp_message_t*)((uint8_t*)frame+sizeof(eth_frame_t)-4);
	memset(frame->MAC_dst, 0xff, 6);
	memcpy((uint8_t*)frame->MAC_src, MAC_ADDR, 6);
	arp_msg->IP_dst = ip;
	memcpy((uint8_t*)arp_msg->MAC_src, MAC_ADDR, 6);
	arp_msg->IP_src = IP_ADDR;
	arp_msg->Operation = 0x0100;
	web_SendRNDISPacket((uint8_t*)arp_msg, sizeof(eth_frame_t)-4 + sizeof(arp_message_t));
	free(frame);
}

uint32_t web_SendDNSRequest(const char *url) {
	uint32_t res_ip = 0;
	web_ScheduleDNSRequest(url, &dns_callback, &res_ip);
	while(!res_ip)
		web_WaitForEvents();
	web_UnlistenPort(DNS_PORT);
	return res_ip;
}

static usb_error_t dns_callback(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data) {
	(void)port;
	*((uint32_t*)user_data) = res_ip;
	return (res_ip!=0xffffffff)*USB_ERROR_FAILED;
}

void web_ScheduleDNSRequest(const char *url, web_dns_callback_t *callback, web_callback_data_t *user_data) {
	/* Returns -1 or error */
	size_t length = sizeof(dns_message_t)+strlen(url)+2+4; /* 2=length byte at the begining of the string+0 terminated string */
	uint8_t *query = calloc(length, 1);

	query[2] = 0x01;
	query[5] = 0x01;

	/* formating address for dns purposes */
	char *cursor_qry = (char*)(query+sizeof(dns_message_t)+1);
	char *cursor_str = (char*)url;
	uint8_t i = 1;
	while(*cursor_str) {
		if(*cursor_str == '.') {
			*(cursor_qry-i) = i-1;
			i = 0;
		} else
			*cursor_qry = *cursor_str;
		i++;
		cursor_str++;
		cursor_qry++;
	}
	*(cursor_qry-i) = i-1;
	*cursor_qry = 0;
	*(cursor_qry+2) = 1; /* A (IPv4) */
	*(cursor_qry+4) = 1; /* IN (internet) */

	web_port_t client_port = web_RequestPort();
	dns_exchange_t *dns_exch = malloc(sizeof(dns_exchange_t));
	dns_exch->callback = callback;
	dns_exch->user_data = user_data;
	dns_exch->queued_request = web_PushUDPDatagram(query, length, netinfo.DNS_IP_addr, client_port, DNS_PORT);
	free(query);

	web_ListenPort(client_port, fetch_dns_msg, dns_exch);
}

static usb_error_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data) {
	(void)port; (void)length; /* Unused parameters */
	if(protocol != UDP_PROTOCOL)
		return USB_IGNORE;
	dns_exchange_t *exch = (dns_exchange_t*)user_data;
	web_popMessage(exch->queued_request);

	const udp_datagram_t *udp_dtgm = (udp_datagram_t*)msg;
	if(udp_dtgm->port_src/256 == DNS_PORT && udp_dtgm->port_src%256 == 0x00) {
		const dns_message_t *dns_msg = (dns_message_t*)((uint8_t*)udp_dtgm + sizeof(udp_datagram_t));

		if(!(dns_msg->flags&0x8000) || !(dns_msg->flags&0x0080) || (dns_msg->flags&0x0F00)) { /* if -> it isn't a response OR the recursion wasn't available OR an error occurred */
			usb_error_t ret_err = (*exch->callback)(port, 0xffffffff, exch->user_data);
			free(exch);
			return ret_err;
		}
		const uint8_t nb_answers = dns_msg->answerRRs>>8;
		const uint8_t nb_queries = dns_msg->questions>>8;

		const uint8_t *ptr = (uint8_t*)dns_msg + sizeof(dns_message_t);
		for(int i=0; i<nb_queries; i++) {
			while(*(ptr++)) {}
			ptr += 4;
		}

		int i = 0;
		while(i < nb_answers && (*((uint16_t*)(ptr+2)) != 0x0100 || *((uint16_t*)(ptr+4)) != 0x0100)) {
			ptr += 11;
			ptr += *ptr + 1;
			i++;
		}
		if(i == nb_answers) {
			usb_error_t ret_err = (*exch->callback)(port, 0xffffffff, exch->user_data);
			free(exch);
			return ret_err;
		}

		ptr += 12;
		usb_error_t ret_err = (*exch->callback)(port, *((uint32_t*)ptr), exch->user_data);
		free(exch);
		return ret_err;
	}

	free(exch);
	return USB_IGNORE;
}

static msg_queue_t *dhcp_last_queued_msg = NULL;
static uint8_t phase = 0; /* 0=not initiated, 1=discover sent, 2=request sent, 3=done */
static void dhcp_init() {
	/* DHCP DISCOVERY */
	static uint32_t xid = 0x03F82639;
	if(phase != 0) /* if an init() is already running */
		return;

	web_ListenPort(CLIENT_DHCP_PORT, fetch_dhcp_msg, NULL);
	const uint8_t beg_header[] = {0x01, 0x01, 0x06, 0x00};
	const uint8_t options_disc[] = {53, 1, 1, 0x37, 3, 1, 3, 6, 0xFF, 0};
	const size_t length_disc = sizeof(dhcp_message_t)+sizeof(options_disc);
	uint8_t *data_disc = calloc(length_disc, 1);
	memcpy(data_disc, &beg_header, 4);
	((uint32_t*)data_disc)[1] = xid;
	memcpy(data_disc+28, &MAC_ADDR, 6);
	((uint32_t*)data_disc)[59] = 0x63538263;
	memcpy(data_disc+240, &options_disc, sizeof(options_disc));

	dhcp_last_queued_msg = web_PushUDPDatagram(data_disc, length_disc, 0xffffffff, CLIENT_DHCP_PORT, SERVER_DHCP_PORT);
	free(data_disc);
	phase = 1;
	xid++;
}

static usb_error_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data) {
	(void)port; (void)length; (void)user_data; /* Unused parameters */

	if(protocol != UDP_PROTOCOL)
		return USB_IGNORE;

	const dhcp_message_t *dhcp_msg = (dhcp_message_t*)((uint8_t*)msg+sizeof(udp_datagram_t));

	if(dhcp_msg->op == 0x02) {
		netinfo.DHCP_IP_addr = dhcp_msg->siaddr;
		const uint8_t *cur_opt = (uint8_t*)((uint8_t*)dhcp_msg+sizeof(dhcp_message_t));
		while(*cur_opt != 0xFF) {
			switch(*cur_opt) {
				case 53: /* DHCP message type */
					if(*(cur_opt+2) == 2 && phase == 1) { /* DHCP Offer */
						web_popMessage(dhcp_last_queued_msg);
						const uint8_t beg_header[] = {0x01, 0x01, 0x06, 0x00};
						const uint8_t options_req[] = {53, 1, 3, 0x37, 3, 1, 3, 6, 54, 4, 0, 0, 0, 0, 50, 4, 0, 0, 0, 0, 0xFF};
						const size_t length_req = sizeof(dhcp_message_t)+21; /*1=0xFF, 20=options */
						uint8_t *data_req = calloc(length_req, 1);
						memcpy(data_req, &beg_header, 4);
						((uint32_t*)data_req)[1] = dhcp_msg->xid;
						memcpy(data_req+28, &MAC_ADDR, 6);
						((uint32_t*)data_req)[59] = 0x63538263;
						memcpy(data_req+240, &options_req, 21);
						((uint32_t*)(data_req+2))[62] = netinfo.DHCP_IP_addr;
						((uint32_t*)data_req)[64] = dhcp_msg->yiaddr;
						dhcp_last_queued_msg = web_PushUDPDatagram(data_req, length_req, 0xffffffff, CLIENT_DHCP_PORT, SERVER_DHCP_PORT);
						phase = 2;
					} else if(*(cur_opt+2) == 5 && phase == 2) { /* ACK */
						web_popMessage(dhcp_last_queued_msg);
						dhcp_last_queued_msg = NULL;
						IP_ADDR = dhcp_msg->yiaddr;
						memcpy(netinfo.router_MAC_addr, src_mac_addr, 6);
						phase = 3;
						netinfo.state = STATE_NETWORK_CONFIGURED;
						/* TODO: unlisten DHCP port? Or keep listening it for possible information packets? */
					} else if(*(cur_opt+2) == 6) { /* NACK */
						if(dhcp_last_queued_msg) {
							web_popMessage(dhcp_last_queued_msg);
							dhcp_last_queued_msg = NULL;
						}
						phase = 0;
						web_UnlistenPort(CLIENT_DHCP_PORT);
						dhcp_init();
						return USB_ERROR_FAILED;
					}
					break;
				case 6: /* DNS SERVER */
					netinfo.DNS_IP_addr = *((uint32_t*)(cur_opt+2)); /* we only take the first entry */
					break;
				case 58: /* T1 Lease time */
					//t1_leasetime = rtc_Time() + getBigEndianValue(cur_opt+2);
					break;
				default:
					break;
			}
			cur_opt += *(cur_opt+1)+2;
		}
	}
	return USB_SUCCESS;
}


usb_error_t web_SendTCPSegment(char *data, size_t length, uint32_t ip_dst, web_port_t port_src, web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options) {
	msg_queue_t *queued = web_PushTCPSegment(data, length, ip_dst, port_src, port_dst, seq_number, ack_number, flags, opt_size, options);
	queued->waitingTime += 100; /* We don't want the segment to be sent as a "repeated segment" */
	return usb_ScheduleTransfer(queued->endpoint, queued->msg, queued->length, send_callback, queued);
}

static usb_error_t send_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data) {
	(void)endpoint; (void)status; (void)transferred; /* Unused parameters */
	web_popMessage((msg_queue_t*)data);
	return USB_SUCCESS;
}

msg_queue_t *web_PushTCPSegment(char *data, size_t length, uint32_t ip_dst, web_port_t port_src, web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options) {
	uint8_t *tcp_seg = calloc(length+sizeof(tcp_segment_t), 1);
	tcp_seg[0] = port_src/256;
	tcp_seg[1] = port_src%256;
	tcp_seg[2] = port_dst/256;
	tcp_seg[3] = port_dst%256;
	tcp_seg[4] = seq_number/16777216;
	tcp_seg[5] = seq_number/65536;
	tcp_seg[6] = seq_number/256;
	tcp_seg[7] = seq_number%256;
	tcp_seg[8] = ack_number/16777216;
	tcp_seg[9] = ack_number/65536;
	tcp_seg[10] = ack_number/256;
	tcp_seg[11] = ack_number%256;
	tcp_seg[12] = ((sizeof(tcp_segment_t)+opt_size)*4)|(flags&0x0100);
	tcp_seg[13] = flags&0x00FF;
	tcp_seg[14] = TCP_WINDOW_SIZE/256;	/* window size */
	tcp_seg[15] = TCP_WINDOW_SIZE%256;

	if(options)
		memcpy(tcp_seg+sizeof(tcp_segment_t), options, opt_size);
	if(length)
		memcpy(tcp_seg+sizeof(tcp_segment_t)+opt_size, data, length);

	uint16_t chksm = transport_checksum(tcp_seg, length+sizeof(tcp_segment_t)+opt_size, IP_ADDR, ip_dst, TCP_PROTOCOL);
	tcp_seg[16] = chksm/256;
	tcp_seg[17] = chksm%256;

	msg_queue_t *queued = web_PushIPv4Packet(tcp_seg, length+sizeof(tcp_segment_t)+opt_size, IP_ADDR, ip_dst, TCP_PROTOCOL);
	free(tcp_seg);
	return queued;
}

static uint16_t transport_checksum(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol) {
	uint16_t chksmmsb = length/256 + (ip_dst/65536&0xff) + (ip_dst&0xff) + (ip_src/65536&0xff) + (ip_src&0xff);
	uint16_t chksmlsb = protocol + length%256 + (ip_dst/16777216&0xff) + (ip_dst/256&0xff) + (ip_src/16777216&0xff) + (ip_src/256&0xff);
	for(size_t i=0; i<length-1; i+=2) {
		chksmmsb += data[i];
		chksmlsb += data[i+1];
	}
	if(length%2)
		chksmmsb += data[length-1];
	chksmmsb += chksmlsb>>8;
	chksmlsb += chksmmsb>>8;
	return ~((chksmmsb<<8)+(chksmlsb&0x00FF));
}


msg_queue_t *web_PushUDPDatagram(uint8_t *data, size_t length, uint32_t ip_dst, web_port_t port_src, web_port_t port_dst) {
	uint8_t *datagram = malloc(length+sizeof(udp_datagram_t));
	datagram[0] = port_src/256;
	datagram[1] = port_src%256;
	datagram[2] = port_dst/256;
	datagram[3] = port_dst%256;
	datagram[4] = (length+sizeof(udp_datagram_t))/256;
	datagram[5] = (length+sizeof(udp_datagram_t))%256;
	datagram[6] = 0;
	datagram[7] = 0;
	memcpy(datagram+sizeof(udp_datagram_t), data, length);
	uint16_t chksm = transport_checksum(datagram, length+sizeof(udp_datagram_t), IP_ADDR, ip_dst, UDP_PROTOCOL);
	datagram[6] = chksm/256;
	datagram[7] = chksm%256;
	
	msg_queue_t *queued = web_PushIPv4Packet(datagram, length+sizeof(udp_datagram_t), IP_ADDR, ip_dst, UDP_PROTOCOL);
	free(datagram);

	return queued;
}


msg_queue_t *web_PushIPv4Packet(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol) {
	static uint16_t nbpacket = 0;
	const size_t size = length+sizeof(ipv4_packet_t);
	const ipv4_packet_t packet = {0x45, 0, 0, 0, 0x40, 0x80, 0, 0, 0, 0};
	uint8_t *ipv4_pckt = malloc(size);
	memcpy(ipv4_pckt, &packet, sizeof(ipv4_packet_t));
	ipv4_pckt[2] = size/256;
	ipv4_pckt[3] = size%256;
	ipv4_pckt[4] = nbpacket/256;
	ipv4_pckt[5] = nbpacket%256;
	ipv4_pckt[9] = protocol;
	((uint32_t*)ipv4_pckt)[3] = ip_src;
	((uint32_t*)ipv4_pckt)[4] = ip_dst;
	uint16_t chksm = ipv4_checksum((uint16_t*)ipv4_pckt, sizeof(ipv4_packet_t));
	ipv4_pckt[10] = chksm%256;
	ipv4_pckt[11] = chksm/256;
	memcpy(ipv4_pckt+sizeof(ipv4_packet_t), data, length);
	nbpacket++;

	msg_queue_t *queued = web_PushEthernetFrame(ipv4_pckt, size, ETH_IPV4);
	free(ipv4_pckt);

	return queued;
 }

static uint16_t ipv4_checksum(uint16_t *header, size_t length) {
	uint24_t sum = 0;
	for(size_t i=0; i<length/2; i++) 
		sum += header[i];
	return (uint16_t)~(sum+(sum >> 16));
}


msg_queue_t *web_PushEthernetFrame(uint8_t *data, size_t length, uint16_t protocol) {
	uint8_t *frame; 
	if(length<46) /* An ethernet frame must be at least 64B */
		frame = calloc(64, 1);
	else
		frame = malloc(sizeof(eth_frame_t)+length);
	memcpy(frame, netinfo.router_MAC_addr, 6);
	memcpy(frame+6, MAC_ADDR, 6);
	((uint16_t*)frame)[6] = protocol;
	memcpy(frame+sizeof(eth_frame_t)-4, data, length);
	if(length<46)
		length = 64;
	else
		length += sizeof(eth_frame_t);
	uint32_t crc = crc32b(frame, length-4);
	memcpy(frame+length-4, &crc, 4);

	msg_queue_t *queued = web_PushRNDISPacket(frame, length);
	free(frame);

	return queued;
}

#define CRC_POLY 0xEDB88320
static uint32_t crc32b(uint8_t *data, size_t length) {
	/**
	 *	Computes ethernet crc32.
	 *	Code found on stackoverflow.com (no licence was given to the code)
	 */
	// LES BOUCLES IMBRIQUEES FREEZENT AVEC LA TOOLCHAIN
    uint32_t crc;
	size_t j;

    if(!data || !length)
        return 0;
    crc = 0xFFFFFFFF;
    for(j = 0; j < length; j++) {
        crc ^= data[j];
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
    }
    return ~crc;
}


msg_queue_t *web_PushRNDISPacket(uint8_t *data, size_t length) {
	uint8_t *pckt = malloc(sizeof(rndis_packet_msg_t)+length);
	memset(pckt, 0, sizeof(rndis_packet_msg_t));
	pckt[0] = RNDIS_PACKET_MSG;
	pckt[4] = (sizeof(rndis_packet_msg_t)+length)%256;
	pckt[5] = (sizeof(rndis_packet_msg_t)+length)/256;
	pckt[8] = 36;
	pckt[12] = length%256;
	pckt[13] = length/256;
	memcpy(pckt+sizeof(rndis_packet_msg_t), data, length);

	return web_pushMessage(pckt, length+sizeof(rndis_packet_msg_t), usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc_out), packets_callback, NULL);
}

usb_error_t web_SendRNDISPacket(uint8_t *data, size_t length) {
	uint8_t *pckt = malloc(sizeof(rndis_packet_msg_t)+length);
	memset(pckt, 0, sizeof(rndis_packet_msg_t));
	pckt[0] = RNDIS_PACKET_MSG;
	pckt[4] = (sizeof(rndis_packet_msg_t)+length)%256;
	pckt[5] = (sizeof(rndis_packet_msg_t)+length)/256;
	pckt[8] = 36;
	pckt[12] = length%256;
	pckt[13] = length/256;
	memcpy(pckt+sizeof(rndis_packet_msg_t), data, length);

	return usb_ScheduleTransfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc_out), pckt, length+sizeof(rndis_packet_msg_t), send_rndis_callback, pckt);
}

static usb_error_t send_rndis_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data) {
	(void)endpoint; (void)status; (void)transferred; /* Unused parameters */
	free(data);
	return USB_SUCCESS;
}


void web_Init() {
	netinfo.ep_wc_in = 0;
	netinfo.ep_cdc_in = 0;
	netinfo.ep_cdc_out = 0;
	netinfo.state = STATE_UNKNOWN;
	netinfo.device = NULL;
	usb_Init(usbHandler, NULL, NULL, USB_DEFAULT_INIT_FLAGS);
	memset(&(netinfo.router_MAC_addr), 0xFF, 6);
	srand(rtc_Time());
	MAC_ADDR[5] = randInt(0, 0xFF);
}


static size_t getChunkSize(const char **ascii) {
	/**
	 *	Considering this is a correct chunk size :
	 *	-> 0x0a0d terminated
	 *	-> which is only a combination of 0123456789abcdefABCDEF
	 */
	size_t size = 0;
	while(**ascii != 0x0d) {
		if(**ascii <= '9')
			size = size*16 + (**ascii - '0');
		else if(**ascii <= 'F')
			size = size*16 + 10+(**ascii - 'A');
		else
			size = size*16 + 10+(**ascii - 'a');
		(*ascii)++;
	}
	return size;
}

static bool cmpbroadcast(const uint8_t *mac_addr) {
	bool is_brdcst = true;
	for(int i=0; i<6; i++)
		is_brdcst = is_brdcst && *(mac_addr+i)==0xff;
	return is_brdcst;
}

static uint32_t getBigEndianValue(uint8_t *beVal) {
	return beVal[0]*16777216 + beVal[1]*65536 + beVal[2]*256 + beVal[3];
}

uint32_t web_getMyIPAddr() {
	return IP_ADDR;
}

bool web_Connected() {
	return netinfo.state == STATE_NETWORK_CONFIGURED;
}

usb_error_t web_WaitForEvents() {
	msg_queue_t *cur_msg = send_queue;
	uint8_t *fetched = msg_buffer;
	const uint32_t beg_time = rtc_Time();
	usb_error_t err;

	if(netinfo.state == STATE_USB_LOST) {
		web_Cleanup();
		web_Init();
	}
	
	if(netinfo.state == STATE_USB_ENABLED) {
		if(configure_usb_device() == USB_SUCCESS) {
			netinfo.state = STATE_DHCP_CONFIGURING;
			dhcp_init();
		} else {
			netinfo.state = STATE_UNKNOWN;
		}
	}

	if(netinfo.state <= STATE_USB_ENABLED) {
		return usb_HandleEvents();
	}

	err = usb_ScheduleTransfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc_in), msg_buffer, MAX_SEGMENT_SIZE + 100, packets_callback, &fetched);
	if(err != USB_SUCCESS)
		return err;

	while(fetched) {
		if(beg_time + TIMEOUT <= rtc_Time())
			return USB_ERROR_TIMEOUT;
		while(cur_msg) {
			if(cur_msg->waitingTime <= rtc_Time()) {
				cur_msg->waitingTime = rtc_Time() + SEND_EVERY;
				usb_Transfer(cur_msg->endpoint, cur_msg->msg, cur_msg->length, 3, NULL);
			}
			cur_msg = cur_msg->next;
		}
		err = usb_HandleEvents();
	}
	return err;
}

web_port_t web_RequestPort() {
	static web_port_t next_port = 0xC000;
	if(next_port)
		return next_port++;
	else
		return 0;
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
			if(prev_port)
				prev_port->next = cur_port->next;
			else
				listened_ports = cur_port->next;
			free(cur_port);
		}
		prev_port = cur_port;
		cur_port = next_port;
	}
}


msg_queue_t *web_pushMessage(uint8_t *msg, size_t length, usb_endpoint_t endpoint, web_transfer_callback_t callback, web_callback_data_t *user_data) {
	msg_queue_t *new_msg = malloc(sizeof(msg_queue_t));
	new_msg->length = length;
	new_msg->msg = msg;
	new_msg->waitingTime = rtc_Time();
	new_msg->endpoint = endpoint;
	new_msg->callback = callback;
	new_msg->user_data = user_data;
	new_msg->prev = NULL;
	new_msg->next = send_queue;
	if(send_queue)
		send_queue->prev = new_msg;
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

static usb_error_t configure_usb_device() {
	rndis_init_msg_t rndis_initmsg = {RNDIS_INIT_MSG, 24, 0, 1, 0, 0x0400};
	rndis_set_msg_t rndis_setpcktflt = {RNDIS_SET_MSG , 32, 4, 0x0001010e, 4, 20, 0, 0x2d};
	usb_control_setup_t out_ctrl = {0x21, 0, 0, 0, 0};
	usb_control_setup_t in_ctrl = {0xa1, 1, 0, 0, 256};
	uint8_t buffer[256] = {0};  /* Allocating 256 bytes for the messages buffer, should be enough */
	size_t len = 0;
	size_t total_length;
	bool is_wireless_int = false, is_cdc_int = false;
	uint8_t i = 0;

	/* First, let's retrieve the configuration descriptor total size */
	usb_GetDescriptor(netinfo.device, USB_CONFIGURATION_DESCRIPTOR, 0, buffer, 9, &len);
	if(len != 9)
		return USB_ERROR_FAILED;
	total_length = ((usb_configuration_descriptor_t*)buffer)->wTotalLength;  /* More or less 40 bytes */
	if(total_length > 256)
		return USB_ERROR_NO_MEMORY;

	usb_GetDescriptor(netinfo.device, USB_CONFIGURATION_DESCRIPTOR, 0, buffer, total_length, &len);
	if(len != total_length)
		return USB_ERROR_FAILED;

	/* Iterating through all the descriptors to see if there are an rndis and cdc interfaces */
	while(i < len) {
		usb_descriptor_t *usb_descr = (usb_descriptor_t*)(buffer + i);
		switch(usb_descr->bDescriptorType) {
			/* USB Interface Descriptor */
			case USB_INTERFACE_DESCRIPTOR: {
				usb_interface_descriptor_t *interface_desc = (usb_interface_descriptor_t*)usb_descr;
				if(interface_desc->bInterfaceClass    == USB_WIRELESS_CONTROLLER_CLASS &&
				   interface_desc->bInterfaceSubClass == WIRELESS_RNDIS_SUBCLASS &&
				   interface_desc->bInterfaceProtocol == WIRELESS_RNDIS_PROTOCOL)
				{
					is_wireless_int = true;
					is_cdc_int = false;
				} else if(interface_desc->bInterfaceClass    == USB_MISCELLANEOUS_CLASS &&
				   		  interface_desc->bInterfaceSubClass == MISC_RNDIS_SUBCLASS &&
				   		  interface_desc->bInterfaceProtocol == MISC_RNDIS_PROTOCOL)
				{
					is_wireless_int = true;
					is_cdc_int = false;
				} else if(interface_desc->bInterfaceClass == USB_CDC_DATA_CLASS &&
						  interface_desc->bInterfaceSubClass == 0x00 &&
						  interface_desc->bInterfaceProtocol == 0x00)
				{
					is_wireless_int = false;
					is_cdc_int = true;
				} else {
					is_wireless_int = false;
					is_cdc_int = false;
				}
				break;
			}
			/* USB Endpoint Descriptor */
			case USB_ENDPOINT_DESCRIPTOR: {
				usb_endpoint_descriptor_t *endpoint_desc = (usb_endpoint_descriptor_t*)usb_descr;
				if(is_wireless_int) {
					netinfo.ep_wc_in = endpoint_desc->bEndpointAddress;
				} else if(is_cdc_int && (endpoint_desc->bEndpointAddress & 0x80) != 0) {  /* IN endpoint */
					netinfo.ep_cdc_in = endpoint_desc->bEndpointAddress;
				} else if(is_cdc_int && (endpoint_desc->bEndpointAddress & 0x80) == 0) {  /* OUT endpoint */
					netinfo.ep_cdc_out = endpoint_desc->bEndpointAddress;
				}
				break;
			}
			/* Unknown, Unrelevant Descriptor */
			default:
				break;
		}

		i += usb_descr->bLength;
	}

	/* If one is missing, ignoring the device */
	if(netinfo.ep_wc_in == 0 || netinfo.ep_cdc_in == 0 || netinfo.ep_cdc_out == 0) {
		netinfo.state = STATE_UNKNOWN;
		netinfo.ep_wc_in = 0;
		netinfo.ep_cdc_in = 0;
		netinfo.ep_cdc_out = 0;
		return USB_IGNORE;
	}

	/* Otherwise, let's goooo */
	if(usb_SetConfiguration(netinfo.device, (usb_configuration_descriptor_t*)buffer, len) != USB_SUCCESS)
		return USB_ERROR_FAILED;

	/************** Configuration RNDIS ************/
	out_ctrl.wLength = 24;
	do {
		usb_DefaultControlTransfer(netinfo.device, &out_ctrl, &rndis_initmsg, 3, NULL);
		usb_DefaultControlTransfer(netinfo.device, &in_ctrl, buffer, 3, &len);
	} while(len == 0 || ((rndis_msg_t*)buffer)->MessageType != RNDIS_INIT_CMPLT);

	out_ctrl.wLength = 32;
	do {
		usb_DefaultControlTransfer(netinfo.device, &out_ctrl, &rndis_setpcktflt, 3, NULL);
		usb_DefaultControlTransfer(netinfo.device, &in_ctrl, buffer, 3, &len);
	} while(len == 0 || ((rndis_msg_t*)buffer)->MessageType != RNDIS_SET_CMPLT);

	return USB_SUCCESS;
}

static usb_error_t call_callbacks(uint8_t protocol, void *data, size_t length, web_port_t port) {
	port_list_t *cur_listenedPort = listened_ports;
	while(cur_listenedPort) {
		if(port == cur_listenedPort->port) {
			if(cur_listenedPort->callback(port, protocol, data, length, cur_listenedPort->callback_data) == USB_SUCCESS)
				break;
		}
		cur_listenedPort = cur_listenedPort->next;
	}
	return USB_SUCCESS;
}

static usb_error_t fetch_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	if(!transport_checksum((uint8_t*)seg, length, ip_src, ip_dst, TCP_PROTOCOL))
		return call_callbacks(TCP_PROTOCOL, seg, length, seg->port_dst/256 + seg->port_dst*256);
	else
		return USB_ERROR_FAILED;
}

static usb_error_t fetch_udp_datagram(udp_datagram_t *datagram, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	if(!transport_checksum((uint8_t*)datagram, length, ip_src, ip_dst, UDP_PROTOCOL) || !datagram->checksum)
		return call_callbacks(UDP_PROTOCOL, datagram, length, datagram->port_dst/256 + datagram->port_dst*256);
	else
		return USB_ERROR_FAILED;
}

static usb_error_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src) {
	if(msg->type != ICMP_ECHO_REQUEST || msg->code != 0)
		return USB_IGNORE;

	msg->type = ICMP_ECHO_REPLY;
	msg->checksum += ICMP_ECHO_REQUEST - ICMP_ECHO_REPLY; /* Difference between the two messages */
	/* Send IPv4 packet */
	msg_queue_t *queued = web_PushIPv4Packet((uint8_t*)msg, length, IP_ADDR, ip_src, ICMP_PROTOCOL);
	queued->waitingTime += 100; /* We don't want the segment to be sent as a "repeated segment" */
	return usb_ScheduleTransfer(queued->endpoint, queued->msg, queued->length, send_callback, queued);
}

static usb_error_t fetch_IPv4_packet(ipv4_packet_t *pckt, size_t length) {
	if(pckt->Protocol == TCP_PROTOCOL) {
		tcp_segment_t *tcp_seg = (tcp_segment_t*)((uint8_t*)pckt + (pckt->VerIHL&0x0F)*4);
		return fetch_tcp_segment(tcp_seg, length-(pckt->VerIHL&0x0F)*4, pckt->IP_addr_src, pckt->IP_addr_dst);
	} else if(pckt->Protocol == UDP_PROTOCOL) {
		udp_datagram_t *udp_dtgm = (udp_datagram_t*)((uint8_t*)pckt + (pckt->VerIHL&0x0F)*4);
		return fetch_udp_datagram(udp_dtgm, length-(pckt->VerIHL&0x0F)*4, pckt->IP_addr_src, pckt->IP_addr_dst);
	} else if(pckt->Protocol == ICMP_PROTOCOL) {
		icmpv4_echo_t *msg = (icmpv4_echo_t*)((uint8_t*)pckt + (pckt->VerIHL&0x0F)*4);
		return fetch_icmpv4_msg(msg, length-(pckt->VerIHL&0x0F)*4, pckt->IP_addr_src);
	} else
		return USB_IGNORE;
}

static void fetch_arp_msg(eth_frame_t *ethernet_frame) {
	arp_message_t *arp_msg = (arp_message_t*)((uint8_t*)ethernet_frame + sizeof(eth_frame_t) - 4);
	if(ethernet_frame->Ethertype != ETH_ARP || arp_msg->HwType != 0x0100 || arp_msg->Operation != 0x0100 || arp_msg->ProtocolType != ETH_IPV4 || arp_msg->IP_dst != IP_ADDR)
		return;
	arp_message_t *resp = malloc(sizeof(arp_message_t));
	memcpy((uint8_t*)resp->MAC_dst, (uint8_t*)arp_msg->MAC_src, 10);
	memcpy((uint8_t*)resp->MAC_src, MAC_ADDR, 6);
	resp->IP_src = IP_ADDR;
	resp->Operation = 0x0200;
	resp->HwType = 0x0100;
	resp->ProtocolType = 0x0008;
	resp->HwAddrLength = 0x06;
	resp->ProtocolAddrLength = 0x04;

	msg_queue_t *queued = web_PushEthernetFrame((uint8_t*)resp, sizeof(arp_message_t), ETH_ARP);
	queued->waitingTime += 100; /* We don't want the segment to be sent as a "repeated segment" */
	usb_ScheduleTransfer(queued->endpoint, queued->msg, queued->length, send_callback, queued);
	free(resp);
}

static usb_error_t fetch_ethernet_frame(eth_frame_t *frame, size_t length) {
	if(frame->Ethertype == ETH_IPV4 && !memcmp(frame->MAC_dst, MAC_ADDR, 6)) {
		src_mac_addr = frame->MAC_src;
		ipv4_packet_t *ipv4_pckt = (ipv4_packet_t*)((uint8_t*)frame+sizeof(eth_frame_t)-4); /* -4=-crc */
		return fetch_IPv4_packet(ipv4_pckt, length-sizeof(eth_frame_t)+4); /* No CRC */
	} else if(frame->Ethertype == ETH_ARP && (!memcmp(frame->MAC_dst, MAC_ADDR, 6) || cmpbroadcast(frame->MAC_dst))) {
		fetch_arp_msg(frame);
	}

	return USB_IGNORE;
}


static usb_error_t packets_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data) {
	(void)endpoint; (void)status; /* Unused parameters */
	usb_error_t ret_err = fetch_ethernet_frame((eth_frame_t*)(*((uint8_t**)data) + sizeof(rndis_packet_msg_t)), transferred-sizeof(rndis_packet_msg_t));
	*((uint8_t**)data) = NULL; /* Notifying web_WaitForEvents() that we received and fetched something */
	return ret_err;
}

static usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *data) {
	(void)data; /* Unused parameter */
	switch(event)
	{
		case USB_DEVICE_CONNECTED_EVENT:
			netinfo.device = (usb_device_t)event_data;
			netinfo.state = STATE_USB_CONNECTED;
			usb_ResetDevice(netinfo.device);
			break;
		case USB_DEVICE_ENABLED_EVENT:
			if(!(usb_GetRole() & USB_ROLE_DEVICE)) {
				netinfo.state = STATE_USB_ENABLED;
			} else {
				usb_DisableDevice(netinfo.device);
				netinfo.state = STATE_UNKNOWN;
			}
			break;
		case USB_DEVICE_DISABLED_EVENT:
			netinfo.state = STATE_USB_LOST;
			break;
		case USB_DEVICE_DISCONNECTED_EVENT:
			netinfo.state = STATE_USB_LOST;
			break;
		default:
			break;
	}
	
	#ifdef DEBUG
		static const char *usb_event_names[] = {
	        "ROLE_CHANGED_EVENT",
	        "DEVICE_DISCONNECTED_EVENT",
	        "DEVICE_CONNECTED_EVENT",
	        "DEVICE_DISABLED_EVENT",
	        "DEVICE_ENABLED_EVENT",
	        "HUB_LOCAL_POWER_GOOD_EVENT",
	        "HUB_LOCAL_POWER_LOST_EVENT",
	        "DEVICE_RESUMED_EVENT",
	        "DEVICE_SUSPENDED_EVENT",
	        "DEVICE_OVERCURRENT_DEACTIVATED_EVENT",
	        "DEVICE_OVERCURRENT_ACTIVATED_EVENT",
	        "DEFAULT_SETUP_EVENT",
	        "HOST_CONFIGURE_EVENT",
	        // Temp debug events:
	        "DEVICE_INT",
	        "DEVICE_CONTROL_INT",
	        "DEVICE_DEVICE_INT",
	        "OTG_INT",
	        "HOST_INT",
	        "CONTROL_ERROR_INT",
	        "CONTROL_ABORT_INT",
	        "FIFO0_SHORT_PACKET_INT",
	        "FIFO1_SHORT_PACKET_INT",
	        "FIFO2_SHORT_PACKET_INT",
	        "FIFO3_SHORT_PACKET_INT",
	        "DEVICE_SUSPEND_INT",
	        "DEVICE_RESUME_INT",
	        "DEVICE_ISOCHRONOUS_ERROR_INT",
	        "DEVICE_ISOCHRONOUS_ABORT_INT",
	        "DEVICE_DMA_FINISH_INT",
	        "DEVICE_DMA_ERROR_INT",
	        "DEVICE_IDLE_INT",
	        "DEVICE_WAKEUP_INT",
	        "B_SRP_COMPLETE_INT",
	        "A_SRP_DETECT_INT",
	        "A_VBUS_ERROR_INT",
	        "B_SESSION_END_INT",
	        "OVERCURRENT_INT",
	        "HOST_PORT_CONNECT_STATUS_CHANGE_INT",
	        "HOST_PORT_ENABLE_DISABLE_CHANGE_INT",
	        "HOST_PORT_OVERCURRENT_CHANGE_INT",
	        "HOST_PORT_FORCE_PORT_RESUME_INT",
	        "HOST_SYSTEM_ERROR_INT",
	    };
	    if(event <= USB_HOST_CONFIGURE_EVENT) {
	    	printf("%s\n", usb_event_names[event]);
	    }
		unsigned int x, y;
		os_GetCursorPos(&x, &y);
		os_SetCursorPos(0, 0);
		printf("%lu    ", usb_GetCycleCounter());
		switch(netinfo.state) {
			case STATE_USB_CONNECTED:
				printf("CONNECTED   ");
				break;
			case STATE_USB_ENABLED:
				printf("ENABLED     ");
				break;
			case STATE_RNDIS_CONFIGURING:
				printf("RNDIS       ");
				break;
			case STATE_DHCP_CONFIGURING:
				printf("DHCP        ");
				break;
			case STATE_NETWORK_CONFIGURED:
				printf("NETWORK     ");
				break;
			case STATE_UNKNOWN:
				printf("UNKNOWN     ");
				break;
			case STATE_USB_LOST:
				printf("LOST        ");
				break;
			default:
				printf("???         ");
				break;
		}
		os_SetCursorPos(x, y);
	#endif // DEBUG

	return USB_SUCCESS;
}


// Le pb est déplacé au dhcp maintenant. Mais ce qu'il y a avant semble fonctionner OK.
// Juste il semble qu'il y ait un ram cleared après l'init rndis parfois, à voir...


// PB: quand on débranche ou qu'on désactive le partage de co quand on est en RNDIS ça RC ou ça freeze
//	-> Sachant que ça arrive que quand on a fait deux trois transfer déjà
//	-> peut-être que plus on est dans handleEvents plus ça a des chance de bugger ?
// est-ce que le problème peut être résolu avec RefDevice ? ça n'a pas l'air
// est-ce que si on disable à la main ça marche mieux ? bah oui mais on ne sait pas quand ça va être débranché
// est-ce que si on maniupule le timing d'appel avec usb_HandleEvents avec des sleep ça a moins de chance de bugger ?

//NEW
// Est-ce que le pb serait pas lié à une histoire de timer ? parce que dans le cas ou on déco le device, le frame number est reset à 0
//	  -> il se passe donc un truc après que le cable soit retiré, comme le détecter ?
//	  -> Est-ce que si je fais un if connected avant handleEvents je pourrais éviter qu'il bloque ?

//  + autres pb
//		-> les RC intempestifs quand j'active le tethering
//		-> les requetes HTTP qui aboutissent une fois sur 2
//		-> le web_CleanUp qui RC, apparemment au niveau des free des ports (d'ailleurs dhcp n'est pas free ? http peut-être pas non plus ?)


#ifdef DEBUG
void debug(const void *addr, size_t len) {
	uint8_t *content = (uint8_t*)addr;
	size_t i;
	const char *DIGITS = "0123456789ABCDEF";
	for(i=0; i<len; i++) {
		if(i && i%8 == 0)
			printf("\n");
		printf(" %c%c", DIGITS[*(content+i)/16], DIGITS[*(content+i)%16]);
	}
	printf("\n");
}

void disp(unsigned int val) {
	uint24_t value = (uint24_t)val;
	char tmp[20];
	sprintf(tmp, "DISP : %u ", value);
	os_PutStrFull(tmp);
	boot_NewLine();
}

void printf_xy(unsigned int xpos, unsigned int ypos, const char *txt) {
	unsigned int x, y;
	os_GetCursorPos(&x, &y);
	os_SetCursorPos(xpos, ypos);
	printf("%s ", txt);
	os_SetCursorPos(x, y);
}
#endif // DEBUG
