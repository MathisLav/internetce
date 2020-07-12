/**
 *--------------------------------------
 * Lib Name: webgtrce
 * Author: Mathis Lavigne aka Epharius
 * License:
 * Description: This librairy aim at allowing any program to access the internet.
 *--------------------------------------
 */

#define DEBUG

#include <tice.h>
#include <keypadc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <usbdrvce.h>
#include <fileioc.h>
#include <stdarg.h>
#include "../include/webgtrce.h"

extern var_t *MoveToArc(const char* name);
extern var_t *MoveToRam(const char* name);
extern bool os_EnoughMem(size_t mem);
extern int os_DelVarArc(uint8_t type, const char *name);
extern int ResizeAppVar(const char* name, size_t new_size); /* true=the resizing happened, false if not */
#ifdef DEBUG
static void debug(const void *addr, size_t len);
static void disp(unsigned int val);
#endif // DEBUG

network_info_t netinfo;
static uint8_t MAC_ADDR[6] = {0xEA, 0xA5, 0x59, 0x9C, 0xC1, 0};
static uint32_t IP_ADDR = 0;
static uint8_t *src_mac_addr; /* For dhcp purposes (we need to acknowledge the router's mac address) */
static http_data_list_t *http_data_list = NULL;
static msg_queue_t *send_queue = NULL;
static port_list_t *listened_ports = NULL;



/*******************************************************************************\
 * à terme : - la découverte de l'adresse mac du routeur doit se faire par ARP.
 *			 	(voir fetch_ethernet_frame et fetch_dhcp_msg)
 *			 - Faire une version non-bloquante de send_http_request
 *				-> dans ce cas, pourquoi pas faire un système de http-callback ?
 *			 - close_connection
 *			 - lease IP
 *			 - Gérer ICMPv4 echo request
 *			 - Gérer la fusion des packets ipv4 (= meilleures perfs)
 *			 - Y'a moyen d'utiliser les interruptions USB (intce.h)
\*******************************************************************************/


int main(void)
{
	os_ClrHome();
	boot_NewLine();
	//os_PutStrFull("RNDIS Connection... ");
	
	web_Init();
	while(!web_Connected() && !os_GetCSC())
		web_WaitForEvents();
	if(!web_Connected()) {
		boot_NewLine();
		os_PutStrFull("Canceled!");
		while(!os_GetCSC()) {}
		goto _end;
	}
	//os_PutStrFull("Done!");
	//boot_NewLine();


	// Fait :		USB - RNDIS - Ethernet - IPv4 - UDP - DHCP - DNS - ARP - TCP - HTTP
	// Protocoles auxiliaires : ICMPv4 - TLS->HTTPS - IRC - SSH

	

	// !!! LETTRE A MOI-MÊME !!!
	// OK donc si tu vois ce message c'est que y'a eu une grosse pause...
	// Jusqu'à maintenant j'étais en train de faire le truc de "globalité" : à savoir le multi-threading et le système de ports.
	// Donc j'ai VRAIMENT galéré, mais vraiment beaucoup. Et me voici aujourd'hui à cette avancée :
	// Dans la théorie le code fonctionne : requestport, listenport mais surtout fetch_http_request, httpget etc.
	// En pratique y'a pas mal de bugs qu'ils faut absolument résoudre pour qualifier la globalité de "terminée".
	//	A savoir, y'a une liste de bugs plus bas, voilà les trucs que j'ai remarqué.
	// Evidemment y'a surement tout plein d'autres bugs, donc une fois que j'aurai résolu ceux-là (bon courage) faudra en chercher d'autres.
	// Càd qu'il va falloir faire des dizaines de tests sur des dizaines de sites différents pour voir que tout fonctionne (ou pas).
	// Et encore une fois bon courage, rien que pour résoudre les bugs suivants ça risque de prendre un certain temps.
	//
	// Une fois que je n'aurais pas remarqué d'autres bugs, il faudra faire les deux petits "A termes" ci-dessous quie vraient être rapides.
	// Et une fois que ce sera fait, il faudra voir les "A termes" en haut, séléctionner les plus pertinents et les mettre en oeuvre.
	// 
	// ATTENTION : un certain nombre de bugs ont été causé par des trucs qui ne dépendent pas de moi.
	//		-> Pour pas faire deux fois la même erreur il est important de noter les deux remarques "MORALE" juste en-dessous.



	// MORALE : NE PAS UTILISER DE USB_HANDLEEVENTS/WAITFOREVENTS/WAITFORINTERRUPTS DANS UN CALLBACK !!!! (donc usb_transfer non plus)
	// MORALE : NE PAS UTILISER OS_PUTSTRFULL À OUTRANCE (FAUT PAS QUE ÇA SCROLLE)


	// BUGS :
	//	- www.fcstream.cc se charge que jusqu'à 14000 environ : surement un problème avec les chunks
	//		-> Cause : les chunks sont en effet mal configurés par le serveur qui a l'air d'envoyer la taille du chunk + le "chunk header" (taille du chunk+2*0d0a)
	//			Il semblerait que ça n'arrive pas quand on travaille en gzip : l'admin du site n'a pas du vérifier que le site marchait sur des vieux navigateurs.
	//		-> Solution : Traiter le gzip : c'est pas pour tout de suite donc pour le moment je laisse ça comme ça
	//
	//	- Avant, après un transfert au niveau de lock_data ça RC. Et du jour au lendemain plus (y'a juste eu un Garbage Collect entre)
	//	- Des fois, le transfert (HTTP) s'arrête en plein milieu et la calc freeze (plus d'events/boucle infinie ?)
	//	- Des fois, WLCE0000 n'est pas effacé



	//os_PutStrFull("HTTP Request...     ");
	http_data_t *data = NULL;
	http_status_t status = HTTPGet("www.perdu.com", &data, false);
	while(!os_GetCSC()) {}
	os_ClrHome();
	disp(status);
	debug(data, 72);
	while(!os_GetCSC()) {}
	//os_ClrHome();
	//os_PutStrFull((const char*)data->data);
	//while(!os_GetCSC()) {}
	//os_PutStrFull("Done!");
	//boot_NewLine();

	// The End.
	boot_NewLine();
	os_PutStrFull("Waiting for keypress...");
	_end:
	while(!os_GetCSC())
		usb_WaitForInterrupt();

	web_Cleanup();
	return 0;
}

	//		est-ce que je gère la possibilité d'envoyer du multi-packet ?

	// CDC Personnel pour TCP (à restreindre ou à élargir en fonction)
	//  *	crucial
	// (*)	important
	// ~*~	facultatif
	//
	//		- ORGANISER une connexion
	//	->		 * 	Gérer les SYN, SYN/ACK, ACK du début de connexion
	//	->		(*)	Renvoyer un segment au bout d'un certain temps
	//	_		(*)	Terminer une connexion (FIN, FIN/ACK *2)
	//	->		~*~	Permettre la communication simultanée de plusieurs applications (utile seulement si la lib ne bloque pas l'application)
	//
	//		- ASSURER la réception des segments
	//	->		* Remettre les segments dans l'ordre, malgré leur arrivée asynchrone
	//	->		* Avoir un assez gros buffer pour recevoir un segment de taille maximale
	//	->		* ACK le serveur en bonne et due forme
	//
	//		- VERIFIER la conformité de la réponse
	//	->		*	Vérifier le checksum
	//	->		*	Prévenir le serveur (ne pas ACK) en cas de segment erronné
	//


http_status_t HTTPGet(const char* url, http_data_t **data, bool keep_http_header) {
	/**
	 *	WARNING : The content returned by those functions are in READ-ONLY
	 */
	char null_pointer = 0x00;
	return http_request("GET", url, data, keep_http_header, &null_pointer);
}

http_status_t HTTPPost(const char* url, http_data_t **data, bool keep_http_header, int nb_params, ...) {
	/**
	 *	WARNING : The content returned by those functions are in READ-ONLY
	 */

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
		sprintf(params+param_len, "%s: %s\r\n", arg_name, arg_value);
		param_len += strlen(arg_name)+strlen(arg_value)+4;
	}
	va_end(list_params);

	http_status_t status = http_request("POST", url, data, keep_http_header, params);
	free(params);
	return status;
}

static http_status_t http_request(const char *request_type, const char* url, http_data_t **data, bool keep_http_header, char *params) {
	// usb_error_t on error
	// http_status_t else
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
	uint32_t ip = send_dns_request(websitename);
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
	os_PutStrFull("INITED ");

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
			free(exch);
			return SYSTEM_TIMEOUT;
		}
	}

	web_UnlistenPort(exch->port_src);
	
	//close_tcp_session(ip);
	http_status_t status = exch->status;
	free(exch);
	return status;
}

void add_tcp_queue(char *data, size_t length, http_exchange_t *exchange, uint16_t flags, size_t opt_size, const uint8_t *options) {
	/**	- Add segment to send_queue (call push_tcp_segment)
	 *	- Add segment to http queue (http_exchange_t pushed_seg field)
	 *	- Increase the sequence number
	 */
	msg_queue_t *queued = push_tcp_segment(data, length, exchange->ip_dst, exchange->port_src, exchange->port_dst, exchange->cur_sn, exchange->cur_ackn, flags, opt_size, options);
	exchange->cur_sn += length;
	pushed_seg_list_t *new_seg = malloc(sizeof(pushed_seg_list_t));
	new_seg->relative_sn = (exchange->cur_sn) - exchange->beg_sn;
	new_seg->seg = queued;
	new_seg->next = exchange->pushed_seg;
	exchange->pushed_seg = new_seg;
}

void fetch_ack(http_exchange_t *exchange, uint32_t ackn) {
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
		pop_message(cur_seg->seg);
		free(cur_seg);
		cur_seg = next_seg;
	}

	exchange->relative_seqacked = ackn-exchange->beg_sn;
}

usb_error_t fetch_http_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data) {
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
		send_tcp_segment(NULL, 0, exch->ip_dst, exch->port_src, exch->port_dst, exch->cur_sn, exch->cur_ackn, FLAG_TCP_ACK, 0, NULL);
	}

	/* If ACK */
	const uint32_t ack_number = getBigEndianValue((uint8_t*)&tcp_seg->ack_number);
	if(ack_number-exch->beg_sn > exch->relative_seqacked && tcp_seg->dataOffset_flags&0x1000)
		fetch_ack(exch, ack_number);

	/* MAIN LOOP */
	asm_HomeUp();
	boot_NewLine();
	disp(exch->content_received);

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
			send_tcp_segment(NULL, 0, exch->ip_dst, exch->port_src, exch->port_dst, exch->cur_sn, exch->cur_ackn, FLAG_TCP_ACK, 0, NULL);
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
		send_tcp_segment(NULL, 0, exch->ip_dst, exch->port_src, exch->port_dst, exch->cur_sn, exch->cur_ackn, FLAG_TCP_ACK, 0, NULL);
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
		if(exch->content_length>TI_MAX_SIZE) {
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

	// FIN MAIN LOOP
	if(!exch->content_length || (exch->content_length && exch->content_length>exch->content_received))
		return USB_SUCCESS;

	end_http_message:
	os_PutStrFull("EEEEEEND ");

	/* We store the data in an appvar, in order to relieve the heap */
	if(exch->content_received > TI_MAX_SIZE) {
		wipe_data(exch);
		exch->status = SYSTEM_NOT_ENOUGH_MEM;
		return USB_ERROR_NO_MEMORY;
	}
	http_data_list_t *new_http_data_el = calloc(1, sizeof(http_data_list_t));
	char varstorage_name[9] = "WLCE0000";
	/* Trying to find a name that is not already in used */
	uint16_t n=0;
	while(n<9999 && os_ChkFindSym(TI_APPVAR_TYPE, varstorage_name, NULL, NULL)) {
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

	lock_data(exch->data);
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


int unlock_data(http_data_t **http_data) {
	// Il faudra avertir que c'est une opération dangereuse
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

int lock_data(http_data_t **http_data) {
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
		os_ClrHome();
		debug(cur_queue->msg+40, 72);
		while(!os_GetCSC()) {}

		next_queue = cur_queue->next;
		pop_message(cur_queue);
		cur_queue = next_queue;
	}

	/* Freeing the appvars used for saving what the lib receives */
	http_data_list_t *cur_data = http_data_list;
	http_data_list_t *next_data = NULL;
	while(cur_data) {
		next_data = cur_data->next;
		if(os_DelVarArc(TI_APPVAR_TYPE, cur_data->varname))
			os_PutStrFull("DELETED ");
		else
			os_PutStrFull("NOTDELED ");
		while(!os_GetCSC()) {}
		free(cur_data);
		cur_data = next_data;
	}

	usb_Cleanup();
}

void fetch_arp_msg(eth_frame_t *ethernet_frame) {
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

	msg_queue_t *queued = push_ethernet_frame((uint8_t*)resp, sizeof(arp_message_t), ETH_ARP);
	queued->waitingTime += 100; /* We don't want the segment to be sent as a "repeated segment" */
	usb_ScheduleTransfer(queued->endpoint, queued->msg, queued->length, send_callback, queued);
	free(resp);
}

void send_arp_query(uint32_t ip) {
	eth_frame_t *frame = calloc(1, sizeof(eth_frame_t)-4 + sizeof(arp_message_t));
	arp_message_t *arp_msg = (arp_message_t*)((uint8_t*)frame+sizeof(eth_frame_t)-4);
	memset(frame->MAC_dst, 0xff, 6);
	memcpy((uint8_t*)frame->MAC_src, MAC_ADDR, 6);
	arp_msg->IP_dst = ip;
	memcpy((uint8_t*)arp_msg->MAC_src, MAC_ADDR, 6);
	arp_msg->IP_src = IP_ADDR;
	arp_msg->Operation = 0x0100;
	send_rndis_packet((uint8_t*)arp_msg, sizeof(eth_frame_t)-4 + sizeof(arp_message_t));
	free(frame);
}

uint32_t send_dns_request(const char *addr) {
	uint32_t res_ip = 0;
	push_dns_request(addr, &res_ip);
	while(!res_ip)
		web_WaitForEvents();
	return res_ip;
}

void push_dns_request(const char *addr, uint32_t *res_ip) {
	/* Returns -1 or error */
	size_t length = sizeof(dns_message_t)+strlen(addr)+2+4; /* 2=length byte at the begining of the string+0 terminated string */
	uint8_t *query = calloc(length, 1);

	query[2] = 0x01;
	query[5] = 0x01;

	/* formating address for dns purposes */
	char *cursor_qry = (char*)(query+sizeof(dns_message_t)+1);
	char *cursor_str = (char*)addr;
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
	dns_exch->res_ip = res_ip;
	dns_exch->queued_request = push_udp_datagram(query, length, netinfo.DNS_IP_addr, client_port, DNS_PORT);
	free(query);

	web_ListenPort(client_port, fetch_dns_msg, dns_exch);
}

usb_error_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data) {
	(void)port; (void)length; /* Unused parameters */
	if(protocol != UDP_PROTOCOL)
		return USB_IGNORE;
	dns_exchange_t *exch = (dns_exchange_t*)user_data;
	pop_message(exch->queued_request);

	const udp_datagram_t *udp_dtgm = (udp_datagram_t*)msg;
	if(udp_dtgm->port_src/256 == DNS_PORT && udp_dtgm->port_src%256 == 0x00) {
		const dns_message_t *dns_msg = (dns_message_t*)((uint8_t*)udp_dtgm + sizeof(udp_datagram_t));

		if(!(dns_msg->flags&0x8000) || !(dns_msg->flags&0x0080) || (dns_msg->flags&0x0F00)) { /* if -> it isn't a response OR the recursion wasn't available OR an error occurred */
			*exch->res_ip = 0xffffffff;
			return USB_ERROR_FAILED;
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
			*exch->res_ip = 0xffffffff;
			return USB_ERROR_FAILED;
		}

		ptr += 12;
		*exch->res_ip = *((uint32_t*)ptr); /* Warning : returning the little endian value */

		return USB_SUCCESS;
	}

	return USB_IGNORE;
}

static msg_queue_t *dhcp_last_queued_msg = NULL;
static uint8_t phase = 0; /* 0=not initiated, 1=discover sent, 2=request sent, 3=done */
void dhcp_init() {
	/**
	 *	Sends an IPv4 request to the local server.
	 *	The RNDIS netinfo must have been initialized with rndis_init() first.
	 *	@return USB_SUCCESS or an error.
	 *	@output netinfo correct attributes (router_MAC_addr, DNS_IP_addr, DHCP_IP_addr) and static variable IP_ADDR.
	 */
	/* DHCP DISCOVERY */
	static uint32_t xid = 0x03F82639;
	if(phase != 0) /* if an init() is already running */
		return;
	
	web_ListenPort(0x44, fetch_dhcp_msg, NULL);

	const uint8_t beg_header[] = {0x01, 0x01, 0x06, 0x00};
	const uint8_t options_disc[] = {53, 1, 1, 0x37, 3, 1, 3, 6, 0xFF, 0};
	const size_t length_disc = sizeof(dhcp_message_t)+sizeof(options_disc);
	uint8_t *data_disc = calloc(length_disc, 1);
	memcpy(data_disc, &beg_header, 4);
	((uint32_t*)data_disc)[1] = xid;
	memcpy(data_disc+28, &MAC_ADDR, 6);
	((uint32_t*)data_disc)[59] = 0x63538263;
	memcpy(data_disc+240, &options_disc, sizeof(options_disc));

	dhcp_last_queued_msg = push_udp_datagram(data_disc, length_disc, 0xffffffff, CLIENT_DHCP_PORT, SERVER_DHCP_PORT);
	free(data_disc);
	phase = 1;
	xid++;
}

usb_error_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data) {
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
						pop_message(dhcp_last_queued_msg);
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
						dhcp_last_queued_msg = push_udp_datagram(data_req, length_req, 0xffffffff, CLIENT_DHCP_PORT, SERVER_DHCP_PORT);
						phase = 2;
					} else if(*(cur_opt+2) == 5 && phase == 2) { /* ACK */
						pop_message(dhcp_last_queued_msg);
						dhcp_last_queued_msg = NULL;
						IP_ADDR = dhcp_msg->yiaddr;
						memcpy(netinfo.router_MAC_addr, src_mac_addr, 6);
						phase = 3;
					} else if(*(cur_opt+2) == 6) { /* NACK */
						if(dhcp_last_queued_msg) {
							pop_message(dhcp_last_queued_msg);
							dhcp_last_queued_msg = NULL;
						}
						phase = 0;
						dhcp_init();
						return USB_ERROR_FAILED;
					}
					break;
				case 6: /* DNS SERVER */
					netinfo.DNS_IP_addr = *((uint32_t*)(cur_opt+2)); /* we only take the first entry */
					break;
				case 51: /* Lease time */
					// nothing to do yet
					break;
				default:
					break;
			}
			cur_opt += *(cur_opt+1)+2;
		}
	}
	return USB_SUCCESS;
}


usb_error_t send_tcp_segment(char *data, size_t length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options) {
	msg_queue_t *queued = push_tcp_segment(data, length, ip_dst, port_src, port_dst, seq_number, ack_number, flags, opt_size, options);
	queued->waitingTime += 100; /* We don't want the segment to be sent as a "repeated segment" */
	return usb_ScheduleTransfer(queued->endpoint, queued->msg, queued->length, send_callback, queued);
}

static usb_error_t send_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data) {
	(void)endpoint; (void)status; (void)transferred; /* Unused parameters */
	pop_message((msg_queue_t*)data);
	return USB_SUCCESS;
}

msg_queue_t *push_tcp_segment(char *data, size_t length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options) {
	/**
	 *	Encapsulates data with a TCP header.
	 *	The current version is not able to break down data into several ipv4 packets.
	 *	Consequently, this lib is not aim at uploading large amount of data.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param ip_dst The IP of the target server.
	 *	@param port_dst The destination port. For example HTTP (80).
	 *	@param ack_number The 32-bits number that must be written in the ACK field.
	 *	@param flags For example FLAG_TCP_ACK for acknowledging a segment.
	 *	@param options The options, or NULL if there is no option. THE SIZE OF THE ARRAY MUST BE A MULTIPLE OF 4.
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
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

	msg_queue_t *queued = push_ipv4_packet(tcp_seg, length+sizeof(tcp_segment_t)+opt_size, IP_ADDR, ip_dst, TCP_PROTOCOL);
	free(tcp_seg);
	return queued;
}

uint16_t transport_checksum(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol) {
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


msg_queue_t *push_udp_datagram(uint8_t *data, size_t length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst) {
	/**
	 *	Encapsulates data with an UDP header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param port_dst The destination port. For example DHCP_PORT (68) or DNS_PORT (53).
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	uint8_t *datagram = calloc(length+sizeof(udp_datagram_t), 1);
	datagram[0] = port_src/256;
	datagram[1] = port_src%256;
	datagram[2] = port_dst/256;
	datagram[3] = port_dst%256;
	datagram[4] = (length+sizeof(udp_datagram_t))/256;
	datagram[5] = (length+sizeof(udp_datagram_t))%256;
	memcpy(datagram+sizeof(udp_datagram_t), data, length);
	uint16_t chksm = transport_checksum(datagram, length+sizeof(udp_datagram_t), IP_ADDR, ip_dst, UDP_PROTOCOL);
	datagram[6] = chksm/256;
	datagram[7] = chksm%256;
	
	msg_queue_t *queued = push_ipv4_packet(datagram, length+sizeof(udp_datagram_t), IP_ADDR, ip_dst, UDP_PROTOCOL);
	free(datagram);

	return queued;
}


msg_queue_t *push_ipv4_packet(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol) {
	/**
	 *	Encapsulates data with an IPv4 header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param ip_src Your IP or 0.0.0.0 if you have been attributed no IP yet (for DHCP requests for example).
	 *	@param ip_dst The IP of the target server.
	 *	@param protocol Protocol of the data. For example ICMP_PROTOCOL (0x01), TCP_PROTOCOL (0x06) or UDP_PROTOCOL (0x11).
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	static uint16_t nbpacket = 0;
	const size_t size = length+sizeof(ipv4_packet_t);
	const ipv4_packet_t packet = {0x45, 0x10, 0, 0, 0x40, 0x80, 0, 0, 0, 0};
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

	msg_queue_t *queued = push_ethernet_frame(ipv4_pckt, size, ETH_IPV4);
	free(ipv4_pckt);

	return queued;
 }

uint16_t ipv4_checksum(uint16_t *header, size_t length) {
	uint24_t sum = 0;
	for(size_t i=0; i<length/2; i++) 
		sum += header[i];
	return (uint16_t)~(sum+(sum >> 16));
}


msg_queue_t *push_ethernet_frame(uint8_t *data, size_t length, uint16_t protocol) {
	/**
	 *	Encapsulates data with an ethernet header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
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

	msg_queue_t *queued = push_rndis_packet(frame, length);
	free(frame);

	return queued;
}

#define CRC_POLY 0xEDB88320
uint32_t crc32b(uint8_t *data, size_t length) {
	/**
	 *	Computes ethernet crc32.
	 *	Code found on stackoverflow.com (no licence was given to the code)
	 */
	// IL FAUT EN PARLER AVEC QUELQU'UN
	// LORS DE LA DEUXIÈME BOUCLE EMBRIQUÉE, IL A DIT NTM ET BOUCLE DANS LA VIDE
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


msg_queue_t *push_rndis_packet(uint8_t *data, size_t length) {
	/**
	 *	Sends a packet to the rndis device.
	 *	Blocks until the transfer finishes.
	 *	@param **data Pointer of the data to be sent, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@return USB_SUCCESS or an error.
	 */
	uint8_t *pckt = malloc(sizeof(rndis_packet_msg_t)+length);
	memset(pckt, 0, sizeof(rndis_packet_msg_t));
	pckt[0] = RNDIS_PACKET_MSG;
	pckt[4] = (sizeof(rndis_packet_msg_t)+length)%256;
	pckt[5] = (sizeof(rndis_packet_msg_t)+length)/256;
	pckt[8] = 36;
	pckt[12] = length%256;
	pckt[13] = length/256;
	memcpy(pckt+sizeof(rndis_packet_msg_t), data, length);

	return push_message(pckt, length+sizeof(rndis_packet_msg_t), usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc), packets_callback, NULL);
}

usb_error_t send_rndis_packet(uint8_t *data, size_t length) {
	uint8_t *pckt = malloc(sizeof(rndis_packet_msg_t)+length);
	memset(pckt, 0, sizeof(rndis_packet_msg_t));
	pckt[0] = RNDIS_PACKET_MSG;
	pckt[4] = (sizeof(rndis_packet_msg_t)+length)%256;
	pckt[5] = (sizeof(rndis_packet_msg_t)+length)/256;
	pckt[8] = 36;
	pckt[12] = length%256;
	pckt[13] = length/256;
	memcpy(pckt+sizeof(rndis_packet_msg_t), data, length);

	return usb_ScheduleTransfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc), pckt, length+sizeof(rndis_packet_msg_t), send_rndis_callback, pckt);
}

static usb_error_t send_rndis_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *data) {
	(void)endpoint; (void)status; (void)transferred; /* Unused parameters */
	free(data);
	return USB_SUCCESS;
}


void web_Init() {
	/**
		Waits until a rndis device is detected
		If any key is pressed, returns USB_IGNORE.
		If the RNDIS Device has been initialized properly, returns USB_SUCCESS.
		If not, returns an error.
	**/
	netinfo.int_wc = 0;
	netinfo.int_cdc = 0;
	netinfo.ep_wc = 0;
	netinfo.ep_cdc = 0;
	netinfo.enabled = false;
	netinfo.connected = false;
	netinfo.configuring = true;
	netinfo.device = NULL;
	usb_Init(usbHandler, NULL, NULL, USB_DEFAULT_INIT_FLAGS);
	while(!netinfo.device)
		usb_WaitForEvents();

	memset(&(netinfo.router_MAC_addr), 0xFF, 6);
	srand(rtc_Time());
	MAC_ADDR[5] = randInt(0, 0xFF);
}


size_t getChunkSize(const char **ascii) {
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

bool cmpbroadcast(const uint8_t *mac_addr) {
	bool is_brdcst = true;
	for(int i=0; i<6; i++)
		is_brdcst = is_brdcst && *(mac_addr+i)==0xff;
	return is_brdcst;
}

uint32_t getBigEndianValue(uint8_t *beVal) {
	return beVal[0]*16777216 + beVal[1]*65536 + beVal[2]*256 + beVal[3];
}

uint32_t getMyIPAddr() {
	return IP_ADDR;
}

bool web_Connected() {
	return netinfo.connected && netinfo.enabled && netinfo.ep_wc && netinfo.ep_cdc && IP_ADDR;
}

usb_error_t web_WaitForEvents() {
	msg_queue_t *cur_msg = send_queue;
	uint8_t msg[MAX_SEGMENT_SIZE+100];
	uint8_t *fetched = msg;
	const uint32_t beg_time = rtc_Time();
	usb_error_t sched_err;
	
	if(!netinfo.connected)
		return usb_HandleEvents();

	sched_err = usb_ScheduleTransfer(usb_GetDeviceEndpoint(netinfo.device, (netinfo.ep_cdc)|0x80), msg, MAX_SEGMENT_SIZE+100, packets_callback, &fetched);
	if(sched_err != USB_SUCCESS)
		return sched_err;

	while(fetched) {
		if(beg_time + TIMEOUT <= rtc_Time())
			return USB_ERROR_TIMEOUT;
		while(cur_msg) {
			if(cur_msg->waitingTime <= rtc_Time()) {
				os_PutStrFull(".");
				cur_msg->waitingTime = rtc_Time() + SEND_EVERY;
				usb_Transfer(cur_msg->endpoint, cur_msg->msg, cur_msg->length, 3, NULL);
			}
			cur_msg = cur_msg->next;
		}
		usb_HandleEvents();
	}
	return USB_SUCCESS;
}

web_port_t web_RequestPort() {
	static web_port_t next_port = 0x9000;
	if(next_port)
		return next_port++;
	else
		return 0;
}

void web_ListenPort(web_port_t port, web_port_event_t *callback, web_callback_data_t *callback_data) {
	port_list_t *new_port = malloc(sizeof(port_list_t));
	new_port->port = port;
	new_port->callback = callback;
	new_port->callback_data = callback_data;
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


msg_queue_t *push_message(uint8_t *msg, size_t length, usb_endpoint_t endpoint, usb_transfer_callback_t callback, usb_callback_data_t *user_data) {
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
	//os_PutStrFull("Push ");
	return new_msg;
}

void pop_message(msg_queue_t *msg) {
	if(msg->prev)
		msg->prev->next = msg->next;
	else
		send_queue = msg->next;
	if(msg->next)
		msg->next->prev = NULL;
	free(msg->msg);
	free(msg);
	//os_PutStrFull("Pop ");
}



static usb_error_t fetch_IPv4_packet(ipv4_packet_t *pckt, size_t length) {
	if(pckt->Protocol == TCP_PROTOCOL) {
		tcp_segment_t *tcp_seg = (tcp_segment_t*)((uint8_t*)pckt + (pckt->VerIHL&0x0F)*4);
		return fetch_tcp_segment(tcp_seg, length-(pckt->VerIHL&0x0F)*4, pckt->IP_addr_src, pckt->IP_addr_dst);
	} else if(pckt->Protocol == UDP_PROTOCOL) {
		udp_datagram_t *udp_dtgm = (udp_datagram_t*)((uint8_t*)pckt + (pckt->VerIHL&0x0F)*4);
		return fetch_udp_datagram(udp_dtgm, length-(pckt->VerIHL&0x0F)*4, pckt->IP_addr_src, pckt->IP_addr_dst);
	} else
		return USB_IGNORE;
}

static usb_error_t fetch_ethernet_frame(eth_frame_t *frame, size_t length) {
	if(frame->Ethertype == ETH_IPV4 && !memcmp(frame->MAC_dst, MAC_ADDR, 6)) {
		src_mac_addr = frame->MAC_src;
		ipv4_packet_t *ipv4_pckt = (ipv4_packet_t*)((uint8_t*)frame+sizeof(eth_frame_t)-4); /* -4=-crc */
		return fetch_IPv4_packet(ipv4_pckt, length-sizeof(eth_frame_t)+4); /* No CRC */
	} else if((!memcmp(frame->MAC_dst, MAC_ADDR, 6) || cmpbroadcast(frame->MAC_dst)) && frame->Ethertype == ETH_ARP)
		fetch_arp_msg(frame);
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
	#ifdef DEBUG
		static int nbdebug = 0;
		char tmp[30];
		unsigned int x, y;
		os_GetCursorPos(&x, &y);
		os_SetCursorPos(0, 0);
		sprintf(tmp, "%d", nbdebug++);
		os_PutStrFull(tmp);
		os_SetCursorPos(x, y);
	#endif // DEBUG
	if(netinfo.configuring && event == USB_DEVICE_CONNECTED_EVENT)
	{
		const rndis_init_msg_t rndis_initmsg = {RNDIS_INIT_MSG, 24, 0, 1, 0, 0x0400};
		const rndis_set_msg_t rndis_setpcktflt = {RNDIS_SET_MSG , 32, 4, 0x0001010e, 4, 20, 0, 0x2d};
		const usb_control_setup_t out_ctrl = {0x21, 0, 0, 0, 0};
		const usb_control_setup_t in_ctrl = {0xa1, 1, 0, 0, 0x0400};
		uint8_t buffer[512];
		size_t len = 0;
		uint8_t cur_interface = 0; /* b0 -> wc, b1 -> cdc */
		uint8_t i;

		if(!netinfo.connected)
			usb_Init(usbHandler, NULL, NULL, USB_DEFAULT_INIT_FLAGS);
		netinfo.device = (usb_device_t)event_data;
		netinfo.connected = true;
		usb_ResetDevice(netinfo.device);
		while(!netinfo.enabled)
			usb_WaitForEvents();

		/*********** Configuration USB ***********/
		usb_GetDescriptor(netinfo.device, USB_CONFIGURATION_DESCRIPTOR, 0, buffer, 512, &len);
		if(!len)
			return USB_ERROR_FAILED;
		i = 0;
		while(i<len) {
			if(*(buffer+i+1)==USB_INTERFACE_DESCRIPTOR) {
				if(*(buffer+i+5)==USB_WIRELESS_CONTROLLER_CLASS && *(buffer+i+6)==RNDIS_SUBCLASS && *(buffer+i+7)==RNDIS_PROTOCOL) {
					cur_interface = 1; /* wireless controller */
					netinfo.int_wc = *(buffer+i+2);
				} else if(*(buffer+i+5)==USB_CDC_DATA_CLASS && *(buffer+i+6)==0x00 && *(buffer+i+7)==0x00) {
					cur_interface = 2; /* cdc interface */
					netinfo.int_cdc = *(buffer+i+2);
				} else
					cur_interface = 0;
			} else if(*(buffer+i+1)==USB_ENDPOINT_DESCRIPTOR) {
				if(cur_interface == 1)
					netinfo.ep_wc = *(buffer+i+2) & 0x7F;
				else if(cur_interface == 2)
					netinfo.ep_cdc = *(buffer+i+2) & 0x7F;
			}
			i += *(buffer+i);
		}
		if(!netinfo.ep_wc || !netinfo.ep_cdc) {
			netinfo.connected = false;
			return USB_IGNORE;
		}
		if(usb_SetConfiguration(netinfo.device, (usb_configuration_descriptor_t*)buffer, len) != USB_SUCCESS)
			return USB_ERROR_FAILED;

		netinfo.configuring = false; /* Preventing from calling the callback twice */
		/************** Configuration RNDIS ************/
		/* Init Out */
		memcpy(buffer, &out_ctrl, sizeof(usb_control_setup_t));
		buffer[6] = 24; /* wLength */
		memcpy(buffer+sizeof(usb_control_setup_t), &rndis_initmsg, sizeof(rndis_init_msg_t));
		do {
			usb_Transfer(usb_GetDeviceEndpoint(netinfo.device, 0), buffer, 0, 3, &len);
		} while(len == 0);

		memcpy(buffer, &in_ctrl, sizeof(usb_control_setup_t));
		do {
			usb_Transfer(usb_GetDeviceEndpoint(netinfo.device, 0), buffer, 0, 3, &len);
		} while(len == 0 || ((rndis_msg_t*)(buffer+sizeof(usb_control_setup_t)))->MessageType != RNDIS_INIT_CMPLT);

		memcpy(buffer, &out_ctrl, sizeof(usb_control_setup_t));
		buffer[6] = 32; /* wLength */
		memcpy(buffer+sizeof(usb_control_setup_t), &rndis_setpcktflt, sizeof(rndis_setpcktflt));
		do {
			usb_Transfer(usb_GetDeviceEndpoint(netinfo.device, 0), buffer, 0, 3, &len);
		} while(len == 0);

		memcpy(buffer, &in_ctrl, sizeof(usb_control_setup_t));
		do {
			usb_Transfer(usb_GetDeviceEndpoint(netinfo.device, 0), buffer, 0, 3, &len);
		} while(len == 0 || ((rndis_msg_t*)(buffer+sizeof(usb_control_setup_t)))->MessageType != RNDIS_SET_CMPLT);
		
		dhcp_init();
	}
	else if(event == USB_DEVICE_ENABLED_EVENT) {
		netinfo.enabled = true;
	} else if(event == USB_DEVICE_DISABLED_EVENT) {
		netinfo.enabled = false;
	} else if(event == USB_DEVICE_DISCONNECTED_EVENT) {
		netinfo.connected = false;
		usb_Init(usbHandler, NULL, NULL, USB_DEFAULT_INIT_FLAGS);
	}
	return USB_SUCCESS;
}


#ifdef DEBUG
static void debug(const void *addr, size_t len) {
	uint8_t *content = (uint8_t*)addr;
	char tmp[4];
	size_t i;
	const char *DIGITS = "0123456789ABCDEF";
	for(i=0; i<len; i++) {
		if(i && i%8 == 0)
			boot_NewLine();
		tmp[0] = ' ';
		tmp[1] = DIGITS[*(content+i)/16];
		tmp[2] = DIGITS[*(content+i)%16];
		tmp[3] = 0;
		os_PutStrFull(tmp);
	}
	boot_NewLine();
}

static void disp(unsigned int val) {
	uint24_t value = (uint24_t)val;
	char tmp[20];
	sprintf(tmp, "DISP : %u ", value);
	os_PutStrFull(tmp);
	boot_NewLine();
}
#endif // DEBUG
