/**
 *--------------------------------------
 * Lib Name: webgtrce
 * Author: Mathis Lavigne aka Epharius
 * License:
 * Description: This librairy aim at allowing any program to access the internet.
 *--------------------------------------
 */

#include <tice.h>
#include <keypadc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <usbdrvce.h>
#include <stdarg.h>
#include "../include/webgtrce.h"


static uint8_t MAC_ADDR[6] = {0xDA, 0xA5, 0x59, 0x9b, 0x71, 0xa8};
static uint32_t IP_ADDR = 0;

/*************************************************************\
 * à terme : - renvoyer les packets aux bout d'un certain temps
 *			 notamment dhcp qui fait souvent de la merde.
 *			 - choisir seq_number aleatoirement.
 *			 - Le permier dns answer est pas forcément le bon (cf tiplanet)
 *			 il faudra donc affiner la requête DNS.
 *			 - Mettre device en variable globale plutôt.
 *			 - Ajouter un checksum à UDP
\*************************************************************/

int main(void) {
	rndis_device_t device;
	usb_error_t ret_err;

	os_ClrHome();
	boot_NewLine();
	os_PutStrFull("RNDIS Connection... ");
	
	ret_err = rndis_init(&device);
	if(ret_err != USB_SUCCESS) {
		boot_NewLine();
		if(ret_err == USB_ERROR_NOT_SUPPORTED) {
			os_PutStrFull("Device not compatible...");
			boot_NewLine();
			os_PutStrFull("Please read the README formore information.");
		} else if(ret_err == USB_ERROR_FAILED)
			os_PutStrFull("Error: Connection lost!");
		else
			os_PutStrFull("Canceled!");
		while(!os_GetCSC()) {}
		goto _end;
	}
	os_PutStrFull("Done!");
	boot_NewLine();

	// Fait :		USB - RNDIS - Ethernet - IPv4 - UDP - DHCP - DNS - ARP - TCP
	// Maintenant : HTTP

	// Attention, DNS fournit des résultats pas forcément dans le premier answer
	// CF "à termes" (où il faudra aussi gérer les erreurs dns et renvoyer la requête)


	// Yeah ! Il faut que je communique ma joie parce que j'suis vraiment trop fort !
	// HTTPGet et HTTPPost ont l'air de fonctionner !!!
	// Il manque donc plus qu'à résoudre les cas particuliers (wikipedia entre autre, google ce serait pas mal) et tout est bon !
	// Une fois que les cas particuliers seront gérés (dont le prbl dns) ça part en close_connection puis "globalité" !
	// J'ai presque fini ! (enfin, je crois ?)


	// Du coup :
	// Normalement tout fonctionne à peu près
	// il faut encore :
	//	- résoudre le petit prbl avec wikipédia, j'ai l'impression de ne rien recevoir (mauvais dns ? pourtant j'init bien)
	//	- tester dans tout plein de situations
	//	- corriger le truc DNS (CF plus haut)
	
	// Puis dans un second temps :
	//	- close_connection
	//	- faire le truc de "globalité" (appeler reassemble en tant que callback)
	//	- chercher pourquoi on arrive pas à récup google.com (RAM CLEAR au bout d'un certain temps)
	//	- lease IP
	//	- regarder "à termes" si y'a d'autres choses... 


	os_PutStrFull("DHCP Request...     ");
	ret_err = dhcp_ip_request(&device);
	//if(ret_err != USB_SUCCESS) -> ne fonctionne pas ?
	//	goto _end;
	os_PutStrFull("Done!");
	boot_NewLine();
	os_PutStrFull("HTTP Request...     ");
	char *data = NULL;
	size_t len;
	HTTPPost("www.perdu.com", (void**)&data, &len, false, &device, 2, "Joyeux", "Noel", "La", "Bise");
	while(!os_GetCSC()) {}
	os_ClrHome();
	os_PutStrFull(data);
	while(!os_GetCSC()) {}
	if(data)
		free(data);
	os_PutStrFull("Done!");
	boot_NewLine();

	// The End.
	boot_NewLine();
	os_PutStrFull("Waiting for keypress...");
	_end:
	while(!os_GetCSC())
		usb_WaitForInterrupt();
	usb_Cleanup();
	return 0;
}

	//		est-ce que j'autorise une window size assez grande ou je fonctionne en segment->ack ?
	//		je renvoie un paquet au bout de combien de temps ?
	//		comment je gère une erreur (checksum ou ack_number etc) ?
	//		est-ce que je gère la possibilité d'envoyer du multi-packet ?
	//		est-ce que je fais aussi une vérification qu'il a bien renvoyé un bon ack (= notre seq_number) ?
	//			faudra d'ailleurs pas oublier d'augmenter en conséquence notre sequence number juste ici...

	// CDC Personnel (à restreindre ou à élargir en fonction)
	//  *	crucial
	// (*)	important
	// ~*~	facultatif
	//
	//		- ORGANISER une connexion
	//	->		 * 	Gérer les SYN, SYN/ACK, ACK du début de connexion
	//	_		(*)	Renvoyer un segment au bout d'un certain temps
	//	_		(*)	Terminer une connexion (FIN, FIN/ACK *2)
	//	_		~*~	Permettre la communication simultanée de plusieurs applications (utile seulement si la lib ne bloque pas l'application)
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


http_status_t HTTPGet(const char* url, void **data, size_t *transferred, bool keep_http_header, rndis_device_t *device) {
	// à terme, mettre le seq_num dans un structure genre "tcp_request" avec seq_num, ack_num, ip_dst, src_port...
	// Différent pour chaque requête.
	char null_pointer = 0x00;
	return http_request("GET", url, data, transferred, keep_http_header, device, &null_pointer);
}

http_status_t HTTPPost(const char* url, void **data, size_t *transferred, bool keep_http_header, rndis_device_t *device, int nb_params, ...) {
	if(nb_params == 0) {
		char null_pointer = 0x00;
		return http_request("POST", url, data, transferred, keep_http_header, device, &null_pointer);
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

	http_status_t status = http_request("POST", url, data, transferred, keep_http_header, device, params);
	free(params);
	return status;
}

static http_status_t http_request(const char *request_type, const char* url, void **data, size_t *transferred, bool keep_http_header, rndis_device_t *device, char *params) {
	static uint32_t seq_number = 0x12345678; // first client segment's sequence number
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
	uint32_t ip = send_dns_request(websitename, device);
	uint32_t server_sn;
	init_tcp_session(device, ip, 0xec87, &seq_number, &server_sn);

	/* Building HTTP request */
	size_t length = strlen(request_type) + 1 + !uri + 11 + 6 + strlen(url) + 4 + strlen(params); // 10=" HTTP/1.1\r\n", 6="Host: ", 4="\r\n\r\n"
	const size_t http_len = length;
	char *request = malloc(length+1);
	sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", request_type, uri ? url+websitelen : "/", websitename, params);
	free(websitename);

	/* Sending HTTP request */
	tcp_encapsulate((uint8_t**)&request, &length, ip, 0xec87, HTTP_PORT, seq_number, server_sn, FLAG_TCP_ACK|FLAG_TCP_PSH);
	seq_number += http_len;
	ipv4_encapsulate((uint8_t**)&request, &length, IP_ADDR, ip, TCP_PROTOCOL);
	ethernet_encapsulate((uint8_t**)&request, &length, device);
	rndis_send_packet((uint8_t**)&request, &length, device);
	free(request);

	/* Receiving HTTP response */
	usb_error_t error = reassemble_tcp_segments(data, ip, 0xec87, seq_number, &server_sn, device, transferred);
	if(error != USB_SUCCESS)
		return -1;
	http_status_t status = (((char*)*data)[9]-'0')*100 + (((char*)*data)[10]-'0')*10 + (((char*)*data)[11]-'0');
	
	//close_tcp_session(ip, device);

	if(keep_http_header)
		return status;

	size_t header_length = 0;
	while(*((uint32_t*)(*data+header_length)) != 0x0a0d0a0d) header_length++;
	header_length += 4;
	memcpy(*data, *data+header_length, *transferred-header_length);
	*data = realloc(*data, *transferred-header_length); /* Shrinking buffer */
	*transferred -= header_length;

	return status;
}


usb_error_t reassemble_tcp_segments(void **data, uint32_t expected_ip, uint16_t src_port, uint32_t cur_sn, uint32_t *cur_ackn, rndis_device_t *device, size_t *transferred) {
	// à terme, faire une fonction popqueuelist(ack_num);
	/* cur_ackn : last acked server's sequence number */
	tcp_segment_list_t *segment_list = NULL;
	size_t length;
	usb_error_t code_err;
	usb_error_t ret_err = USB_SUCCESS;
	const uint32_t beg_ackn = *cur_ackn;
	size_t content_length = 0;
	size_t content_received = 0;
	uint16_t ackn_next_header_segment = 0; /* ACK number of the next header segment (See "Third process") */
	bool chunked_mode = false;
	size_t chunk_counter = 0xffffff;
	do {
		boot_NewLine();
		tcp_segment_t *response = malloc(MAX_SEGMENT_SIZE+0x40); /* The MAX_SEGMENT_SIZE does not take into account the TCP header (which is at most 0x40 bytes */
		if(!response) {
			ret_err = USB_ERROR_NO_MEMORY;
			break;
		}
		code_err = receive_tcp_segment(&response, &length, expected_ip, device);
		if(code_err == USB_IGNORE) {
			ret_err = code_err;
			break;
		}

		const char *payload_response = (char*)response + 4*(response->dataOffset_flags>>4&0x0f);

		//if(response->dataOffset_flags&0x0x1000) /* If the ack flag is set */
		//	popqueuelist(response->ack_number, expected_ip, port);
		if((char*)response+length == payload_response) { /* If there's no payload */
			free(response);
			continue;
		}

		/* First process : chaining data */
		tcp_segment_list_t *new_segment_list = malloc(sizeof(tcp_segment_list_t));
		if(!new_segment_list) {
			ret_err = USB_ERROR_NO_MEMORY;
			break;
		}

		new_segment_list->relative_sn = getBigEndianValue((uint8_t*)&response->seq_number)-beg_ackn;
		new_segment_list->pl_length = length - 4*(response->dataOffset_flags>>4&0x0f);
		new_segment_list->segment = response;

		if(!segment_list) {
			new_segment_list->next = NULL;
			segment_list = new_segment_list;
			content_received += new_segment_list->pl_length;
			os_PutStrFull(" ajout");
		} else {
			tcp_segment_list_t *cur_el = segment_list;
			tcp_segment_list_t *prev_el = NULL;
			while(cur_el && cur_el->relative_sn < new_segment_list->relative_sn) {
				prev_el = cur_el;
				cur_el = cur_el->next;
			}
			if(cur_el && cur_el->relative_sn == new_segment_list->relative_sn) {
				os_PutStrFull(" dejarecu!");
				size_t len = 0;
				uint8_t *ack_msg = NULL;
				tcp_encapsulate(&ack_msg, &len, expected_ip, src_port, HTTP_PORT, cur_sn, *cur_ackn, FLAG_TCP_ACK);
				ipv4_encapsulate(&ack_msg, &len, IP_ADDR, expected_ip, TCP_PROTOCOL);
				ethernet_encapsulate(&ack_msg, &len, device);
				rndis_send_packet(&ack_msg, &len, device);
				free(ack_msg);
				continue;
			} else {
				new_segment_list->next = cur_el;
				if(prev_el)
					prev_el->next = new_segment_list;
				else
					segment_list = new_segment_list;
				content_received += new_segment_list->pl_length;
				os_PutStrFull(" ajout");
			}
		}

		/* Second process : acking data */
		if(segment_list->relative_sn != 0) /* If we haven't received the first segment yet... */
			continue;

		tcp_segment_list_t *cur_el = segment_list;
		while(cur_el->next && cur_el->relative_sn+cur_el->pl_length == cur_el->next->relative_sn)
			cur_el = cur_el->next;
		if(*cur_ackn-beg_ackn != cur_el->relative_sn+cur_el->pl_length) {
			*cur_ackn = beg_ackn + cur_el->relative_sn + cur_el->pl_length;

			size_t len = 0;
			uint8_t *ack_msg = NULL;
			tcp_encapsulate(&ack_msg, &len, expected_ip, src_port, HTTP_PORT, cur_sn, *cur_ackn, FLAG_TCP_ACK);
			ipv4_encapsulate(&ack_msg, &len, IP_ADDR, expected_ip, TCP_PROTOCOL);
			ethernet_encapsulate(&ack_msg, &len, device);
			rndis_send_packet(&ack_msg, &len, device);
			free(ack_msg);

			os_PutStrFull(" ack");
		}

		/* Third process : trying to find what the Content-Length value is */
		if(ackn_next_header_segment == new_segment_list->relative_sn) {
			tcp_segment_list_t *cur_seg_list = new_segment_list;
			tcp_segment_t *seg_processing;
			char *payload_processing;

			third_process:

			seg_processing = new_segment_list->segment;
			payload_processing = (char*)seg_processing + 4*(seg_processing->dataOffset_flags>>4&0x0f);

			//ret_status = (payload_processing[9]-0x30)*100 + (payload_processing[10]-0x30)*10 + (payload_processing[11]-0x30);
			//if(ret_status != HTTP_STATUS_OK)
			//	break;
			/* Searching for the Content-Length field */
			const char *ptr = payload_processing;
			const char cont_len[] = "Content-Length:";
			const char cont_enc[] = "Transfer-Encoding: chunked\r\n";
			while(*((uint32_t*)ptr) != 0x0a0d0a0d && ptr-(char*)seg_processing<(int)length) {
				ptr += 2;
				if(!memcmp(ptr, cont_len, 15)) { /* If we found it, we update the content_length value */
					ptr += 15;
					while(*ptr == ' ') ptr++; /* Ignoring whitespaces */
					while(*ptr >= 0x30 && *ptr <= 0x39) {
						content_length = content_length*10 + (*ptr-0x30);
						ptr++;
					}
				} else if(!memcmp(ptr, cont_enc, 28))
					chunked_mode = true;
				while(ptr-(char*)seg_processing<(int)length && (*ptr != 0x0d || *(ptr+1) != 0x0a)) ptr++;
			}
			/* If the payload is more large than we can handle, returning. */
			if(content_length>65000) {
				ret_err = USB_ERROR_NO_MEMORY;
				break;
			}
			if(ptr-(char*)seg_processing>=(int)length) {
				/* If we came at the end of the segment without reaching the end of the HTTP Header... */
				ackn_next_header_segment += cur_seg_list->pl_length;
				if(cur_seg_list->next && cur_seg_list->relative_sn+cur_seg_list->pl_length == cur_seg_list->next->relative_sn) {
					cur_seg_list = cur_seg_list->next;
					goto third_process;
				} else
					continue;
			}
			ptr += 4;
			if(!chunked_mode)
				content_length += ackn_next_header_segment + (ptr-payload_processing);
			else /* Cheating a little bit (by considering that the header is a chunk) */
				chunk_counter = (cur_seg_list->relative_sn - new_segment_list->relative_sn) + (ptr - payload_processing);
		}

		/* Fourth process : if the content is chunked... */
		if(chunk_counter != 0xffffff && *cur_ackn-beg_ackn == new_segment_list->relative_sn+new_segment_list->pl_length) {
			tcp_segment_list_t *cur_seg_list = new_segment_list;
			tcp_segment_t *seg_processing;
			char *payload_processing;

			fourth_process:

			seg_processing = new_segment_list->segment;
			payload_processing = (char*)seg_processing + 4*(seg_processing->dataOffset_flags>>4&0x0f);

			if(cur_seg_list->pl_length <= chunk_counter)
				chunk_counter -= cur_seg_list->pl_length;
			else {
				const char *ptr = payload_processing+chunk_counter;
				chunk_counter = getChunkSize(&ptr)+4;
				if(chunk_counter == 4)
					break;
				chunk_counter -= cur_seg_list->pl_length - (ptr-payload_processing);
			}
			
			if(cur_seg_list->next && cur_seg_list->relative_sn+cur_seg_list->pl_length == cur_seg_list->next->relative_sn) {
				cur_seg_list = cur_seg_list->next;
				goto fourth_process;
			}
		}
	} while(!content_length || (content_length && content_length>content_received));

	*data = malloc(1); /* to be reallocated... */
	if(!*data)
		ret_err = USB_ERROR_NO_MEMORY;
	tcp_segment_list_t *cur_seg = segment_list;
	tcp_segment_list_t *next_seg = NULL;
	size_t cur_size = 0;
	while(cur_seg) {
		next_seg = cur_seg->next;
		if(ret_err == USB_SUCCESS) {
			void *tmp = realloc(*data, cur_size+cur_seg->pl_length);
			if(!tmp) {
				free(*data);
				ret_err = USB_ERROR_NO_MEMORY;
				cur_size = 0;
			} else {
				*data = tmp;
				memcpy((char*)*data+cur_size, (char*)cur_seg->segment+4*(cur_seg->segment->dataOffset_flags>>4&0x0f), cur_seg->pl_length);
				cur_size += cur_seg->pl_length;
			}
		}
		free(cur_seg->segment);
		free(cur_seg);
		cur_seg = next_seg;
	}

	*transferred = cur_size;
	return ret_err;
}

usb_error_t init_tcp_session(rndis_device_t *device, uint32_t ip_dst, uint16_t src_port, uint32_t *fsn, uint32_t *next_ack) {
	/* Handshaking... */
	/* SYN */
	uint8_t *data = NULL;
	size_t length = 0;
	tcp_encapsulate(&data, &length, ip_dst, src_port, HTTP_PORT, (*fsn)++, 0, FLAG_TCP_SYN);
	ipv4_encapsulate(&data, &length, IP_ADDR, ip_dst, TCP_PROTOCOL);
	ethernet_encapsulate(&data, &length, device);
	rndis_send_packet(&data, &length, device);
	free(data);

	/* SYN ACK */
	tcp_segment_t *response = malloc(MAX_SEGMENT_SIZE+0x40); // The MAX_SEGMENT_SIZE does not take into account the TCP header (which is at most 0x40 bytes)
	receive_tcp_segment(&response, &length, ip_dst, device);
	if(!(response->dataOffset_flags&0x0200) || !(response->dataOffset_flags&0x1000))
		return USB_ERROR_FAILED;

	/* ACK */
	length = 0;
	data = NULL;
	tcp_encapsulate(&data, &length, ip_dst, src_port, HTTP_PORT, *fsn, getBigEndianValue((uint8_t*)&response->seq_number)+1, FLAG_TCP_ACK);
	ipv4_encapsulate(&data, &length, IP_ADDR, ip_dst, TCP_PROTOCOL);
	ethernet_encapsulate(&data, &length, device);
	rndis_send_packet(&data, &length, device);
	free(data);
	free(response);

	if(next_ack)
		*next_ack = getBigEndianValue((uint8_t*)&response->seq_number)+1;
	return USB_SUCCESS;
}

usb_error_t receive_tcp_segment(tcp_segment_t **tcp_segment, size_t *length, uint32_t expected_ip, rndis_device_t *device) {
	/**
	 *	Checks the checksum.
	 */
	uint8_t resp[MAX_SEGMENT_SIZE+180];
	size_t len;
	while(!os_GetCSC()) {
		usb_Transfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), resp, MAX_SEGMENT_SIZE+180, 1, &len);		
		// Il manque l'info len qui est donnée dans le callback
		//transferred = false;
		//usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), resp, MAX_SEGMENT_SIZE+180, transfer_callback, &transferred);
		//do {
		//	usb_WaitForInterrupt();
		//	key = os_GetCSC();
		//} while(!key && !transferred);
		const eth_frame_t *ethernet_frame = (eth_frame_t*)(resp + sizeof(rndis_packet_msg_t));
		if(!memcmp(ethernet_frame->MAC_dst, MAC_ADDR, 6)) { // if it's for us (broadcast messages aren't interesting here)
			if(ethernet_frame->Ethertype == ETH_IPV4) {
				const ipv4_packet_t *ipv4_pckt = (ipv4_packet_t*)((uint8_t*)ethernet_frame+sizeof(eth_frame_t)-4); // -4=-crc
				if(ipv4_pckt->IP_addr_src == expected_ip && ipv4_pckt->Protocol == TCP_PROTOCOL) {
					const tcp_segment_t *tcp_seg = (tcp_segment_t*)((uint8_t*)ipv4_pckt + (ipv4_pckt->VerIHL&0x0F)*4);
					uint16_t seg_len = len-sizeof(rndis_packet_msg_t)-sizeof(eth_frame_t)+4-(ipv4_pckt->VerIHL&0x0F)*4;
					if(!tcp_checksum((uint8_t*)tcp_seg, seg_len, expected_ip, IP_ADDR) && tcp_seg->port_src/256 == HTTP_PORT%256 && tcp_seg->port_src%256 == HTTP_PORT/256) {
						*length = seg_len;
						memcpy(*tcp_segment, tcp_seg, *length);
						return USB_SUCCESS;
					}
				}
			}
		}
		if((!memcmp(ethernet_frame->MAC_dst, MAC_ADDR, 6) || cmpbroadcast(ethernet_frame->MAC_dst)) && ethernet_frame->Ethertype == ETH_ARP)
			send_arp_reply(resp, device);
	}
	return USB_IGNORE;
}


void send_arp_reply(uint8_t *rndis_packet, rndis_device_t *device) {
	eth_frame_t *ethernet_frame = (eth_frame_t*)(rndis_packet + sizeof(rndis_packet_msg_t));
	arp_message_t *arp_msg = (arp_message_t*)((uint8_t*)ethernet_frame + sizeof(eth_frame_t) - 4);
	if(ethernet_frame->Ethertype != ETH_ARP || arp_msg->HwType != 0x0100 || arp_msg->Operation != 0x0100 || arp_msg->ProtocolType != ETH_IPV4 || arp_msg->IP_dst != IP_ADDR)
		return;
	memcpy(ethernet_frame->MAC_dst, ethernet_frame->MAC_src, 6);
	memcpy((uint8_t*)ethernet_frame->MAC_src, MAC_ADDR, 6);
	memcpy((uint8_t*)arp_msg->MAC_dst, (uint8_t*)arp_msg->MAC_src, 10);
	memcpy((uint8_t*)arp_msg->MAC_src, MAC_ADDR, 6);
	arp_msg->IP_src = IP_ADDR;
	arp_msg->Operation = 0x0200;

	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, device->ep_cdc), rndis_packet, sizeof(rndis_packet_msg_t) + sizeof(eth_frame_t)-4 + sizeof(arp_message_t), NULL, NULL);
}


uint32_t send_dns_request(const char *addr, rndis_device_t *device) {
	size_t length = sizeof(dns_query_t)+strlen(addr)+2+4;
	uint8_t *query = calloc(length, 1); // 2=length byte at the begining of the string+0 terminated string
	query[2] = 0x01;
	query[5] = 0x01;

	// formating address for dns purposes
	char *cursor_qry = (char*)(query+sizeof(dns_query_t)+1);
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
	*(cursor_qry+2) = 1; // A (IPv4)
	*(cursor_qry+4) = 1; // IN (internet)

	udp_encapsulate(&query, &length, 0xd52f, DNS_PORT);
	ipv4_encapsulate(&query, &length, IP_ADDR, device->DNS_IP_addr, UDP_PROTOCOL);
	ethernet_encapsulate(&query, &length, device);
	usb_error_t ret_err = rndis_send_packet(&query, &length, device);
	free(query);
	if(ret_err)
		return ret_err;

	uint8_t answer[512];
	bool transferred;
	int key = 0;
	while(!key) {
		//usb_Transfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), answer, 512, 3, NULL);
		transferred = false;
		usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), answer, 512, transfer_callback, &transferred);
		do {
			usb_WaitForInterrupt();
			key = os_GetCSC();
		} while(!key && !transferred);

		const eth_frame_t *ethernet_frame = (eth_frame_t*)(answer + sizeof(rndis_packet_msg_t));
		if(!memcmp(ethernet_frame->MAC_dst, MAC_ADDR, 6)) { // if it's for us (broadcast messages aren't interesting here)
			if(ethernet_frame->Ethertype == ETH_IPV4) {
				const ipv4_packet_t *ipv4_pckt = (ipv4_packet_t*)((uint8_t*)ethernet_frame+sizeof(eth_frame_t)-4); // -4=-crc
				if(ipv4_pckt->Protocol == UDP_PROTOCOL) {
					const udp_packet_t *udp_pckt = (udp_packet_t*)((uint8_t*)ipv4_pckt + (ipv4_pckt->VerIHL&0x0F)*4);
					if(udp_pckt->port_src/256 == DNS_PORT && udp_pckt->port_src%256 == 0x00) {
						const dns_query_t *dns_qry = (dns_query_t*)((uint8_t*)udp_pckt + sizeof(udp_packet_t));
						const uint8_t *resp = (uint8_t*)dns_qry + sizeof(dns_query_t) + (strlen(addr)+2+4);
						
						if((dns_qry->flags&0x8000) && (dns_qry->flags&0x0080) && !((dns_qry->flags&0x0F00) && *(resp+3)==0x01)) // if -it is a response -the recursion was available -no error occurred -the response is an IPv4 address
							return *((uint32_t*)(resp+12)); // we only take into account of the first answer
						else
							return USB_ERROR_FAILED; // the server reponse does not suit us
					}
				}
			}
		}
		if((!memcmp(ethernet_frame->MAC_dst, MAC_ADDR, 6) || cmpbroadcast(ethernet_frame->MAC_dst)) && ethernet_frame->Ethertype == ETH_ARP)
			send_arp_reply(answer, device);
	}
	return USB_IGNORE;
}


usb_error_t dhcp_ip_request(rndis_device_t *device) {
	/**
	 *	Sends an IPv4 request to the local server.
	 *	The RNDIS device must have been initialized with rndis_init() first.
	 *	@param device The RNDIS Device to communicate with.
	 *	@return USB_SUCCESS or an error.
	 *	@output device correct attributes (router_MAC_addr, DNS_IP_addr, DHCP_IP_addr) and static variable IP_ADDR.
	 */
	// DHCP DISCOVERY
	static uint32_t xid = 0x03F82639;
	const uint8_t beg_header[] = {0x01, 0x01, 0x06, 0x00};
	const uint8_t options_disc[] = {53, 1, 1, 0x37, 3, 1, 3, 6, 0xFF, 0};
	const size_t length_disc = sizeof(dhcp_message_t)+sizeof(options_disc);
	uint8_t *data_disc = calloc(length_disc, 1);
	memcpy(data_disc, &beg_header, 4);
	((uint32_t*)data_disc)[1] = xid;
	memcpy(data_disc+28, &MAC_ADDR, 6);
	((uint32_t*)data_disc)[59] = 0x63538263;
	memcpy(data_disc+240, &options_disc, sizeof(options_disc));
	send_dhcp_request(data_disc, length_disc, device);

	// planning DHCP REQUEST data
	const uint8_t options_req[] = {53, 1, 3, 0x37, 3, 1, 3, 6, 54, 4, 0, 0, 0, 0, 50, 4, 0, 0, 0, 0, 0xFF};
	const size_t length_req = sizeof(dhcp_message_t)+21; //1=0xFF, 20=options
	uint8_t *data_req = calloc(length_req, 1);
	memcpy(data_req, &beg_header, 4);
	((uint32_t*)data_req)[1] = xid;
	memcpy(data_req+28, &MAC_ADDR, 6);
	((uint32_t*)data_req)[59] = 0x63538263;
	memcpy(data_req+240, &options_req, 21);

	
	bool completed = false;
	uint8_t dhcp_error = 0;
	uint8_t response[512];
	int key = 0;
	bool transferred;
	uint32_t time = ((rtc_Days*24+rtc_Hours)*60+rtc_Minutes)*60+rtc_Seconds;
	while(!key && !completed && !dhcp_error) {
		transferred = false;
		usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), response, 512, transfer_callback, &transferred);
		do {
			uint32_t cur_time = ((rtc_Days*24+rtc_Hours)*60+rtc_Minutes)*60+rtc_Seconds;
			if(cur_time - time >= 2) {
				time = cur_time;
				send_dhcp_request(data_disc, length_disc, device);
			}
			usb_WaitForInterrupt();
			key = os_GetCSC();
		} while(!key && !transferred);

		const eth_frame_t *ethernet_frame = (eth_frame_t*)(response + sizeof(rndis_packet_msg_t));
		if(!memcmp(ethernet_frame->MAC_dst, MAC_ADDR, 6)) { // if it's for us (broadcast messages aren't interesting here)
			memcpy(device->router_MAC_addr, ethernet_frame->MAC_src, 6);
			if(ethernet_frame->Ethertype == ETH_IPV4) {
				const ipv4_packet_t *ipv4_pckt = (ipv4_packet_t*)((uint8_t*)ethernet_frame+sizeof(eth_frame_t)-4); // -4=-crc
				if(ipv4_pckt->Protocol == UDP_PROTOCOL) {
					const udp_packet_t *udp_pckt = (udp_packet_t*)((uint8_t*)ipv4_pckt + (ipv4_pckt->VerIHL&0x0F)*4);
					if(udp_pckt->port_dst == 0x4400) {
						const dhcp_message_t *dhcp_msg = (dhcp_message_t*)((uint8_t*)udp_pckt+sizeof(udp_packet_t));
						if(dhcp_msg->op == 0x02 && dhcp_msg->xid == xid) {
							IP_ADDR = dhcp_msg->yiaddr;
							device->DHCP_IP_addr = dhcp_msg->siaddr;
							const uint8_t *cur_opt = (uint8_t*)((uint8_t*)dhcp_msg+sizeof(dhcp_message_t));
							while(*cur_opt != 0xFF) {
								switch(*cur_opt) {
									case 53: // DHCP message type
										if(*(cur_opt+2) == 2) { // DHCP Offer
											((uint32_t*)(data_req+2))[62] = device->DHCP_IP_addr;
											((uint32_t*)data_req)[64] = IP_ADDR;
											delay(100); // that's funny but.. the calculator is too fast for some dhcp servers
											send_dhcp_request(data_req, length_req, device);
										} else if(*(cur_opt+2) == 5) // ACK
											completed = true;
										else if(*(cur_opt+2) == 6) // NACK
											dhcp_error = ERROR_DHCP_NACK;
										break;
									case 6: // DNS SERVER
										device->DNS_IP_addr = *((uint32_t*)(cur_opt+2)); // we only take the first entry
										break;
									case 51: // Lease time
										// nothing to do yet
										break;
									default:
										break;
								}
								cur_opt += *(cur_opt+1)+2;
							}
						}
					}
				}
			}
		}
	}
	xid++;
	free(data_disc);
	free(data_req);
	if(!completed) {
		os_PutStrFull("An error occurred...");
		return USB_ERROR_FAILED;
	}
	return USB_SUCCESS;
}

usb_error_t send_dhcp_request(uint8_t *data, size_t length, rndis_device_t *device) {
	uint8_t *old_data = data;
	data = calloc(length, 1); // it needs to be allocated with malloc
	memcpy(data, old_data, length);
	udp_encapsulate(&data, &length, CLIENT_DHCP_PORT, SERVER_DHCP_PORT);
	ipv4_encapsulate(&data, &length, 0x00000000, 0xFFFFFFFF, UDP_PROTOCOL);
	ethernet_encapsulate(&data, &length, device);
	usb_error_t ret_err = rndis_send_packet(&data, &length, device);

	free(data);
	return ret_err;
}


void tcp_encapsulate(uint8_t **data, size_t *length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags) {
	/**
	 *	Encapsulates data with a TCP header.
	 *	The current version is not able to break down data into several ipv4 packets.
	 *	Consequently, this lib is not aim at uploading large amount of data.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param ip_dst The IP of the target server.
	 *	@param port_dst The destination port. For example TCP_PORT (443) or HTTP (80).
	 *	@param ack_number The 32-bits number that must be written in the ACK field.
	 *	@param flags For example FLAG_TCP_ACK for acknowledging a segment.
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */

	//			Faire en sorte qu'on puisse mettre les options en paramètre plutôt
	uint8_t *old_data = *data;
	if(flags&FLAG_TCP_SYN)
		*data = calloc(*length+sizeof(tcp_segment_t)+4, 1);
	else
		*data = calloc(*length+sizeof(tcp_segment_t), 1);
	(*data)[0] = port_src/256;
	(*data)[1] = port_src%256;
	(*data)[2] = port_dst/256;
	(*data)[3] = port_dst%256;
	(*data)[4] = seq_number/16777216;
	(*data)[5] = seq_number/65536;
	(*data)[6] = seq_number/256;
	(*data)[7] = seq_number%256;
	(*data)[8] = ack_number/16777216;
	(*data)[9] = ack_number/65536;
	(*data)[10] = ack_number/256;
	(*data)[11] = ack_number%256;
	if(flags&FLAG_TCP_SYN)
		(*data)[12] = 0x60|(flags&0x0100);
	else
		(*data)[12] = 0x50|(flags&0x0100);
	(*data)[13] = flags&0x00FF;
	(*data)[14] = TCP_WINDOW_SIZE/256;	/* window size */
	(*data)[15] = TCP_WINDOW_SIZE%256;
	
	if(flags&FLAG_TCP_SYN) {
		const uint8_t options[] = {0x02, 0x04, MAX_SEGMENT_SIZE/256, MAX_SEGMENT_SIZE%256};
		memcpy(*data+sizeof(tcp_segment_t), options, sizeof(options));
		if(*length)
			memcpy(*data+sizeof(tcp_segment_t)+4, old_data, *length);
	} else if(*length)
		memcpy(*data+sizeof(tcp_segment_t), old_data, *length);
	if(flags&FLAG_TCP_SYN)
		*length += sizeof(tcp_segment_t)+4;
	else
		*length += sizeof(tcp_segment_t);
	
	uint16_t chksm = tcp_checksum(*data, *length, IP_ADDR, ip_dst);
	(*data)[16] = chksm/256;
	(*data)[17] = chksm%256;
	if(old_data)
		free(old_data);
}

uint16_t tcp_checksum(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	uint16_t chksmmsb = length/256 + (ip_dst/65536&0xff) + (ip_dst&0xff) + (ip_src/65536&0xff) + (ip_src&0xff);
	uint16_t chksmlsb = TCP_PROTOCOL + length%256 + (ip_dst/16777216&0xff) + (ip_dst/256&0xff) + (ip_src/16777216&0xff) + (ip_src/256&0xff);
	for(size_t i=0; i<length-1; i+=2) {
		chksmmsb += data[i];
		chksmlsb += data[i+1];
	}
	if(length%2)
		chksmmsb += data[length-1];
	chksmmsb += chksmlsb>>8;
	chksmlsb += chksmmsb>>8;
	return (uint16_t)~((chksmmsb<<8)+(chksmlsb&0x00FF));
}


void udp_encapsulate(uint8_t **data, size_t *length, uint16_t port_src, uint16_t port_dst) {
	/**
	 *	Encapsulates data with an UDP header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param port_dst The destination port. For example DHCP_PORT (68) or DNS_PORT (53).
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	uint8_t *old_data = *data;
	*data = calloc(*length+sizeof(udp_packet_t), 1);
	(*data)[0] = port_src/256;
	(*data)[1] = port_src%256;
	(*data)[2] = port_dst/256;
	(*data)[3] = port_dst%256;
	(*data)[4] = (*length+sizeof(udp_packet_t))/256;
	(*data)[5] = (*length+sizeof(udp_packet_t))%256;
	memcpy(*data+sizeof(udp_packet_t), old_data, *length);
	free(old_data);
	*length += sizeof(udp_packet_t);
}


void ipv6_encapsulate(uint8_t **data, size_t *length, ipv6_addr ip_src, ipv6_addr ip_dst) {
	/**
	 *	Encapsulates data with an IPv6 header.
	 *	This header is only aim at providing a way to make ICMPv6 messages.
	 *	Consequently Hop Limit is set to 1, NextHeader is set to 0 and an Hop-by-Hop option is put.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param ip_src Your IP or 0::0 if you have been attributed no IP yet (which will usually be the case).
	 *	@param ip_dst The IP of the target server (for broadcast messages : ff02::16).
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	const uint8_t hopByHopOption[] = {0x3a, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00};
	uint8_t *old_data = *data;
	*data = calloc(*length+sizeof(ipv6_packet_t)+8, 1); /* 8=Hop-by-Hop option */
	(*data)[0] = 0x06;
	((uint16_t*)*data)[2] = *length+8; /* 8=Hop-by-Hop option */
	(*data)[7] = 0x01; // Hop limit
	memcpy(*data+8, ip_src, 16);
	memcpy(*data+24, ip_dst, 16);
	memcpy(*data+sizeof(ipv6_packet_t), hopByHopOption, sizeof(hopByHopOption));
	memcpy(*data+sizeof(ipv6_packet_t)+8, old_data, *length);
	free(old_data);
	*length += sizeof(ipv6_packet_t)+8;
}


void ipv4_encapsulate(uint8_t **data, size_t *length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol) {
	/**
	 *	Encapsulates data with an IPv4 header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param device The device to communicate with. 
	 *	@param ip_src Your IP or 0.0.0.0 if you have been attributed no IP yet (for DHCP requests for example).
	 *	@param ip_dst The IP of the target server.
	 *	@param protocol Protocol of the data. For example ICMP_PROTOCOL (0x01), TCP_PROTOCOL (0x06) or UDP_PROTOCOL (0x11).
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	static uint16_t nbpacket = 0;
	const size_t size = *length+sizeof(ipv4_packet_t);
	const ipv4_packet_t packet = {0x45, 0x10, 0, 0, 0x40, 0x80, 0, 0, 0, 0};
	uint8_t *old_data = *data;
	*data = malloc(size);
	memcpy(*data, &packet, sizeof(ipv4_packet_t));
	(*data)[2] = size/256;
	(*data)[3] = size%256;
	(*data)[4] = nbpacket/256;
	(*data)[5] = nbpacket%256;
	(*data)[9] = protocol;
	((uint32_t*)*data)[3] = ip_src;
	((uint32_t*)*data)[4] = ip_dst;
	uint16_t chksm = ipv4_checksum((uint16_t*)*data, sizeof(ipv4_packet_t));
	(*data)[10] = chksm%256;
	(*data)[11] = chksm/256;
	memcpy(*data+sizeof(ipv4_packet_t), old_data, *length);
	free(old_data);
	*length = size;
	nbpacket++;
}

uint16_t ipv4_checksum(uint16_t *header, size_t length) {
	uint24_t sum = 0;
	for(size_t i=0; i<length/2; i++) 
		sum += header[i];
	return (uint16_t)~(sum+(sum >> 16));
}


void ethernet_encapsulate(uint8_t **data, size_t *length, rndis_device_t *device) {
	/**
	 *	Encapsulates data with an ethernet header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param device RNDIS device to communicate with.
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	uint8_t *old_data = *data;
	if(*length<46) /* An ethernet frame must be at least 64B */
		*data = calloc(64, 1);
	else
		*data = malloc(sizeof(eth_frame_t)+*length);
	memcpy(*data, device->router_MAC_addr, 6);
	memcpy(*data+6, MAC_ADDR, 6);
	((uint16_t*)*data)[6] = ETH_IPV4; // Ethertype : IPv4
	memcpy(*data+sizeof(eth_frame_t)-4, old_data, *length);
	if(*length<46)
		*length = 64;
	else
		*length += sizeof(eth_frame_t);
	uint32_t crc = crc32b(*data, *length-4);
	
	memcpy(*data+*length-4, &crc, 4);
	free(old_data);
}

#define CRC_POLY 0xEDB88320
uint32_t crc32b(uint8_t *data, size_t length) {
	/**
	 *	Computes ethernet crc 32bits. The bytes must be written reversed in the frame.
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


usb_error_t rndis_send_packet(uint8_t **data, size_t *length, rndis_device_t *device) {
	/**
	 *	Sends a packet to the device.
	 *	Blocks until the transfer finishes.
	 *	@param **data Pointer of the data to be sent, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param device The device to communicate with. 
	 *	@return USB_SUCCESS or an error.
	 */
	usb_error_t ret_err;
	uint8_t *old_data = *data;
	*data = malloc(sizeof(rndis_packet_msg_t)+*length);
	memset(*data, 0, sizeof(rndis_packet_msg_t));
	(*data)[0] = RNDIS_PACKET_MSG;
	(*data)[4] = (sizeof(rndis_packet_msg_t)+*length)%256;
	(*data)[5] = (sizeof(rndis_packet_msg_t)+*length)/256;
	(*data)[8] = 36;
	(*data)[12] = *length%256;
	(*data)[13] = *length/256;
	memcpy(*data+sizeof(rndis_packet_msg_t), old_data, *length);
	*length += sizeof(rndis_packet_msg_t);
	free(old_data);

	bool completed = false;
	ret_err = usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, device->ep_cdc), *data, *length, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();

	return ret_err;
}

usb_error_t rndis_init(rndis_device_t *device) {
	/**
		Waits until a rndis device is detected
		If any key is pressed, returns USB_IGNORE.
		If the RNDIS Device has been initialized properly, returns USB_SUCCESS.
		If not, returns an error.
	**/
	const rndis_init_msg_t rndis_initmsg = {RNDIS_INIT_MSG, 24, 0, 1, 0, 0x0400};
	const rndis_set_msg_t rndis_setpcktflt = {RNDIS_SET_MSG , 32, 1, 0x0001010e, 4, 20, 0, 0x2d};
	const usb_control_setup_t out_ctrl = {0x21, 0, 0, 0, 0};
	const usb_control_setup_t in_ctrl = {0xa1, 1, 0, 0, 0x0400};
	uint8_t desc[512];
	size_t len = 0;
	uint8_t cur_interface = 0; // b0 -> wc, b1 -> cdc
	bool completed;
	uint8_t i;
	device->int_wc = 0;
	device->int_cdc = 0;
	device->ep_wc = 0;
	device->ep_cdc = 0;
	device->enabled = false;

	_init:
	/*********** Connection ***********/
	device->connected = false;
	usb_Init(usbHandler, device, NULL, USB_DEFAULT_INIT_FLAGS);
	while(!os_GetCSC() && !device->connected)
		usb_WaitForInterrupt();
	if(!device->connected)
		return USB_IGNORE;
	usb_ResetDevice(device->device);
	while(!os_GetCSC() && !(device->enabled))
		usb_WaitForInterrupt();
	if(!device->enabled)
		return USB_IGNORE;

	/*********** Configuration USB ***********/
	usb_GetDescriptor(device->device, USB_CONFIGURATION_DESCRIPTOR, 0, desc, 512, &len);
	if(!len)
		return USB_ERROR_FAILED;
	i = 0;
	while(i<len) {
		if(*(desc+i+1)==USB_INTERFACE_DESCRIPTOR) {
			if(*(desc+i+5)==USB_WIRELESS_CONTROLLER_CLASS && *(desc+i+6)==RNDIS_SUBCLASS && *(desc+i+7)==RNDIS_PROTOCOL) {
				cur_interface = 1; // wireless controller
				device->int_wc = *(desc+i+2);
			} else if(*(desc+i+5)==USB_CDC_DATA_CLASS && *(desc+i+6)==0x00 && *(desc+i+7)==0x00) {
				cur_interface = 2; // cdc interface
				device->int_cdc = *(desc+i+2);
			} else
				cur_interface = 0;
		} else if(*(desc+i+1)==USB_ENDPOINT_DESCRIPTOR) {
			if(cur_interface == 1)
				device->ep_wc = *(desc+i+2) & 0x7F;
			else if(cur_interface == 2)
				device->ep_cdc = *(desc+i+2) & 0x7F;
		}
		i += *(desc+i);
	}
	if(!device->ep_wc || !device->ep_cdc) {
		device->connected = false;
		while(!os_GetCSC() && !device->connected)
			usb_WaitForInterrupt();
		if(!device->connected)
			return USB_IGNORE;
		goto _init;
	}
	if(USB_SUCCESS != usb_SetConfiguration(device->device, (usb_configuration_descriptor_t*)desc, len))
		return USB_ERROR_FAILED;


	/************** Configuration RNDIS ************/
	// Init Out
	completed = false;
	memcpy(desc, &out_ctrl, sizeof(usb_control_setup_t));
	desc[6] = 24; // wLength
	memcpy(desc+sizeof(usb_control_setup_t), &rndis_initmsg, sizeof(rndis_init_msg_t));
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	if(!completed)
		return USB_IGNORE;
	// Init In
	completed = false;
	memcpy(desc, &in_ctrl, sizeof(usb_control_setup_t));
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	if(!completed)
		return USB_IGNORE;
	// set OID_GEN_CURRENT_PACKET_FILTER with default value
	completed = false;
	memcpy(desc, &out_ctrl, sizeof(usb_control_setup_t));
	desc[6] = 32; // wLength
	memcpy(desc+sizeof(usb_control_setup_t), &rndis_setpcktflt, sizeof(rndis_setpcktflt));
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	if(!completed)
		return USB_IGNORE;
	memcpy(desc, &in_ctrl, sizeof(usb_control_setup_t));
	completed = false;
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	if(!completed)
		return USB_IGNORE;


	memset(&(device->router_MAC_addr), 0xFF, 6);
	srand(rtc_Time());
	MAC_ADDR[5] = randInt(0, 0xFF);
	return USB_SUCCESS;
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


static usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *device) {
	static int nbdebug = 0;
	char tmp[30];
	unsigned int x, y;
	os_GetCursorPos(&x, &y);
	os_SetCursorPos(0, 0);
	sprintf(tmp, "%d", nbdebug++);
	os_PutStrFull(tmp);
	os_SetCursorPos(x, y);
	if(event == USB_DEVICE_CONNECTED_EVENT) {
		((rndis_device_t*)device)->device = (usb_device_t)event_data;
		((rndis_device_t*)device)->connected = true;
	} else if(event == USB_DEVICE_ENABLED_EVENT)
		((rndis_device_t*)device)->enabled = true;
	else if(event == USB_DEVICE_DISABLED_EVENT)
		((rndis_device_t*)device)->enabled = false;
	else if(event == USB_DEVICE_DISCONNECTED_EVENT)
		((rndis_device_t*)device)->connected = false;
	return USB_SUCCESS;
}

static usb_error_t transfer_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *completed) {
	//char tmp[30];
	//sprintf(tmp, "CALLBACK ! %u - %u ", status, transferred);
	//os_PutStrFull(tmp);
	//boot_NewLine();
	if(!status && transferred)
		*((bool*)completed) = true;
	return USB_SUCCESS;
}


static void debug(void *addr, size_t len) {
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
	char tmp[30];
	sprintf(tmp, "DISP : %u ", value);
	os_PutStrFull(tmp);
	boot_NewLine();
}
