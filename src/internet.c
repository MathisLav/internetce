// TODO
//	- Splitter les protocoles dans des fichiers différents
//	- Créer sur l'ordi un webserver de test et un programme de test de la lib avec différents test cases


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
#include <ctype.h>

#define DEBUG_LEVEL NO_DEBUG

#define max(x, y) (x > y ? x : y)
#define min(x, y) (x < y ? x : y)


/**
 * Global variables
 */
network_info_t netinfo;
static msg_queue_t *dhcp_last_msg_queue = NULL;
static uint8_t MAC_ADDR[6] = {0xEA, 0xA5, 0x59, 0x9C, 0xC1, 0x1E};
static uint8_t *src_mac_addr; /* For dhcp purposes (we need to acknowledge the router's mac address) */
static http_data_list_t *http_data_list = NULL;
static msg_queue_t *send_queue = NULL;
static port_list_t *listened_ports = NULL;
static http_exchange_list_t *http_exchanges;


web_status_t web_HTTPGet(const char* url, http_data_t **data, bool keep_http_header) {
	char pointer_to_null = 0x00;
	return http_request("GET", url, data, keep_http_header, &pointer_to_null);
}

web_status_t web_HTTPPost(const char* url, http_data_t **data, bool keep_http_header,
						   int nb_params, ...) {
	// TODO escape special chars such as '&'
	if(nb_params == 0) {
		char pointer_to_null = 0x00;
		return http_request("POST", url, data, keep_http_header, &pointer_to_null);
	}
	size_t param_len = 0;
	char *params = malloc(1);  /* To be reallocated */
	va_list list_params;
	va_start(list_params, nb_params);
	/* Turning the va parameters into a string like "param1=v1&param2=v2...paramN=vN\0" */
	for(uint8_t i = 0; i < nb_params * 2; i += 2) {
		const char *arg_name = va_arg(list_params, const char*);
		const char *arg_value = va_arg(list_params, const char*);
		const size_t new_param_size = strlen(arg_name) + strlen(arg_value) + 2 /* '=' and '&' */;
		void *tmp = realloc(params, param_len + new_param_size + 1 /* 1='\0' */);
		if(tmp == NULL) {
			free(params);
			return WEB_NOT_ENOUGH_MEM;
		}
		params = tmp;
		snprintf(&params[param_len], new_param_size + 1 /* 1='\0' */, "%s=%s&", arg_name, arg_value);
		param_len += new_param_size;
	}
	params[param_len - 1] = '\0';  /* Replacing the last & with the NULL char */
	va_end(list_params);

	/* The NULL char is already taken into account in param_len */
	const size_t max_size_chars = 5;  /* len(MAX_UINT16_T) == len('65535') == 5 */
	const size_t post_info_size = strlen(POST_HTTP_INFO) - (2 * 2) /* 2 '%s' */ + max_size_chars + param_len;
	char post_info[post_info_size];
	snprintf(post_info, post_info_size, POST_HTTP_INFO, param_len, params);
	free(params);

	web_status_t status = http_request("POST", url, data, keep_http_header, post_info);
	return status;
}

static uint32_t ip_ascii_to_hex(const char *ipstr) {
	uint32_t ip = 0;
	uint8_t index = 0;
	for(int i = 0; i < 4; i++) {
		size_t particule = 0;
		for(int j = 0; j < 3; j++) {
			if(ipstr[index] == '.' || ipstr[index] == '\0') {
				break;
			} else if(ipstr[index] >= '0' && ipstr[index] <= '9') {
				particule = particule * 10 + (ipstr[index] - '0');
			} else {
				return 0xffffffff;
			}
			index++;
		}
		if(particule > 255) {
			return 0xffffffff;
		}
		ip = (ip >> 8) + ((uint32_t)particule << 24);
		index++;
	}
	return ip;
}

static void check_timeout(http_exchange_t *exch) {
	if(exch->timeout <= rtc_Time()) {
		exch->dirty = true;
		exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
		exch->status = WEB_TIMEOUT;
		dbg_err("Timeout");
	}
}

static web_status_t http_request(const char *request_type, const char* url, http_data_t **data,
								  bool keep_http_header, char *params) {
	/* HTTPS not supported yet */
	const char *https_str = "https://";
	if(!strcmp(url, https_str)) {
		dbg_err("HTTPS not supported");
		return WEB_NOT_SUPPORTED;
	}

	/* Ignoring http:// */
	const char *http_str = "http://";
	if(!strcmp(url, http_str)) {
		url += 7;
	}

	bool is_ip = true;
	size_t websitelen = 0;
	while(url[websitelen] != '/' && url[websitelen] != 0x00) {
		is_ip &= url[websitelen] < 'A';
		websitelen++;
	}

	bool has_path = url[websitelen] == '/'; /* '/' or 0x00 ? */

	/* Formatting website name */
	char websitename[websitelen + 1];
	memcpy(websitename, url, websitelen);
	websitename[websitelen] = 0x00;

	uint32_t ip;
	if(!is_ip) {
		ip = web_SendDNSRequest(websitename);
	} else {
		ip = ip_ascii_to_hex(websitename);
	}
	if(ip == 0xffffffff) {
		return WEB_DNS_ERROR;
	}

	/* Configuring request information */
	http_exchange_t *exch = malloc(sizeof(http_exchange_t));
	memset(exch, 0, sizeof(http_exchange_t));
	exch->tcp_exch.ip_dst = ip;
	exch->tcp_exch.port_src = web_RequestPort();
	exch->tcp_exch.port_dst = HTTP_PORT;
	exch->tcp_exch.cur_sn = random();
	exch->tcp_exch.beg_sn = exch->tcp_exch.cur_sn;
	exch->data = data;
	exch->keep_http_header = keep_http_header;
	exch->timeout = rtc_Time() + TIMEOUT_WEB;
	exch->tcp_exch.tcp_state = TCP_STATE_SYN_SENT;

	/* Chaining */
	http_exchange_list_t *http_el = malloc(sizeof(http_exchange_list_t));
	http_el->http_exch = exch;
	http_el->next = http_exchanges;
	http_exchanges = http_el;

	/* Initiating connection */
	web_ListenPort(exch->tcp_exch.port_src, fetch_http_msg, exch);
	const uint8_t options[] = {0x02, 0x04, MAX_SEGMENT_SIZE / 256, MAX_SEGMENT_SIZE % 256};
	add_tcp_queue(NULL, 0, exch, FLAG_TCP_SYN, sizeof(options), options);
	while(exch->tcp_exch.tcp_state != TCP_STATE_ESTABLISHED) {
		web_WaitForEvents();
		check_timeout(exch);
		if(exch->dirty) {
			const web_status_t ret_status = exch->status;
			wipe_http_exchange(exch);
			return ret_status;
		}
	}

	/* Building HTTP request */
	uint24_t length = (strlen(BASIC_HTTP_REQUEST) - (4 * 2) /* 4 '%s' options */ + strlen(request_type) +
					  !has_path /* if no path, add 1 for '/' char */ + strlen(url) + strlen(params));
	
	char request[length + 1];  /* 1='\0' */
	snprintf(request, length + 1, BASIC_HTTP_REQUEST, request_type, has_path ? &url[websitelen] : "/", websitename,
			 params);

	/* Sending HTTP request */
	add_tcp_queue(request, length, exch, FLAG_TCP_ACK | FLAG_TCP_PSH, 0, NULL);

	/* Waiting for the end of the request */
	while(exch->tcp_exch.tcp_state & (TCP_STATE_ESTABLISHED | TCP_STATE_SYN_SENT)) {
		web_WaitForEvents();
		check_timeout(exch);
		if(exch->dirty) {
			const web_status_t ret_status = exch->status;
			wipe_http_exchange(exch);
			return ret_status;
		}
	}

	web_status_t status = exch->status;
	/* Not freeing the connection data until the connection is properly closed */
	return status;
}

static void close_tcp_connection(http_exchange_t *exch) {
	if(exch->tcp_exch.tcp_state != TCP_STATE_ESTABLISHED && exch->tcp_exch.tcp_state != TCP_STATE_CLOSE_WAIT) {
		return;
	}

	add_tcp_queue(NULL, 0, exch, FLAG_TCP_FIN | FLAG_TCP_ACK, 0, NULL);
	switch(exch->tcp_exch.tcp_state) {
		case TCP_STATE_ESTABLISHED:
			exch->tcp_exch.tcp_state = TCP_STATE_FIN_WAIT_1;
			break;
		case TCP_STATE_CLOSE_WAIT:
			exch->tcp_exch.tcp_state = TCP_STATE_LAST_ACK;
			break;
		default:
			break;
	}

	/* Free the received segments to recover some space */
	tcp_segment_list_t *cur_seg = exch->tcp_exch.segment_list;
	tcp_segment_list_t *next_seg = NULL;
	while(cur_seg) {
		next_seg = cur_seg->next;
		free(cur_seg->segment);
		free(cur_seg);
		cur_seg = next_seg;
	}
	exch->tcp_exch.segment_list = NULL;
}


static int add_tcp_queue(char *data, size_t length, http_exchange_t *exchange, uint16_t flags, size_t opt_size,
						 const uint8_t *options) {
	/**
	 *	- Add segment to send_queue (call web_PushTCPSegment)
	 *	- Add segment to http queue (http_exchange_t pushed_seg field)
	 *	- Increase the sequence number
	 */
	msg_queue_t *queued = web_PushTCPSegment(data, length, exchange->tcp_exch.ip_dst, exchange->tcp_exch.port_src,
											 exchange->tcp_exch.port_dst, exchange->tcp_exch.cur_sn,
											 exchange->tcp_exch.cur_ackn, flags, opt_size, options);
	if(queued == NULL) {
		return -1;
	}
	exchange->tcp_exch.cur_sn += length;
	if(flags & (FLAG_TCP_FIN | FLAG_TCP_SYN)) {
		/* The next ack number will be incremented */
		exchange->tcp_exch.cur_sn++;
	}
	pushed_seg_list_t *new_seg = malloc(sizeof(pushed_seg_list_t));
	new_seg->next_rsn = (exchange->tcp_exch.cur_sn) - exchange->tcp_exch.beg_sn;
	new_seg->seg = queued;
	new_seg->next = exchange->tcp_exch.pushed_seg;
	exchange->tcp_exch.pushed_seg = new_seg;
	return 0;
}

static void fetch_ack(http_exchange_t *exchange, uint32_t ackn) {
	/**
	 *	Unofficial name: remove_tcp_segments_that_are_acked_by_ackn
	 *	Note: The segments in pushed_seg list are in descending order of sequence number.
	 */
	pushed_seg_list_t *cur_seg = exchange->tcp_exch.pushed_seg;
	pushed_seg_list_t *prev_seg = NULL;
	while(cur_seg && cur_seg->next_rsn > ackn - exchange->tcp_exch.beg_sn) {
		prev_seg = cur_seg;
		cur_seg = cur_seg->next;
	}

	if(!cur_seg) {
		return;
	}

	if(prev_seg) {
		prev_seg->next = NULL;
	} else {
		exchange->tcp_exch.pushed_seg = NULL;
	}

	pushed_seg_list_t *next_seg = NULL;
	while(cur_seg) {
		next_seg = cur_seg->next;
		web_popMessage(cur_seg->seg);
		free(cur_seg);
		cur_seg = next_seg;
	}
}

static size_t httpcpy(http_exchange_t *exch, size_t offset_dst, const void *src, size_t size, size_t *jump_chars) {
	/*
	 * Like memcpy but we can ignore some chars (chunks metadata, header)
	 * Return the number of copied bytes
	 */
	if(*jump_chars != 0) {
		if(size >= *jump_chars) {
			size -= *jump_chars;
			src = src + *jump_chars;
			*jump_chars = 0;
		} else {
			*jump_chars -= size;
			return 0;
		}
	}
	memcpy((*exch->data)->data + offset_dst, src, size);
	return size;
}

static void _fill_window(char *window, size_t size_window, tcp_segment_list_t *cur_seg, size_t chunk_offset) {
	const size_t chars_remaining = cur_seg->pl_length - chunk_offset;
	if(chars_remaining < size_window) {
		memcpy(window, get_payload_addr(cur_seg->segment) + chunk_offset, chars_remaining);
		const tcp_segment_list_t *next_seg = cur_seg->next;
		if(!next_seg) {
			memset(window + chars_remaining, 0, size_window - chars_remaining);
		} else {
			memcpy(window + chars_remaining, get_payload_addr(next_seg->segment), size_window - chars_remaining);
		}
	} else {
		memcpy(window, get_payload_addr(cur_seg->segment) + chunk_offset, size_window);
	}
}

static web_status_t return_http_data(http_exchange_t *exch) {
	http_data_list_t *new_http_data_el = malloc(sizeof(http_data_list_t));
	if(new_http_data_el == NULL) {
		exch->dirty = true;
		exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
		exch->status = WEB_NOT_ENOUGH_MEM;
		return WEB_NOT_ENOUGH_MEM;
	}

	/* Trying to find a name that is not already in used */
	char varstorage_name[9] = "WLCE0000";
	unsigned int n = 0;
	while(n <= 9999 && os_ChkFindSym(OS_TYPE_APPVAR, varstorage_name, NULL, NULL)) {
		n++;
		varstorage_name[7] = (n % 10) + '0';
		varstorage_name[6] = ((n / 10) % 10) + '0';
		varstorage_name[5] = ((n / 100) % 10) + '0';
		varstorage_name[4] = ((n / 1000) % 10) + '0';
	}
	if(n > 9999) {
		exch->dirty = true;
		exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
		free(new_http_data_el);
		exch->status = WEB_NOT_ENOUGH_MEM;
		return WEB_NOT_ENOUGH_MEM;
	}

	/* Data is stored in an appvar, in order to relieve the heap */
	/* The +2 corresponds to the first \r\n not being removed when the header is kept */
	const size_t final_size = exch->content_received - exch->chunks_metadata_length -
							  (exch->keep_http_header ? 0 : exch->header_length);
	*exch->data = os_CreateAppVar(varstorage_name, final_size);
	if(!(*exch->data)) {
		exch->dirty = true;
		exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
		free(new_http_data_el);
		exch->status = WEB_NOT_ENOUGH_MEM;
		return WEB_NOT_ENOUGH_MEM;
	}

	/*
	* The following code reassemble all segments in one, removing the chunk metadata if necessary.
	* As it is hard to understand, here is a pseudo algorithm of what it does:
	* 	For each TCP segment:
	*		For each complete chunk in the TCP segment:
	*			The first time, copy all data from the beggining of the segment to the next chunk metadata
	*			The other times, copy data between the previous chunk metadata to the next chunk metadata
	*			Get the offset of the next chunk metadata
	*		Repeat
	*		Copy the remaining data between the last chunk metadata and the end of the segment
	*	Repeat
	* Im aware this code may be difficult but it allows not to do giant memcpy to move the code backward for each chunk.
	* Note: For non-chunked data, the same code is used by specifying a first chunk of the size of the received data.
	*/
	tcp_segment_list_t *cur_seg = exch->tcp_exch.segment_list;
	size_t offset = 0;
	size_t jump_chars = exch->keep_http_header ? 0 : exch->header_length - 2; /* To ignore chunks metadata and header */
	size_t next_chunk_rsn;
	bool stop = false;
	bool keep_rn = false;  /* true = keep the \r\n before the first chunk metadata (end header second \r\n) */
	if(exch->data_chunked) {
		next_chunk_rsn = exch->header_length - 2;
		keep_rn = exch->keep_http_header;
	} else {  /* Non chunked data <=> a single big chunk of content_received length */
		next_chunk_rsn = exch->content_received;
	}
	while(!stop && cur_seg != NULL) {
		size_t prev_chunk_offset = 0;  /* Offset in the segment of the previous chunk */
		while(cur_seg->relative_sn + cur_seg->pl_length > next_chunk_rsn) {
			/* Copy & Update */
			const size_t cur_chunk_offset = next_chunk_rsn - cur_seg->relative_sn;
			const size_t copy_size = cur_chunk_offset - prev_chunk_offset;
			const size_t copied = httpcpy(exch, offset, get_payload_addr(cur_seg->segment) + prev_chunk_offset,
										  copy_size, &jump_chars);
			offset += copied;
			/* Where is the next one */
			char window[6];  /* 6 = (MAX_SIZE = "ffff") + "\r\n" */
			_fill_window(window, 6, cur_seg, cur_chunk_offset + 2);
			const uint24_t chunk_size = get_chunk_size(window, window + 6, &jump_chars);
			if(chunk_size == 0xffffff) {
				dbg_err("Couldn't read the chunk");
				os_DelVarArc(OS_TYPE_APPVAR, new_http_data_el->varname);
				free(new_http_data_el);
				exch->dirty = true;
				exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
				return WEB_ERROR_FAILED;
			} else if(chunk_size == 0) {
				prev_chunk_offset = cur_seg->pl_length;  /* Not copying what comes next */
				stop = true;
				break;
			} else {
				prev_chunk_offset = cur_chunk_offset;
				jump_chars += 4;  /* 4=\r\n...\r\n */
				next_chunk_rsn += chunk_size + jump_chars;
				if(keep_rn) {
					keep_rn = false;
					jump_chars -= 2;  /* keeping one of the \r\n */
				}
			}
		}
		const size_t remaining_size = cur_seg->pl_length - prev_chunk_offset;
		const size_t copied = httpcpy(exch, offset, get_payload_addr(cur_seg->segment) + prev_chunk_offset,
									  remaining_size, &jump_chars);
		offset += copied;
		cur_seg = cur_seg->next;
	}

	if(final_size != offset) {
		dbg_warn("The appvar is too big/small:");
		dbg_warn("Appvar size=%u, needed=%u", final_size, offset);
	}

	/*
	 * Getting the HTTP status code of the request.
	 * Requires that the HTTP status code is not cut into two TCP segments.
	 * But, hey, would it be OK to receive a first segment of less than 11 bytes?
	 */
	const char *hdr_seg = get_payload_addr(exch->tcp_exch.segment_list->segment);
	exch->status = (hdr_seg[9] - '0') * 100 +
				   (hdr_seg[10] - '0') * 10 +
				   (hdr_seg[11] - '0');

	/* Chaining... */
	strncpy(new_http_data_el->varname, varstorage_name, 9);
	new_http_data_el->next = http_data_list;
	http_data_list = new_http_data_el;

	web_LockData(exch->data);
	// TODO if(!keepalive)
	close_tcp_connection(exch);
	dbg_info("Received all data from %u", exch->tcp_exch.port_src);
	return WEB_SUCCESS;
}

static void fetch_tcp_flags(const tcp_segment_t *tcp_seg, http_exchange_t *exch, bool has_data) {
	/* If SYN/ACK */
	if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_SYN)) {
		exch->tcp_exch.beg_ackn = htonl(tcp_seg->seq_number) + 1;
		exch->tcp_exch.cur_ackn = exch->tcp_exch.beg_ackn;
		exch->tcp_exch.tcp_state = TCP_STATE_ESTABLISHED;
	}

	/* If RST */
	if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_RST)) {
		dbg_warn("RST received");
		exch->dirty = true;
		exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
		return;
	}

	/* If ACK */
	if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_ACK)) {
		fetch_ack(exch, htonl(tcp_seg->ack_number));
		switch(exch->tcp_exch.tcp_state) {
			case TCP_STATE_FIN_WAIT_1:
				dbg_verb("WAIT1 -> WAIT2");
				exch->tcp_exch.tcp_state = TCP_STATE_FIN_WAIT_2;
				break;
			case TCP_STATE_CLOSING:
				dbg_verb("CLOSING -> TIME_WAIT");
				exch->tcp_exch.tcp_state = TCP_STATE_TIME_WAIT;
				break;
			case TCP_STATE_LAST_ACK:
				/* The last ACK segment must be a segment with only the ACK flag set */
				if(tcp_seg->dataOffset_flags == htons(FLAG_TCP_ACK)) {
					dbg_verb("LAST_ACK -> CLOSED");
					exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
					exch->dirty = true;
				}
				break;
			default:
				break;
		}
	}

	/* If FIN */
	if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_FIN)) {
		exch->tcp_exch.cur_ackn++;
		switch(exch->tcp_exch.tcp_state) {
			case TCP_STATE_FIN_WAIT_1:
			case TCP_STATE_CLOSING:  /* in case the previous ack did not reach its destination */
				exch->tcp_exch.tcp_state = TCP_STATE_CLOSING;
				dbg_verb("WAIT1 -> CLOSING");
				break;
			case TCP_STATE_FIN_WAIT_2:
			case TCP_STATE_TIME_WAIT:
				exch->tcp_exch.tcp_state = TCP_STATE_TIME_WAIT;
				exch->tcp_exch.timeout_close = rtc_Time() + TIMEOUT_TIME_WAIT;
				dbg_verb("WAIT2 -> TIME_WAIT");
				break;
			case TCP_STATE_ESTABLISHED:
				dbg_verb("EST -> LAST_ACK");
			case TCP_STATE_CLOSE_WAIT:
				exch->tcp_exch.tcp_state = TCP_STATE_CLOSE_WAIT;
				break;
			default:
				dbg_verb("Unexpected FIN in %u state", exch->tcp_exch.tcp_state);
				break;
		}
	}

	/* If the ACK flag is not the only one to be set or there is data to acknowledge, send an ack segment */
	if((has_data || tcp_seg->dataOffset_flags & htons(FLAG_TCP_MASK)) != htons(FLAG_TCP_ACK)) {
		web_SendTCPSegment(NULL, 0, exch->tcp_exch.ip_dst, exch->tcp_exch.port_src, exch->tcp_exch.port_dst,
						   exch->tcp_exch.cur_sn, exch->tcp_exch.cur_ackn, FLAG_TCP_ACK, 0, NULL);
	}
}

static inline const char *get_payload_addr(const tcp_segment_t *seg) {
	return (const char *)seg + 4 * (seg->dataOffset_flags >> 4 & 0x0f);
}

static uint24_t search_in_window(tcp_segment_list_t *prev_seg, tcp_segment_list_t *cur_seg, const char *str,
								 uint24_t size_str) {
	const uint24_t window_size = cur_seg->pl_length + size_str;
	char window[window_size];
	if(prev_seg == NULL) {
		memset(window, 0, size_str);
	} else {
		memcpy(window, get_payload_addr(prev_seg->segment) + prev_seg->pl_length - size_str, size_str);
	}
	memcpy(window + size_str, get_payload_addr(cur_seg->segment), cur_seg->pl_length);

	/* Recoding memcmp so it is faster (I think? the constant cost of calling a C function is pretty big) */
	size_t iwin = 0;
	size_t istr;
	do {
		const size_t nexti = iwin + 1;
		for(istr = 0; istr < size_str; istr++) {
			if(str[istr] != window[iwin]) {
				break;
			}
			iwin++;
		}
		iwin = nexti;
	} while(istr != size_str && iwin < window_size);

	return iwin == window_size ? 0 : (iwin - 1);
}

static char *lowercase(char *str) {
	/* Lower in-place a string until the \r char */
	size_t index = 0;
	while(str[index] != '\r') {
		str[index] = tolower(str[index]);
		index++;
	}
	return str;
}

static const char *search_field_header(char *data, size_t length, const char *str, size_t size_str) {
	/* Search the field name preceded by a new line */
	char *ptr = data;
	bool search_str = false;  /* false=search \n true=search str */
	while(ptr < data + length) {
		if(*ptr == '\n') {
			search_str = true;
		} else if(search_str && memcmp(lowercase(ptr), str, size_str) == 0) {
			return ptr + size_str;
		} else {
			search_str = false;
		}
		ptr++;
	}
	return NULL;
}

static int search_content_size(http_exchange_t *exch) {
	/* update exch in place, return 0 if successful */
	char header[exch->header_length];
	size_t cur_size = 0;
	tcp_segment_list_t *cur_el = exch->tcp_exch.segment_list;
	/* Building a temporary representation of the entire HTTP header to search for some important fields */
	while(cur_el != NULL) {
		if(cur_size + cur_el->pl_length < exch->header_length) {
			memcpy(header + cur_size, get_payload_addr(cur_el->segment), cur_el->pl_length);
			cur_size += cur_el->pl_length;
			cur_el = cur_el->next;
		} else {
			memcpy(header + cur_size, get_payload_addr(cur_el->segment), exch->header_length - cur_size);
			break;
		}
	}

	const char content_length_str[] = "content-length:";
	const char *content_length_field = search_field_header(header, exch->header_length, content_length_str,
														   strlen(content_length_str));
	if(content_length_field != NULL) {
		const char *cur_ptr = content_length_field;
		/* Removing whitespaces */
		while(*cur_ptr == ' ') { cur_ptr++; }
		/* Get the content length */
		while(*cur_ptr >= '0' && *cur_ptr <= '9') {
			exch->content_length = exch->content_length * 10 + (*cur_ptr - '0');
			cur_ptr++;
		}
		if(exch->content_length == 0) {
			return -2;
		}
		exch->content_length += exch->header_length;
	} else {
		const char content_encoding_str[] = "transfer-encoding: chunked";
		const char *content_encoding_field = search_field_header(header, exch->header_length, content_encoding_str,
																 strlen(content_encoding_str));
		if(content_encoding_field != NULL) {
			exch->data_chunked = true;
			exch->next_chunk_rsn = exch->header_length;  /* Considering that the header is the first chunk */
		} else {
			return -1;
		}
	}
	return 0;
}

static web_status_t fetch_http_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
								   web_callback_data_t *user_data) {
	(void)port; /* Unused parameter */
	if(protocol != TCP_PROTOCOL)
		return WEB_SUCCESS;

	const tcp_segment_t *tcp_seg = (tcp_segment_t *)msg;
	http_exchange_t *exch = (http_exchange_t *)user_data;

	print_tcp_info(tcp_seg, exch, length);

	/* If the connection is not in established state or there's no payload */
	if(exch->tcp_exch.tcp_state != TCP_STATE_ESTABLISHED || (char *)msg + length == get_payload_addr(tcp_seg)) {
		fetch_tcp_flags(tcp_seg, exch, false);  /* Let's just fetch the TCP flags */
		return WEB_SUCCESS;
	}

	/*
	 * First process: creating and initializing the data list structure
	 */
	tcp_segment_t *response = malloc(length);
	if(!response) {
		dbg_err("No memory");
		exch->dirty = true;
		exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
		exch->status = WEB_NOT_ENOUGH_MEM;
		return WEB_NOT_ENOUGH_MEM;
	}
	memcpy(response, msg, length);  // TODO no need to store the TCP header?

	tcp_segment_list_t *new_segment_list = malloc(sizeof(tcp_segment_list_t));
	if(!new_segment_list) {
		dbg_err("No memory");
		free(response);
		exch->dirty = true;
		exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
		exch->status = WEB_NOT_ENOUGH_MEM;
		return WEB_NOT_ENOUGH_MEM;
	}
	new_segment_list->relative_sn = htonl(response->seq_number) - exch->tcp_exch.beg_ackn;
	new_segment_list->pl_length = length - 4 * (response->dataOffset_flags >> 4 & 0x0f);
	new_segment_list->segment = response;

	/*
	 * Second process : chaining the structure
	 */
	tcp_segment_list_t *prev_el = NULL;  /* this will also be useful later for searching for the header end */
	tcp_segment_list_t *seg_after = exch->tcp_exch.segment_list;
	while(seg_after && seg_after->relative_sn < new_segment_list->relative_sn) {
		prev_el = seg_after;
		seg_after = seg_after->next;
	}
	if(seg_after && seg_after->relative_sn == new_segment_list->relative_sn) {  /* deja vue */
		dbg_verb("Segment received twice");
		free(new_segment_list->segment);
		free(new_segment_list);
		fetch_tcp_flags(tcp_seg, exch, true);
		return WEB_SUCCESS;
	} else {
		new_segment_list->next = seg_after;
		if(prev_el) {
			prev_el->next = new_segment_list;
		} else {
			exch->tcp_exch.segment_list = new_segment_list;
		}
		exch->content_received += new_segment_list->pl_length;
	}

	/*
	 * Third process : acking data
	 */
	if(exch->tcp_exch.segment_list->relative_sn != 0) {  /* If we haven't received the first segment yet... */
		return WEB_SUCCESS;
	}
	tcp_segment_list_t *seg_to_ack = exch->tcp_exch.segment_list;
	while(seg_to_ack->next && seg_to_ack->relative_sn + seg_to_ack->pl_length == seg_to_ack->next->relative_sn) {
		seg_to_ack = seg_to_ack->next;
	}
	if(exch->tcp_exch.cur_ackn - exch->tcp_exch.beg_ackn != seg_to_ack->relative_sn + seg_to_ack->pl_length) {
		exch->tcp_exch.cur_ackn = exch->tcp_exch.beg_ackn + seg_to_ack->relative_sn + seg_to_ack->pl_length;
	}
	fetch_tcp_flags(tcp_seg, exch, true);  /* Time to fetch the flag and send an ACK */

	/*
	 * Fourth process : extracting the header to get the content-length or content encoding field
	 * prev_el has been set to the previous segment in the tcp segment list during the 2nd process
	 */
	tcp_segment_list_t *cur_el = new_segment_list;
	while(!exch->header_length && cur_el && exch->next_hdrseg_check == cur_el->relative_sn) {
		const uint24_t offset = search_in_window(prev_el, cur_el, "\r\n\r\n", 4);
		if(offset != 0) {  /* Offset can't be zero because it returns the offset of the next byte after the string */
			exch->header_length = cur_el->relative_sn + offset;
			if(search_content_size(exch) != 0) {
				dbg_err("Size not found and not chunk encoded");
				pause();
				exch->dirty = true;
				exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
				exch->status = WEB_ERROR_FAILED;
				return WEB_ERROR_FAILED;
			} else if(exch->content_length > OS_VAR_MAX_SIZE) {
				dbg_err("Content too big");
				pause();
				exch->dirty = true;
				exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
				exch->status = WEB_NOT_ENOUGH_MEM;
				return WEB_NOT_ENOUGH_MEM;
			}
		} else {
			exch->next_hdrseg_check += cur_el->pl_length;
			cur_el = cur_el->next;
		}
	}

	/*
	 * Fifth process : if the content is chunked
	 */
	if(exch->data_chunked) {
		tcp_segment_list_t *cur_el = exch->tcp_exch.segment_list;
		uint24_t chunk_size;
		uint24_t chunk_chars;
		/* While the next chunk is in an already received & acked segment */
		while(exch->next_chunk_rsn < exch->tcp_exch.cur_ackn - exch->tcp_exch.beg_ackn) {
			/* If the chunk is astride two TCP segments */
			if(exch->rsn_end_chunk != 0) {
				dbg_verb("Dangerous chnunk case");
				/* Searching for the involved segment (cur_el can be NULL) */
				/* prev_el won't be NULL as we are 100% sure this will not be the first segment */
				tcp_segment_list_t *prev_el = NULL;
				while(cur_el && cur_el->relative_sn < exch->rsn_end_chunk) {
					prev_el = cur_el;
					cur_el = cur_el->next;
				}
				if(!cur_el || cur_el->relative_sn != exch->rsn_end_chunk) {
					break;
				}
				const uint24_t chunk_offset = exch->next_chunk_rsn - prev_el->relative_sn;
				const uint8_t prev_seg_length = prev_el->pl_length - chunk_offset;
				const uint8_t max_cur_seg_length = sizeof("ffff\r");
				const uint24_t window_size = prev_seg_length + max_cur_seg_length;
				char window[window_size];
				memcpy(window, get_payload_addr(prev_el->segment) + chunk_offset, prev_seg_length);
				memcpy(window + prev_seg_length, get_payload_addr(cur_el->segment), max_cur_seg_length);
				chunk_size = get_chunk_size(window, window + window_size, &chunk_chars);
				if(chunk_size == 0xffffff) {
					dbg_err("Unable to retrieve chunk");
					pause();
					exch->dirty = true;
					exch->tcp_exch.tcp_state = TCP_STATE_CLOSED;
					exch->status = WEB_ERROR_FAILED;
					return WEB_ERROR_FAILED;
				}
				exch->rsn_end_chunk = 0;
			} else {  /* Nominal case */
				/* Searching for the involved segment (cur_el->next can't be NULL) */
				while(cur_el->relative_sn + cur_el->pl_length <= exch->next_chunk_rsn) {
					cur_el = cur_el->next;
				}
				const uint24_t chunk_offset = exch->next_chunk_rsn - cur_el->relative_sn;
				const char *chunk_addr = get_payload_addr(cur_el->segment) + chunk_offset;
				chunk_size = get_chunk_size(chunk_addr, get_payload_addr(cur_el->segment) + cur_el->pl_length,
											&chunk_chars);
				if(chunk_size == 0xffffff) {
					exch->rsn_end_chunk = new_segment_list->relative_sn + new_segment_list->pl_length;
				}
			}

			if(chunk_size != 0xffffff) {
				exch->chunks_metadata_length += chunk_chars + 4;
				exch->next_chunk_rsn += chunk_size + chunk_chars + 4;  /* 4=\r\n..\r\n */
			}
			if(chunk_size == 0) {
				/* This line drops the data after the last chunk metadata */
				exch->chunks_metadata_length += (cur_el->relative_sn + cur_el->pl_length) - (exch->next_chunk_rsn - 2);
				exch->chunks_metadata_length -= 2;  /* The first \r\n of the first chunk does not count -> header */
				return return_http_data(exch);
			}
		}
	}

	if(exch->content_length && exch->content_length >= exch->content_received) {
		if(exch->content_length != exch->content_received) {
			dbg_warn("Received more data than expected");
		}
		return return_http_data(exch);
	} else {
		return WEB_SUCCESS;
	}
}

static void wipe_http_exchange(http_exchange_t *exch) {
	/* If the connection terminated unexpectedly */
	if(exch->tcp_exch.tcp_state == TCP_STATE_ESTABLISHED) {
		dbg_warn("Sending RST segment");
		web_SendTCPSegment(NULL, 0, exch->tcp_exch.ip_dst, exch->tcp_exch.port_src, exch->tcp_exch.port_dst,
						   exch->tcp_exch.cur_sn, exch->tcp_exch.cur_ackn, FLAG_TCP_RST, 0, NULL);
	}
	dbg_info("Freeing connection %x", exch->tcp_exch.port_src);

	/* Free the received segments */
	tcp_segment_list_t *cur_seg = exch->tcp_exch.segment_list;
	tcp_segment_list_t *next_seg = NULL;
	while(cur_seg) {
		next_seg = cur_seg->next;
		free(cur_seg->segment);
		free(cur_seg);
		cur_seg = next_seg;
	}

	/* Free the sending segments */
	pushed_seg_list_t *cur_pushed = exch->tcp_exch.pushed_seg;
	pushed_seg_list_t *next_pushed = NULL;
	while(cur_pushed != NULL) {
		next_pushed = cur_pushed->next;
		web_popMessage(cur_pushed->seg);
		free(cur_pushed);
		cur_pushed = next_pushed;
	}

	/* Popping from the exchange list */
	http_exchange_list_t *cur_exch = http_exchanges;
	http_exchange_list_t *prev_exch = NULL;
	while(cur_exch != NULL) {
		if(cur_exch->http_exch == exch) {
			if(prev_exch == NULL) {
				http_exchanges = cur_exch->next;
			} else {
				prev_exch->next = cur_exch->next;
			}
			free(exch);
			free(cur_exch);
			break;
		}
	}

	/* Unlisten port */
	web_UnlistenPort(exch->tcp_exch.port_src);
}


int web_UnlockData(http_data_t **http_data) {
	if(!os_EnoughMem((*http_data)->size)) {
		return 0;
	}

	void *cur_entry = os_GetSymTablePtr();
	uint24_t type;
	char name[9];
	void *data = NULL;
	while(cur_entry && *http_data != data) {
		cur_entry = os_NextSymEntry(cur_entry, &type, NULL, name, &data);
	}

	if(!cur_entry) {
		return 0;
	}

	http_data_t *tmp;
	tmp = MoveToRam(name);
	if(tmp) {
		*http_data = tmp;
	}

	return 1;
}

int web_LockData(http_data_t **http_data) {
	os_ArcChk();
	if((*http_data)->size >= os_TempFreeArc) {
		return 0;
	}

	void *cur_entry = os_GetSymTablePtr();
	char name[9];
	void *data = NULL;
	while(cur_entry && *http_data != data) {
		cur_entry = os_NextSymEntry(cur_entry, NULL, NULL, name, &data);
	}

	if(*http_data != data) {
		return 0;
	}

	http_data_t *tmp;
	tmp = MoveToArc(name);

	if(tmp) {
		*http_data = (http_data_t *)((void *)tmp + 18);
	}

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

static web_status_t dns_callback(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data) {
	(void)port;
	*((uint32_t*)user_data) = res_ip;
	return WEB_SUCCESS;
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

static web_status_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
								  web_callback_data_t *user_data) {
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

msg_queue_t *web_PushDHCPMessage(size_t opt_size, const uint8_t *options, uint32_t dhcp_server_ip) {
	static uint32_t xid = 0;
	if(xid == 0) {  /* If not initialized yet */
		xid = random();
	}

	const size_t size = sizeof(dhcp_message_t) + opt_size;
	uint8_t buffer[size];
	memset(buffer, 0, size);
	dhcp_message_t *dhcp_query = (dhcp_message_t *)buffer;
	dhcp_query->op = DHCP_OP_REQUEST;
	dhcp_query->htype = DHCP_HTYPE_MAC;
	dhcp_query->hlen = DHCP_HLEN_MAC;
	dhcp_query->hops = 0x00;
	dhcp_query->xid = xid;
	memcpy(&dhcp_query->chaddr, MAC_ADDR, 6);
	/* 192 zeros */
	dhcp_query->magicCookie = DHCP_MAGIC_COOKIE;
	memcpy(&dhcp_query->options, options, opt_size);
	dhcp_query->siaddr = dhcp_server_ip;  /* = 0 at first */

	return web_PushUDPDatagram(dhcp_query, sizeof(dhcp_message_t) + opt_size, 0xffffffff, CLIENT_DHCP_PORT,
							   SERVER_DHCP_PORT);
}

web_status_t web_SendDHCPMessage(size_t opt_size, const uint8_t *options, uint32_t dhcp_server_ip) {
	msg_queue_t *queued = web_PushDHCPMessage(opt_size, options, dhcp_server_ip);
	if(queued != NULL) {
		queued->waitingTime = 0;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}

static void dhcp_init() {
	const uint8_t options_disc[] = {
		DHCP_OPT_TYPE_ID, DHCP_OPT_TYPE_LEN, DHCP_OPT_V_DISCOVER,
		DHCP_OPT_END_OPTIONS};
	dhcp_last_msg_queue = web_PushDHCPMessage(sizeof(options_disc), options_disc, 0x00);
	web_ListenPort(CLIENT_DHCP_PORT, fetch_dhcp_msg, NULL);
	netinfo.dhcp_cur_state = DHCP_STATE_INIT;
}

static web_status_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
								   web_callback_data_t *user_data) {
	(void)port; (void)length; (void)user_data;  /* Unused parameters */
	if(protocol != UDP_PROTOCOL)
		return WEB_SUCCESS;

	const dhcp_message_t *dhcp_msg = (dhcp_message_t *)((uint8_t *)msg + sizeof(udp_datagram_t));

	if(dhcp_msg->op == DHCP_OP_REPLY) {
		const uint8_t *cur_opt = (uint8_t *)((uint8_t *)dhcp_msg + sizeof(dhcp_message_t));
		while(cur_opt[0] != DHCP_OPT_END_OPTIONS) {
			switch(cur_opt[0]) {
				case DHCP_OPT_TYPE_ID:
					if(cur_opt[2] == DHCP_OPT_V_OFFER && netinfo.dhcp_cur_state == DHCP_STATE_INIT) {
						if(dhcp_last_msg_queue != NULL) {
							web_popMessage(dhcp_last_msg_queue);
						}
						uint8_t options_req[] = {
							DHCP_OPT_TYPE_ID, DHCP_OPT_TYPE_LEN, DHCP_OPT_V_REQUEST,
							DHCP_OPT_PARAM_REQ_LIST_ID, 1, DHCP_OPT_DNS_ID,
							DHCP_OPT_SERVER_ID, DHCP_OPT_IP_LEN, 0, 0, 0, 0,
							DHCP_OPT_REQ_IP_ID, DHCP_OPT_IP_LEN, 0, 0, 0, 0,
							DHCP_OPT_END_OPTIONS};

						*(uint32_t *)(options_req + 8) = dhcp_msg->siaddr;
						*(uint32_t *)(options_req + 14) = dhcp_msg->yiaddr;
						dhcp_last_msg_queue = web_PushDHCPMessage(sizeof(options_req), options_req, dhcp_msg->siaddr);
						if(dhcp_last_msg_queue != NULL) {
							netinfo.dhcp_cur_state = DHCP_STATE_SELECTING;
						}
					} else if(cur_opt[2] == DHCP_OPT_V_ACK && netinfo.dhcp_cur_state == DHCP_STATE_SELECTING) {
						if(dhcp_last_msg_queue != NULL) {
							web_popMessage(dhcp_last_msg_queue);
							dhcp_last_msg_queue = NULL;
						}
						netinfo.IP_addr = dhcp_msg->yiaddr;
						memcpy(netinfo.router_MAC_addr, src_mac_addr, 6);
						netinfo.dhcp_cur_state = DHCP_STATE_BIND;
						netinfo.state = STATE_NETWORK_CONFIGURED;
					} else if(cur_opt[2] == DHCP_OPT_V_NAK && netinfo.dhcp_cur_state == DHCP_STATE_SELECTING) {
						dbg_warn("DHCP NACK");
						if(dhcp_last_msg_queue != NULL) {
							web_popMessage(dhcp_last_msg_queue);
							dhcp_last_msg_queue = NULL;
						}
						web_UnlistenPort(CLIENT_DHCP_PORT);
						dhcp_init();
					}
					break;
				case DHCP_OPT_DNS_ID:
					if(netinfo.dhcp_cur_state != DHCP_STATE_BIND) {
						netinfo.DNS_IP_addr = *((uint32_t *)(cur_opt + 2)); /* we only take the first entry */
					}
					break;
				case 58: /* T1 Lease time */
					// TODO t1_leasetime = rtc_Time() + htonl(*(cur_opt + 2));
					break;
				default:
					break;
			}
			cur_opt += *(cur_opt + 1) + 2;
		}
	}
	return WEB_SUCCESS;
}

static msg_queue_t *_recursive_PushTCPSegment(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
											  web_port_t port_src, web_port_t port_dst, uint32_t seq_number,
											  uint32_t ack_number, uint16_t flags, size_t opt_size,
											  const uint8_t *options) {
	if(data - (sizeof(tcp_segment_t) + opt_size) < buffer) {
		dbg_err("Can't push TCP segment");
		return NULL;
	}

	size_t size_header = sizeof(tcp_segment_t) + opt_size;
	size_t size_all = length_data + size_header;
	tcp_segment_t *tcp_seg = (tcp_segment_t *)(data - size_header);
	tcp_seg->port_src = htons(port_src);
	tcp_seg->port_dst = htons(port_dst);
	tcp_seg->seq_number = htonl(seq_number);
	tcp_seg->ack_number = htonl(ack_number);
	tcp_seg->dataOffset_flags = htons(((size_header * 1024)) + flags);
	tcp_seg->windowSize = htons(TCP_WINDOW_SIZE);
	tcp_seg->checksum = 0x0000;
	tcp_seg->urgentPointer = 0x0000;

	if(options) {
		memcpy(tcp_seg + sizeof(tcp_segment_t), options, opt_size);
	}

	uint16_t chksm = transport_checksum(tcp_seg, size_all, netinfo.IP_addr, ip_dst, TCP_PROTOCOL);
	tcp_seg->checksum = chksm;

	return _recursive_PushIPv4Packet(buffer, tcp_seg, size_all, ip_dst, TCP_PROTOCOL);
}

msg_queue_t *web_PushTCPSegment(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags,
								size_t opt_size, const uint8_t *options) {
	void *buffer = _alloc_msg_buffer(data, length_data, TCP_HEADERS_SIZE + opt_size, true);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushTCPSegment(buffer, buffer + TCP_HEADERS_SIZE + opt_size - 4, length_data,
									 ip_dst, port_src, port_dst, seq_number, ack_number, flags,
									 opt_size, options);
}

web_status_t web_SendTCPSegment(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags,
								size_t opt_size, const uint8_t *options) {
	msg_queue_t *queued = web_PushTCPSegment(data, length_data, ip_dst, port_src, port_dst, seq_number, ack_number,
											 flags, opt_size, options);
	if(queued != NULL) {
		queued->waitingTime = 0;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}

static uint16_t transport_checksum(void *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol) {
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

static msg_queue_t *_recursive_PushUDPDatagram(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
											   web_port_t port_src, web_port_t port_dst) {
	if(data - sizeof(udp_datagram_t) < buffer) {
		dbg_err("Can't push UDP datagram");
		return NULL;
	}

	/* Filling the UDP datagram header */
	size_t size = length_data + sizeof(udp_datagram_t);
	udp_datagram_t *datagram = (udp_datagram_t *)(data - sizeof(udp_datagram_t));
	datagram->port_src = htons(port_src);
	datagram->port_dst = htons(port_dst);
	datagram->length = htons(size);
	datagram->checksum = 0x0000;

	/* Computing the header & data checksum */
	uint16_t chksm = transport_checksum(datagram, size, netinfo.IP_addr, ip_dst, UDP_PROTOCOL);
	datagram->checksum = chksm;

	return _recursive_PushIPv4Packet(buffer, datagram, size, ip_dst, UDP_PROTOCOL);
}

msg_queue_t *web_PushUDPDatagram(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								 web_port_t port_dst) {
	void *buffer = _alloc_msg_buffer(data, length_data, UDP_HEADERS_SIZE, true);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushUDPDatagram(buffer, buffer + UDP_HEADERS_SIZE - 4, length_data, ip_dst, port_src, port_dst);
}

web_status_t web_SendUDPDatagram(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								 web_port_t port_dst) {
	msg_queue_t *queued = web_PushUDPDatagram(data, length_data, ip_dst, port_src, port_dst);
	if(queued != NULL) {
		queued->waitingTime = 0;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}

web_status_t web_SendICMPEchoRequest(uint32_t ip_dst) {
	icmpv4_echo_t icmp_echo = {
		.type = ICMP_ECHO_REQUEST,
		.code = 0x00,
		.checksum = 0x00,
		.identifier = 0x00,
		.seq_number = 0x00,
	};
	icmp_echo.checksum = ipv4_checksum(&icmp_echo, sizeof(icmp_echo));
	return web_SendIPv4Packet(&icmp_echo, sizeof(icmpv4_echo_t), ip_dst, ICMP_PROTOCOL);
}

static msg_queue_t *_recursive_PushIPv4Packet(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
											  uint8_t protocol) {
	static unsigned int nbpacket = 0;
	if(data - sizeof(ipv4_packet_t) < buffer) {
		dbg_err("Can't push IPv4 packet");
		return NULL;
	}

	/* Filling the IPv4 header */
	size_t size = length_data + sizeof(ipv4_packet_t);
	ipv4_packet_t *ipv4_pckt = (ipv4_packet_t *)(data - sizeof(ipv4_packet_t));
	ipv4_pckt->VerIHL = 0x45;
	ipv4_pckt->ToS = 0x00;
	ipv4_pckt->TotalLength = htons(size);
	ipv4_pckt->Id = htons(nbpacket++);
	ipv4_pckt->FlagsFragmentOffset = htons(0x4000);
	ipv4_pckt->TTL = 0x80;
	ipv4_pckt->Protocol = protocol;
	ipv4_pckt->HeaderChecksum = 0x0000;
	ipv4_pckt->IP_addr_src = netinfo.IP_addr;
	ipv4_pckt->IP_addr_dst = ip_dst;

	/* Computing the header checksum */
	uint16_t chksm = ipv4_checksum(ipv4_pckt, sizeof(ipv4_packet_t));
	ipv4_pckt->HeaderChecksum = chksm;

	return _recursive_PushEthernetFrame(buffer, ipv4_pckt, size, ETH_IPV4);
}

msg_queue_t *web_PushIPv4Packet(void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol) {
	void *buffer = _alloc_msg_buffer(data, length_data, IPV4_HEADERS_SIZE, true);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushIPv4Packet(buffer, buffer + IPV4_HEADERS_SIZE - 4, length_data, ip_dst,
									 protocol);
}

web_status_t web_SendIPv4Packet(void *data, size_t length_data, uint32_t ip_dst, uint8_t protocol) {
	msg_queue_t *queued = web_PushIPv4Packet(data, length_data, ip_dst, protocol);
	if(queued != NULL) {
		queued->waitingTime = 0;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}

static uint16_t ipv4_checksum(void *header, size_t count) {
	uint32_t sum = 0;
	uint16_t *data = (uint16_t *)header;

    while(count > 1) {
        sum += *(uint16_t *)data++;
        count -= 2;
    }

    if(count > 0) {
        sum += *(uint8_t *)data;
	}

    while(sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
	}

    return (uint16_t)~sum;
}

web_status_t web_SendARPRequest(uint8_t MAC_dst[6]) {
	arp_message_t arp_msg = {
		.HwType = 0x01,
		.ProtocolType = ETH_IPV4,
		.HwAddrLength = 0x06,
		.ProtocolAddrLength = 0x04,
		.Operation = 0x01,
		.MAC_src = {},
		.IP_src = 0x00,
		.MAC_dst = {},
		.IP_dst = 0x00,
	};
	memcpy(&arp_msg.MAC_src, MAC_ADDR, 6);
	memcpy(&arp_msg.MAC_dst, MAC_dst, 6);
	return web_SendEthernetFrame(&arp_msg, sizeof(arp_message_t), ETH_ARP);
}

static msg_queue_t *_recursive_PushEthernetFrame(void *buffer, void *data, size_t length_data, uint16_t protocol) {
	/* @Warning: 4 bytes must be reserved for CRC after the data */
	/* Ethernet frame must be at least 64B */
	const size_t min_payload_size = MIN_ETH_HDR_SIZE - (sizeof(eth_frame_t) + 4);  /* = 46 */
	if(length_data < min_payload_size) {
		/* Reallocating so it is 64B large */
		uint8_t *new_buffer = malloc(MIN_ETH_HDR_SIZE + sizeof(rndis_packet_msg_t));
		void *new_data = new_buffer + sizeof(rndis_packet_msg_t) + sizeof(eth_frame_t);
		memcpy(new_data, data, length_data);
		memset(new_data + length_data, 0, min_payload_size - length_data);
		free(buffer);
		buffer = new_buffer;
		data = new_data;
		length_data = min_payload_size;
	}
	if(data - sizeof(eth_frame_t) < buffer) {
		dbg_err("Can't push ethernet frame");
		return NULL;
	}

	size_t size = length_data + sizeof(eth_frame_t) + 4;
	eth_frame_t *frame = (eth_frame_t *)(data - sizeof(eth_frame_t));
	memcpy(&frame->MAC_dst, netinfo.router_MAC_addr, 6);
	memcpy(&frame->MAC_src, MAC_ADDR, 6);
	frame->Ethertype = protocol;
	uint32_t crc = crc32b(frame, size - 4);
	memcpy((void *)frame + size - 4, &crc, 4);

	return _recursive_PushRNDISPacket(buffer, frame, size);
}

msg_queue_t *web_PushEthernetFrame(void *data, size_t length_data, uint16_t protocol) {
	void *buffer = _alloc_msg_buffer(data, length_data, ETH_HEADERS_SIZE, true);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushEthernetFrame(buffer, buffer + ETH_HEADERS_SIZE - 4, length_data, protocol);
}

web_status_t web_SendEthernetFrame(void *data, size_t length_data, uint16_t protocol) {
	msg_queue_t *queued = web_PushEthernetFrame(data, length_data, protocol);
	if(queued != NULL) {
		queued->waitingTime = 0;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}

static uint32_t crc32b(void *data, size_t length) {
	/**
	 *	Computes ethernet crc32.
	 *	Code found on stackoverflow.com (no licence was given to the code)
	 */
	const uint32_t crc_poly = 0xEDB88320;
    uint32_t crc;
	unsigned int i, j;

    if(!data || !length) {
        return 0;
	}
    crc = 0xFFFFFFFF;
    for(j = 0; j < length; j++) {
		crc ^= ((uint8_t *)data)[j];
		for(i = 0; i < 8; i++) {
        	crc = (crc & 1) ? ((crc >> 1) ^ crc_poly) : (crc >> 1);
		}
    }
    return ~crc;
}

static msg_queue_t *_recursive_PushRNDISPacket(void *buffer, void *data, size_t length_data) {
	if(data - sizeof(rndis_packet_msg_t) != buffer) {
		dbg_err("Can't push RNDIS packet");
		return NULL;
	}

	rndis_packet_msg_t *pckt = (rndis_packet_msg_t *)(data - sizeof(rndis_packet_msg_t));
	memset(pckt, 0, sizeof(rndis_packet_msg_t));
	pckt->MessageType = RNDIS_PACKET_MSG;
	pckt->MessageLength = sizeof(rndis_packet_msg_t) + length_data;
	pckt->DataOffset = 36;
	pckt->DataLength = length_data;
	memcpy((void *)pckt + sizeof(rndis_packet_msg_t), data, length_data);

	return web_PushMessage(pckt, length_data + sizeof(rndis_packet_msg_t));
}

msg_queue_t *web_PushRNDISPacket(void *data, size_t length_data) {
	void *buffer = _alloc_msg_buffer(data, length_data, sizeof(rndis_packet_msg_t), false);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushRNDISPacket(buffer, buffer + sizeof(rndis_packet_msg_t), length_data);
}

web_status_t web_SendRNDISPacket(void *data, size_t length_data) {
	msg_queue_t *queued = web_PushRNDISPacket(data, length_data);
	if(queued != NULL) {
		queued->waitingTime = 0;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}

static void *_alloc_msg_buffer(void *data, size_t length_data, size_t headers_total_size, bool has_eth_header) {
	const size_t size = length_data + headers_total_size;
	void *buffer = malloc(size);
	if(buffer == NULL) {
		dbg_err("No memory left");
		return NULL;
	}
	memcpy(buffer + headers_total_size - (has_eth_header ? 4 : 0), data, length_data);
	return buffer;
}

void web_Init() {
	netinfo.ep_wc_in = 0;
	netinfo.ep_cdc_in = 0;
	netinfo.ep_cdc_out = 0;
	netinfo.state = STATE_UNKNOWN;
	netinfo.device = NULL;
	netinfo.IP_addr = 0;
	usb_Init(usbHandler, NULL, NULL, USB_DEFAULT_INIT_FLAGS);
	memset(netinfo.router_MAC_addr, 0xFF, 6);
	srand(rtc_Time());
	MAC_ADDR[5] = randInt(0, 0xFF);
}

static uint24_t get_chunk_size(const char *ascii, const char *max_ptr, uint24_t *chunk_chars) {
	/**
	 *	Considering this is a correct chunk size :
	 *	-> \r\n terminated
	 *	-> which is only a combination of 0123456789abcdefABCDEF
	 *	Returns 0xffffff if the chunk metadata is not complete
	 */
	uint24_t size = 0;
	*chunk_chars = 0;
	while(ascii < max_ptr && *ascii != '\r') {
		if(*ascii <= '9') {
			size = size * 16 + (*ascii - '0');
		} else if(*ascii <= 'F') {
			size = size * 16 + 10 + (*ascii - 'A');
		} else {
			size = size * 16 + 10 + (*ascii - 'a');
		}
		ascii++;
		(*chunk_chars)++;
	}
	return ascii == max_ptr ? 0xffffff : size;
}

static bool cmpbroadcast(const uint8_t *mac_addr) {
	const uint24_t *mac24b = (uint24_t *)mac_addr;
	return (mac24b[0] & mac24b[1]) == 0xffffff;
}

static inline uint32_t htonl(uint32_t val) {
	uint8_t *pval = (uint8_t *)&val;
	return (((uint32_t)pval[0] * ((uint32_t)1 << 24)) +
			((uint32_t)pval[1] * ((uint32_t)1 << 16)) +
			((uint32_t)pval[2] * ((uint32_t)1 << 8)) +
			 (uint32_t)pval[3]);
}

static inline uint16_t htons(uint16_t val) {
	uint8_t *pval = (uint8_t *)&val;
	return ((uint16_t)pval[0] * 256) + pval[1];
}

uint32_t web_getMyIPAddr() {
	return netinfo.IP_addr;
}

bool web_Connected() {
	return netinfo.state == STATE_NETWORK_CONFIGURED;
}

static web_status_t handle_send_msg_queue() {
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

static void handle_tcp_connections() {
	const uint32_t current_time = rtc_Time();
	http_exchange_list_t *cur_connection = http_exchanges;
	http_exchange_list_t *prev_connection = NULL;
	while(cur_connection != NULL) {
		http_exchange_t *http_exch = cur_connection->http_exch;
		if((http_exch->tcp_exch.tcp_state == TCP_STATE_TIME_WAIT && current_time >= http_exch->tcp_exch.timeout_close)
		   || http_exch->dirty) {
			if(prev_connection == NULL) {
				http_exchanges = cur_connection->next;
			} else {
				prev_connection->next = cur_connection->next;
			}
			wipe_http_exchange(http_exch);
		}
		prev_connection = cur_connection;
		cur_connection = cur_connection->next;
	}
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
			if(configure_usb_device() == WEB_SUCCESS) {
				netinfo.state = STATE_DHCP_CONFIGURING;
				dhcp_init();
			} else {
				netinfo.state = STATE_UNKNOWN;
			}
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
			uint8_t msg_buffer[MAX_SEGMENT_SIZE + 110];  /* All the headers should take max 102B */
			usb_error_t err = usb_Transfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_cdc_in), msg_buffer,
										   MAX_SEGMENT_SIZE + 110, 0, &transferred);
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

static web_status_t configure_usb_device() {
	rndis_init_msg_t rndis_initmsg = {RNDIS_INIT_MSG, 24, 0, 1, 0, MAX_SEGMENT_SIZE + 110};
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
		return WEB_ERROR_FAILED;
	total_length = ((usb_configuration_descriptor_t*)buffer)->wTotalLength;  /* More or less 40 bytes */
	if(total_length > 256)
		return WEB_NOT_ENOUGH_MEM;

	usb_GetDescriptor(netinfo.device, USB_CONFIGURATION_DESCRIPTOR, 0, buffer, total_length, &len);
	if(len != total_length)
		return WEB_ERROR_FAILED;

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
		return WEB_IGNORE;
	}

	/* Otherwise, let's goooo */
	if(usb_SetConfiguration(netinfo.device, (usb_configuration_descriptor_t*)buffer, len) != USB_SUCCESS)
		return WEB_ERROR_FAILED;

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

	return WEB_SUCCESS;
}

static web_status_t call_callbacks(uint8_t protocol, void *data, size_t length, web_port_t port) {
	port_list_t *cur_listenedPort = listened_ports;
	while(cur_listenedPort) {
		if(port == cur_listenedPort->port) {
			if(cur_listenedPort->callback(port, protocol, data, length, cur_listenedPort->callback_data) == WEB_SUCCESS)
				break;
		}
		cur_listenedPort = cur_listenedPort->next;
	}
	return WEB_SUCCESS;
}

static web_status_t fetch_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	if(!transport_checksum((uint8_t*)seg, length, ip_src, ip_dst, TCP_PROTOCOL)) {
		return call_callbacks(TCP_PROTOCOL, seg, length, seg->port_dst/256 + seg->port_dst*256);
	} else {
		dbg_warn("Received bad checksumed TCP packet");
		return WEB_ERROR_FAILED;
	}
}

static web_status_t fetch_udp_datagram(udp_datagram_t *datagram, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	if(!datagram->checksum || !transport_checksum((uint8_t*)datagram, length, ip_src, ip_dst, UDP_PROTOCOL)) {
		return call_callbacks(UDP_PROTOCOL, datagram, length, datagram->port_dst / 256 + datagram->port_dst * 256);
	} else {
		dbg_warn("Received bad checksumed UDP packet");
		return WEB_ERROR_FAILED;
	}
}

static web_status_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src) {
	if(msg->type != ICMP_ECHO_REQUEST || msg->code != 0) {
		return WEB_SUCCESS;
	}
	dbg_info("Received ping");

	msg->type = ICMP_ECHO_REPLY;
	msg->checksum += ICMP_ECHO_REQUEST - ICMP_ECHO_REPLY; /* Difference between the two messages */
	/* Send IPv4 packet */
	return web_SendIPv4Packet((uint8_t*)msg, length, ip_src, ICMP_PROTOCOL);
}

static web_status_t fetch_IPv4_packet(ipv4_packet_t *pckt, size_t length) {
	const size_t header_size = (pckt->VerIHL & 0x0F) * 4;
	void *payload = (void *)pckt + header_size;
	web_status_t ret_val;

	if(ipv4_checksum(pckt, header_size) != 0) {
		dbg_warn("Received bad checksumed IPv4 packet");
		return WEB_ERROR_FAILED;
	}
	if(pckt->FlagsFragmentOffset != 0 && pckt->FlagsFragmentOffset != 0x40) {
		dbg_warn("Received fragmented IPv4 packet");
	}

	switch(pckt->Protocol) {
		case TCP_PROTOCOL: {
			tcp_segment_t *tcp_seg = (tcp_segment_t *)payload;
			ret_val = fetch_tcp_segment(tcp_seg, length - header_size, pckt->IP_addr_src, pckt->IP_addr_dst);
			break;
		} case UDP_PROTOCOL: {
			udp_datagram_t *udp_dtgm = (udp_datagram_t *)payload;
			ret_val = fetch_udp_datagram(udp_dtgm, length - header_size, pckt->IP_addr_src, pckt->IP_addr_dst);
			break;
		} case ICMP_PROTOCOL: {
			icmpv4_echo_t *msg = (icmpv4_echo_t *)payload;
			ret_val = fetch_icmpv4_msg(msg, length - header_size, pckt->IP_addr_src);
			break;
		} default:
			ret_val = WEB_SUCCESS;
	}
	return ret_val;
}

static void fetch_arp_msg(eth_frame_t *ethernet_frame) {
	arp_message_t *arp_msg = (arp_message_t *)((uint8_t *)ethernet_frame + sizeof(eth_frame_t));

	if(ethernet_frame->Ethertype != ETH_ARP || arp_msg->HwType != 0x0100 || arp_msg->Operation != 0x0100 ||
	   arp_msg->ProtocolType != ETH_IPV4 || arp_msg->IP_dst != netinfo.IP_addr) {
		return;
	}

	arp_message_t resp;
	resp.HwType = 0x0100;
	resp.ProtocolType = ETH_IPV4;
	resp.HwAddrLength = 0x06;
	resp.ProtocolAddrLength = 0x04;
	resp.Operation = 0x0200;
	memcpy(resp.MAC_src, MAC_ADDR, 6);
	resp.IP_src = netinfo.IP_addr;
	memcpy(resp.MAC_dst, arp_msg->MAC_src, 6);
	resp.IP_dst = arp_msg->IP_src;

	web_SendEthernetFrame(&resp, sizeof(arp_message_t), ETH_ARP);
}

static web_status_t fetch_ethernet_frame(eth_frame_t *frame, size_t length) {
	if(frame->Ethertype == ETH_IPV4 && !memcmp(frame->MAC_dst, MAC_ADDR, 6)) {
		src_mac_addr = frame->MAC_src;
		ipv4_packet_t *ipv4_pckt = (ipv4_packet_t *)((uint8_t *)frame + sizeof(eth_frame_t));
		return fetch_IPv4_packet(ipv4_pckt, length - sizeof(eth_frame_t));
	} else if(frame->Ethertype == ETH_ARP && (!memcmp(frame->MAC_dst, MAC_ADDR, 6) || cmpbroadcast(frame->MAC_dst))) {
		fetch_arp_msg(frame);
	}

	return WEB_SUCCESS;
}

static web_status_t packets_callback(size_t transferred, void *data) {
	if(transferred >= MAX_SEGMENT_SIZE + 110) {
		dbg_err("No memory");
		return WEB_NOT_ENOUGH_MEM;
	}
	/* Several messages can be queued in the same transfer */
	void *cur_packet = data;
	while(cur_packet < data + transferred) {
		eth_frame_t *frame = (eth_frame_t *)(data + sizeof(rndis_packet_msg_t));
		web_status_t ret_status = fetch_ethernet_frame(frame, ((rndis_packet_msg_t *)cur_packet)->DataLength);
		if(ret_status != WEB_SUCCESS) {
			return ret_status;
		}
		cur_packet = cur_packet + sizeof(rndis_packet_msg_t) + ((rndis_packet_msg_t *)cur_packet)->DataLength;
	}
	return WEB_SUCCESS;
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
		case USB_DEVICE_DISCONNECTED_EVENT:
			netinfo.state = STATE_USB_LOST;
			break;
		default:
			break;
	}
	
	#if DEBUG_LEVEL >= DEBUG_VERBOSE
		static const char *usb_event_names[] = {
	        "USB_ROLE_CHANGED_EVENT",
			"USB_DEVICE_DISCONNECTED_EVENT",
			"USB_DEVICE_CONNECTED_EVENT",
			"USB_DEVICE_DISABLED_EVENT",
			"USB_DEVICE_ENABLED_EVENT",
			"USB_HUB_LOCAL_POWER_GOOD_EVENT",
			"USB_HUB_LOCAL_POWER_LOST_EVENT",
			"USB_DEVICE_RESUMED_EVENT",
			"USB_DEVICE_SUSPENDED_EVENT",
			"USB_DEVICE_OVERCURRENT_DEACTIVATED_EVENT",
			"USB_DEVICE_OVERCURRENT_ACTIVATED_EVENT",
			"USB_DEFAULT_SETUP_EVENT",
			"USB_HOST_CONFIGURE_EVENT",
			"USB_DEVICE_INTERRUPT",
			"USB_DEVICE_CONTROL_INTERRUPT",
			"USB_DEVICE_DEVICE_INTERRUPT",
			"USB_OTG_INTERRUPT",
			"USB_HOST_INTERRUPT",
			"USB_CONTROL_ERROR_INTERRUPT",
			"USB_CONTROL_ABORT_INTERRUPT",
			"USB_FIFO0_SHORT_PACKET_INTERRUPT",
			"USB_FIFO1_SHORT_PACKET_INTERRUPT",
			"USB_FIFO2_SHORT_PACKET_INTERRUPT",
			"USB_FIFO3_SHORT_PACKET_INTERRUPT",
			"USB_DEVICE_ISOCHRONOUS_ERROR_INTERRUPT",
			"USB_DEVICE_ISOCHRONOUS_ABORT_INTERRUPT",
			"USB_DEVICE_DMA_FINISH_INTERRUPT",
			"USB_DEVICE_DMA_ERROR_INTERRUPT",
			"USB_DEVICE_IDLE_INTERRUPT",
			"USB_DEVICE_WAKEUP_INTERRUPT",
			"USB_B_SRP_COMPLETE_INTERRUPT",
			"USB_A_SRP_DETECT_INTERRUPT",
			"USB_A_VBUS_ERROR_INTERRUPT",
			"USB_B_SESSION_END_INTERRUPT",
			"USB_OVERCURRENT_INTERRUPT",
			"USB_HOST_PORT_CONNECT_STATUS_CHANGE_INTERRUPT",
			"USB_HOST_PORT_ENABLE_DISABLE_CHANGE_INTERRUPT",
			"USB_HOST_PORT_OVERCURRENT_CHANGE_INTERRUPT",
			"USB_HOST_PORT_FORCE_PORT_RESUME_INTERRUPT",
			"USB_HOST_SYSTEM_ERROR_INTERRUPT",
	    };
	    if(event != USB_DEVICE_WAKEUP_INTERRUPT && event != USB_OTG_INTERRUPT && event != USB_DEVICE_DEVICE_INTERRUPT &&
		   event != USB_DEVICE_INTERRUPT && event != USB_HOST_INTERRUPT) {
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
	#endif

	return USB_SUCCESS;
}


#if DEBUG_LEVEL >= DEBUG_ERRORS
void debug(const void *addr, size_t len) {
	uint8_t *content = (uint8_t *)addr;
	for(size_t i = 0; i < len; i++) {
		if(i && i % 8 == 0) {
			printf("\n");
		}
		printf("%.2X ", *(content + i));
	}
	printf("\n");
}

void printf_xy(unsigned int xpos, unsigned int ypos, const char *txt) {
	unsigned int x, y;
	os_GetCursorPos(&x, &y);
	os_SetCursorPos(xpos, ypos);
	printf("%s ", txt);
	os_SetCursorPos(x, y);
}

void print_tcp_info(const tcp_segment_t *seg, http_exchange_t *exch, size_t length) {
	printf("TCP: ");
	if(seg->dataOffset_flags & htons(FLAG_TCP_SYN)) {
		printf("S");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_ACK)) {
		printf("A");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_RST)) {
		printf("R");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_FIN)) {
		printf("F");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_PSH)) {
		printf("P");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_URG)) {
		printf("U");
	}
	if(exch->tcp_exch.beg_ackn != 0) {
		printf(" (%lu+%d)", htonl(seg->seq_number) - exch->tcp_exch.beg_ackn, length - 4 *
			   (seg->dataOffset_flags >> 4 & 0x0f));
	}
	printf(" a=%lu\n", htonl(seg->ack_number) - exch->tcp_exch.beg_sn);
}
#endif
