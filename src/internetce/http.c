#include <internet.h>
#include <stdint.h>
#include <tice.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

#include "include/http.h"
#include "include/debug.h"
#include "include/utils.h"
#include "include/tcp.h"
#include "include/core.h"
#include "include/scheduler.h"


http_data_list_t *http_data_list = NULL;


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

web_status_t web_HTTPGet(const char* url, http_data_t **data, bool keep_http_header) {
	char pointer_to_null = 0x00;
	return http_request("GET", url, data, keep_http_header, &pointer_to_null, false);
}

web_status_t web_HTTPSGet(const char* url, http_data_t **data, bool keep_http_header) {
	char pointer_to_null = 0x00;
	return http_request("GET", url, data, keep_http_header, &pointer_to_null, true);
}

#define web_HTTPPost(url, data, keep_http_header, nb_params, ...) \
		send_post_request(url, data, keep_http_header, false, __VA_ARGS__)

#define web_HTTPSPost(url, data, keep_http_header, nb_params, ...) \
		send_post_request(url, data, keep_http_header, true, __VA_ARGS__)

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


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

uint32_t ip_ascii_to_hex(const char *ipstr) {
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

web_status_t send_post_request(const char* url, http_data_t **data, bool keep_http_header, bool is_https, int nb_params, ...) {
	// TODO escape special chars such as '&'
	if(nb_params == 0) {
		char pointer_to_null = 0x00;
		return http_request("POST", url, data, keep_http_header, &pointer_to_null, is_https);
	}
	size_t param_len = 0;
	char *params = _malloc(1, "httpp");  /* To be reallocated */
	va_list list_params;
	va_start(list_params, nb_params);
	/* Turning the va parameters into a string like "param1=v1&param2=v2...paramN=vN\0" */
	for(uint8_t i = 0; i < nb_params * 2; i += 2) {
		const char *arg_name = va_arg(list_params, const char*);
		const char *arg_value = va_arg(list_params, const char*);
		const size_t new_param_size = strlen(arg_name) + strlen(arg_value) + 2 /* '=' and '&' */;
		void *tmp = _realloc(params, param_len + new_param_size + 1 /* 1='\0' */);
		if(tmp == NULL) {
			_free(params);
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
	_free(params);

	web_status_t status = http_request("POST", url, data, keep_http_header, post_info, is_https);
	return status;
}

web_status_t http_request(const char *request_type, const char* url, http_data_t **data, bool keep_http_header,
                          char *params, bool is_https) {
	/* Ignoring http:// or https:// */
	const char *https_str = "https://";
	const char *http_str = "http://";
	if(is_https && strncmp(url, https_str, strlen(https_str)) == 0) {
		url += 8;
	} else if(!is_https && strncmp(url, http_str, strlen(http_str)) == 0) {
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
	http_exchange_t *http_exch = _malloc(sizeof(http_exchange_t), "httpx");
	if(http_exch == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	memset(http_exch, 0, sizeof(http_exchange_t));
	http_exch->buffer_size = 536;  /* Starting size, will be resized later */
	http_exch->data = data;
	http_exch->buffer = _malloc(http_exch->buffer_size, "httpb");
	if(http_exch->buffer == NULL) {
		_free(http_exch);
		return WEB_NOT_ENOUGH_MEM;
	}
	http_exch->keep_http_header = keep_http_header;
    http_exch->timeout = false;
	http_exch->dirty = false;
	void *exchange;  /* Opaque type depending on the underlying protocol used to send data (TCP or TLS) */
	if(is_https) {
		exchange = web_TLSConnect(ip, HTTPS_PORT, websitename, fetch_http_msg, http_exch);
	} else {
		exchange = web_TCPConnect(ip, HTTP_PORT, fetch_http_msg, http_exch);
	}
    if(exchange == NULL) {
		_free(http_exch->buffer);
		_free(http_exch);
		return WEB_ERROR_FAILED;
	}
	web_status_t ret_val = delay_event(TIMEOUT_HTTP * 1000, boolean_scheduler, boolean_destructor, &http_exch->timeout);
	if(ret_val != WEB_SUCCESS) {
		if(is_https) {
			web_TLSClose(exchange, true);
		} else {
			web_TCPClose(exchange, true);
		}
		_free(http_exch->buffer);
		_free(http_exch);
		return ret_val;
	}

	/* Building HTTP request */
	uint24_t length = (strlen(BASIC_HTTP_REQUEST) - (4 * 2) /* 4 '%s' options */ + strlen(request_type) +
					  !has_path /* if no path, add 1 for '/' char */ + strlen(url) + strlen(params));
	
	char request[length + 1];
	snprintf(request, length + 1, BASIC_HTTP_REQUEST, request_type, has_path ? &url[websitelen] : "/", websitename, params);

	/* Sending HTTP request */
	if(is_https) {
		ret_val = web_DeliverTLSData(exchange, request, length);
	} else {
		ret_val = web_DeliverTCPSegment(exchange, request, length);
	}
	if(ret_val != WEB_SUCCESS) {
		http_exch->dirty = true;
		http_exch->status = ret_val;
	}

	/* Waiting for the end of the request */
	while(!http_exch->dirty) {
		web_WaitForEvents();
		if(http_exch->timeout) {
			http_exch->dirty = true;
			http_exch->status = WEB_TIMEOUT;
			dbg_err("HTTP Timeout");
		}
	}
	remove_event(&http_exch->timeout);

	const web_status_t ret_status = http_exch->status;
	const bool is_succeeded = ret_status >= 100;  /* 100 = minimum HTTP status code, below this is the lib status codes */
	if(is_https) {
		web_TLSClose(exchange, !is_succeeded);
	} else {
		web_TCPClose(exchange, !is_succeeded);
	}
	_free(http_exch->buffer);
	_free(http_exch);

	/* To send the FIN and potential ACK segments (in case the user quits) */
	force_send_queue();

	return ret_status;
}

web_status_t return_http_data(http_exchange_t *exch) {
	http_data_list_t *new_http_data_el = _malloc(sizeof(http_data_list_t), "httpd");
	if(new_http_data_el == NULL) {
		exch->dirty = true;
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
		_free(new_http_data_el);
		exch->status = WEB_NOT_ENOUGH_MEM;
		return WEB_NOT_ENOUGH_MEM;
	}

	/* Data is stored in an appvar, in order to relieve the heap */
	const size_t final_size = exch->content_received - exch->chunks_metadata_length -
							  (exch->keep_http_header ? 0 : exch->header_length);
	*exch->data = os_CreateAppVar(varstorage_name, final_size);
	if(!(*exch->data)) {
		exch->dirty = true;
		_free(new_http_data_el);
		exch->status = WEB_NOT_ENOUGH_MEM;
		return WEB_NOT_ENOUGH_MEM;
	}

	/* The following code copies de data into the AppVar and removes the chunk metadata if necessary */
	if(!exch->data_chunked) {
		memcpy((*exch->data)->data, exch->buffer + (exch->keep_http_header ? 0 : exch->header_length), final_size);
	} else {
		const void *end_buffer = exch->buffer + exch->content_received;
		size_t offset_next_chunk = exch->header_length;
		size_t chunk_chars;
		void *dst_ptr = (*exch->data)->data;
		if(exch->keep_http_header) {
			memcpy(dst_ptr, exch->buffer, exch->header_length);
			dst_ptr += exch->header_length;
		}
		while(offset_next_chunk != 0) {
			const void *src_ptr = exch->buffer + offset_next_chunk;
			size_t chunk_size = get_chunk_size(src_ptr, end_buffer, &chunk_chars);
			if(chunk_size == 0xffffff) {
				os_DelAppVar(varstorage_name);
				_free(new_http_data_el);
				exch->dirty = true;
				exch->status = WEB_ERROR_FAILED;
				dbg_err("Unexpected chunk size");
				return WEB_ERROR_FAILED;
			} else if(chunk_size == 0) {
				break;
			}
			memcpy(dst_ptr, src_ptr + chunk_chars + 2, chunk_size);
			offset_next_chunk += chunk_chars + chunk_size + 4;
			dst_ptr += chunk_size;
		}
		const size_t offset = dst_ptr - (void *)(*exch->data)->data;
		if(final_size != offset) {
			dbg_warn("The appvar is too big/small:");
			dbg_warn("Appvar size=%u, needed=%u", final_size, offset);
		}
	}

	/* Getting the HTTP status code of the request */
	const char *http_status = exch->buffer + sizeof("HTTP/1.1");
	exch->status = (http_status[0] - '0') * 100 +
				   (http_status[1] - '0') * 10 +
				   (http_status[2] - '0');

	/* Chaining... */
	strncpy(new_http_data_el->varname, varstorage_name, 9);
	new_http_data_el->next = http_data_list;
	http_data_list = new_http_data_el;

	web_LockData(exch->data);
	// TODO if(!keepalive)
	exch->dirty = true;
	dbg_info("Received all data from server");
	return WEB_SUCCESS;
}

char *lowercase(char *dst_str, const char *src_str, size_t length) {
	/* Lower a string for length */
	size_t index = 0;
	while(index < length) {
		dst_str[index] = tolower(src_str[index]);
		index++;
	}
	return dst_str;
}

const char *search_field_header(const char *data, size_t length, const char *str, size_t size_str) {
	/* Search the field name preceded by a new line */
	char lower_buffer[size_str];
	const char *ptr = data;
	bool search_str = false;  /* false=search \n true=search str */
	while(ptr < data + length) {
		if(*ptr == '\n') {
			search_str = true;
		} else if(search_str) {
			if(memcmp(lowercase(lower_buffer, ptr, size_str), str, size_str) == 0) {
				return ptr + size_str;
			} else {
				search_str = false;
			}
		}
		ptr++;
	}
	return NULL;
}

int search_content_size(http_exchange_t *exch) {
	const char content_length_str[] = "content-length:";
	const char *content_length_field = search_field_header(exch->buffer, exch->header_length, content_length_str,
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
		exch->content_length += exch->header_length;
		exch->buffer_size = exch->content_length;
		void *temp_mem = _realloc(exch->buffer, exch->buffer_size);
		if(temp_mem == NULL) {
			dbg_err("Not enough memory");
			return -3;
		}
		exch->buffer = temp_mem;
	} else {
		const char content_encoding_str[] = "transfer-encoding: chunked";
		const char *content_encoding_field = search_field_header(exch->buffer, exch->header_length, content_encoding_str,
																 strlen(content_encoding_str));
		if(content_encoding_field != NULL) {
			exch->data_chunked = true;
			exch->offset_next_chunk = exch->header_length;  /* Considering that the header is the first chunk */
		} else {
			/* We'll have to detect the end of the data with the FIN segment */
			dbg_info("No length specified");
		}
	}
	return 0;
}

web_status_t fetch_http_msg(web_port_t port, link_msg_type_t msg_type, void *msg, size_t length,
							web_callback_data_t *user_data) {
	(void)port;  /* Unused parameter */
	http_exchange_t *exch = (http_exchange_t *)user_data;

	if(exch->dirty) {
		return WEB_ERROR_FAILED;
	}

	if(msg_type == LINK_MSG_TYPE_RST) {
		exch->dirty = true;
		exch->status = WEB_CONNECTION_TERMINATION_ERROR;
		dbg_err("Aborted connection");
		return WEB_ERROR_FAILED;
	} else if(msg_type == LINK_MSG_TYPE_FIN) {
		dbg_info("Server closed the connection");
		return return_http_data(exch);
	} else if(msg_type != LINK_MSG_TYPE_DATA) {
		dbg_warn("Unexpected HTTP error");
		return WEB_SUCCESS;
	}

	const size_t previous_content_size = exch->content_received;
	const size_t next_content_size = previous_content_size + length;

	/*
	 * First process: Copying the data into a realloced buffer
	 * If the entire header has not been retrieved yet or if the data is chunked:
	 * Then we alloc (at least) twice as memory as it was previously alloced
	 * Otherwise, it means the content size is already known, so skipping.
	 */
	if(exch->buffer_size < next_content_size) {
		/* previous_size * 1.5 until this is big enough */
		size_t new_buffer_size = exch->buffer_size;
		while(new_buffer_size < next_content_size) {
			new_buffer_size = new_buffer_size * 3 / 2;
			if(new_buffer_size > OS_VAR_MAX_SIZE) {
				exch->dirty = true;
				exch->status = WEB_NOT_ENOUGH_MEM;
				dbg_err("Payload too big (> 65KB)");
				return WEB_NOT_ENOUGH_MEM;
			}
		}
		void *temp_mem = _realloc(exch->buffer, new_buffer_size);
		if(temp_mem == NULL) {
			exch->dirty = true;
			exch->status = WEB_NOT_ENOUGH_MEM;
			dbg_err("Not enough memory");
			return WEB_NOT_ENOUGH_MEM;
		}
		exch->buffer_size = new_buffer_size;
		dbg_verb("Buffer grows to %uB", exch->buffer_size);
		exch->buffer = temp_mem;
	}
	memcpy(exch->buffer + previous_content_size, msg, length);
	exch->content_received = next_content_size;

	/*
	 * Second process: extracting the header to get the content-length, connection: close or content encoding field
	 */
	if(!exch->header_length) {
		/* -4 in case the string is splitted between several payloads */
		const size_t search_before = previous_content_size < 4 ? 0 : 4;
		const char *hdr_end = search_field_header(exch->buffer + previous_content_size - search_before,
												  length + search_before, "\r\n", 2);
		if(hdr_end != 0) {
			exch->header_length = hdr_end - (char *)exch->buffer;
			if(search_content_size(exch) != 0) {
				exch->dirty = true;
				exch->status = WEB_ERROR_FAILED;
				return WEB_ERROR_FAILED;
			} else if(exch->content_length > OS_VAR_MAX_SIZE) {
				dbg_err("Payload too big (> 65KB)");
				exch->dirty = true;
				exch->status = WEB_NOT_ENOUGH_MEM;
				return WEB_NOT_ENOUGH_MEM;
			}
		}
	}

	/*
	 * Third process : if the content is chunked
	 */
	if(exch->data_chunked) {
		uint24_t chunk_chars;
		while(exch->offset_next_chunk < exch->content_received) {
			void *chunk_addr = exch->buffer + exch->offset_next_chunk;
			void *end_data = exch->buffer + exch->content_received;
			const size_t chunk_size = get_chunk_size(chunk_addr, end_data, &chunk_chars);
			if(chunk_size == 0xffffff) {
				break;  /* chunk splitted between 2 segments: will search later */
			} else {
				exch->chunks_metadata_length += chunk_chars + 4;
				exch->offset_next_chunk += chunk_size + chunk_chars + 4;  /* 4=\r\n..\r\n */
				if(chunk_size == 0) {
					/* Drop the data after the last chunk metadata */
					exch->chunks_metadata_length += exch->content_received - exch->offset_next_chunk;
					return return_http_data(exch);
				}
			}
		}
	}

	if(exch->content_length != 0 && exch->content_received >= exch->content_length) {
		if(exch->content_length != exch->content_received) {
			dbg_warn("Received more data than expected");
		}
		return return_http_data(exch);
	} else {
		return WEB_SUCCESS;
	}
}

uint24_t get_chunk_size(const char *ascii, const char *max_ptr, uint24_t *chunk_chars) {
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
