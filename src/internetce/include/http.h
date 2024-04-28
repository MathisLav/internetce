/**
 * HTTP related functions
 */

#ifndef INTERNET_HTTP
#define INTERNET_HTTP


#include <internet.h>
#include <stdint.h>

/**
 * Constants
 */

#define BASIC_HTTP_REQUEST "%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n"
#define POST_HTTP_INFO "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s"


/**
 * Enums & structs
 */

typedef struct http_exchange {
	bool data_chunked;
	size_t content_length;
	size_t content_received;
	size_t header_length;
	size_t chunks_metadata_length;		/**< Size of all the characters encoding chunks metadata			*/
	size_t offset_next_chunk;			/**< Offset from beggining of the next chunk						*/
	http_data_t **data;					/**< Where to put the result										*/
	void *buffer;						/**< Temporary buffer while receiving data							*/
	size_t buffer_size;
	bool keep_http_header;
	bool timeout;
	web_status_t status;				/**< Set when the request is finished (successfuly or with an error) */
	bool dirty;
} http_exchange_t;

typedef struct http_data_list {
	char varname[9];
	struct http_data_list *next;
} http_data_list_t;


/**
 * Global variable
 */

extern http_data_list_t *http_data_list;


/**
 * Internal functions prototype
 */

uint32_t ip_ascii_to_hex(const char *ipstr);

web_status_t http_request(const char *request_type, const char* url, http_data_t **data, bool keep_http_header,
                          char *params);

void fill_window(char *window, size_t size_window, tcp_segment_list_t *cur_seg, size_t chunk_offset);

web_status_t return_http_data(http_exchange_t *exch);

size_t search_in_str(const char *data, size_t length, const char *str, size_t size_str);

char *lowercase(char *dst_str, const char *src_str, size_t length);

const char *search_field_header(const char *data, size_t length, const char *str, size_t size_str);

int search_content_size(http_exchange_t *exch);

web_status_t fetch_http_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
							web_callback_data_t *user_data);

uint24_t get_chunk_size(const char *ascii, const char *max_ptr, uint24_t *chunk_chars);


#endif // INTERNET_HTTP
