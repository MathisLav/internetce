/**
 * HTTP related functions
 */

#ifndef INTERNET_HTTP
#define INTERNET_HTTP


#include <internet.h>
#include <stdint.h>


/**
 * Global variable
 */

extern http_data_list_t *http_data_list;


/**
 * Private functions prototype
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
