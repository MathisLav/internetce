/**
 * DNS related functions
 */

#ifndef INTERNET_DNS
#define INTERNET_DNS


#include <internet.h>
#include <stdint.h>


/**
 * Internal functions prototype
 */

web_status_t dns_callback(web_port_t port, uint32_t res_ip, web_callback_data_t *user_data);

web_status_t dns_timeout_scheduler(web_callback_data_t *user_data);

void dns_timeout_destructor(web_callback_data_t *user_data);

web_status_t fetch_dns_msg(web_port_t port, uint8_t protocol, void *msg, size_t length, web_callback_data_t *user_data);


#endif // INTERNET_DNS
