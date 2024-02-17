/**
 * DHCP related functions
 */

#ifndef INTERNET_DHCP
#define INTERNET_DHCP


#include <internet.h>
#include <stdint.h>


/**
 * Private functions prototype
*/

void dhcp_init();

web_status_t fetch_dhcp_msg(web_port_t port, uint8_t protocol, void *msg, size_t length,
                            web_callback_data_t *user_data);


#endif // INTERNET_DHCP
