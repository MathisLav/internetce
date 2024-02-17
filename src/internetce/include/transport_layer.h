/**
 * Transort layer related functions
 */

#ifndef INTERNET_TRANSPORT_LAYER
#define INTERNET_TRANSPORT_LAYER


#include <internet.h>
#include <stdint.h>


/**
 * Global variable
 */

extern port_list_t *listened_ports;


/**
 * Private functions prototype
*/

web_status_t call_callbacks(uint8_t protocol, void *data, size_t length, web_port_t port);

uint16_t transport_checksum(void *data, size_t length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol);


#endif // INTERNET_TRANSPORT_LAYER
