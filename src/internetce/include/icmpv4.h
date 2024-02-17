/**
 * ICMPv4 related functions
 */

#ifndef INTERNET_ICMPV4
#define INTERNET_ICMPV4


#include <internet.h>
#include <stdint.h>


/**
 * Private functions prototype
*/

web_status_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src);


#endif // INTERNET_ICMPV4
