/**
 * ICMPv4 related functions
 */

#ifndef INTERNET_ICMPV4
#define INTERNET_ICMPV4


#include <internet.h>
#include <stdint.h>


/**
 * Constants
 */

#define PING_TIMEOUT        2   /* 2 seconds timeout */


/**
 * Internal functions prototype
 */

web_status_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src);


#endif // INTERNET_ICMPV4
