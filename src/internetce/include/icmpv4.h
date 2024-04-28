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

#define TIMEOUT_PING        2   /* 2 seconds timeout */


/**
 * Internal functions prototype
 */

web_status_t fetch_icmpv4_msg(icmpv4_echo_t *msg, size_t length, uint32_t ip_src);

web_status_t ping_timeout_scheduler(web_callback_data_t *user_data);

void ping_timeout_destructor(web_callback_data_t *user_data);


#endif // INTERNET_ICMPV4
