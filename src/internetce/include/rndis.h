/**
 * RNDIS related functions
 */

#ifndef INTERNET_RNDIS
#define INTERNET_RNDIS


#include <internet.h>
#include <stdint.h>


/**
 * Private functions prototype
*/

msg_queue_t *_recursive_PushRNDISPacket(void *buffer, void *data, size_t length_data);


#endif // INTERNET_RNDIS
