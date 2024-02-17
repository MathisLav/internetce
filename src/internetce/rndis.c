#include <internet.h>
#include <string.h>

#include "include/rndis.h"
#include "include/debug.h"
#include "include/core.h"


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

msg_queue_t *web_PushRNDISPacket(void *data, size_t length_data) {
	void *buffer = _alloc_msg_buffer(data, length_data, sizeof(rndis_packet_msg_t), false);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushRNDISPacket(buffer, buffer + sizeof(rndis_packet_msg_t), length_data);
}

web_status_t web_SendRNDISPacket(void *data, size_t length_data) {
	msg_queue_t *queued = web_PushRNDISPacket(data, length_data);
	if(queued != NULL) {
		queued->waitingTime = 0;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

msg_queue_t *_recursive_PushRNDISPacket(void *buffer, void *data, size_t length_data) {
	if(data - sizeof(rndis_packet_msg_t) != buffer) {
		dbg_err("Can't push RNDIS packet");
		return NULL;
	}

	rndis_packet_msg_t *pckt = (rndis_packet_msg_t *)(data - sizeof(rndis_packet_msg_t));
	memset(pckt, 0, sizeof(rndis_packet_msg_t));
	pckt->MessageType = RNDIS_PACKET_MSG;
	pckt->MessageLength = sizeof(rndis_packet_msg_t) + length_data;
	pckt->DataOffset = 36;
	pckt->DataLength = length_data;
	memcpy((void *)pckt + sizeof(rndis_packet_msg_t), data, length_data);

	return web_PushMessage(pckt, length_data + sizeof(rndis_packet_msg_t));
}
