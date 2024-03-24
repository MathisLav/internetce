#include <internet.h>
#include <stdlib.h>
#include <string.h>

#include "include/rndis.h"
#include "include/debug.h"
#include "include/core.h"


/**********************************************************************************************************************\
 *                                                  Global Variables                                                  *
\**********************************************************************************************************************/

static rndis_state_t rndis_state = {
	.cur_request_id = 1,
	.has_keepalive_cmplt_received = true,
	.max_transfer_size = 0,  /* Set later */
};


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
		free(buffer);
		return NULL;
	}

	if(length_data + sizeof(rndis_packet_msg_t) > rndis_state.max_transfer_size) {
		dbg_err("Trying to send a too large RNDIS packet");
		free(buffer);
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

void send_control_rndis(void *rndis_msg, size_t length) {
	usb_control_setup_t out_ctrl = {
		.bmRequestType = USB_HOST_TO_DEVICE | USB_CLASS_REQUEST | USB_RECIPIENT_INTERFACE,
		.bRequest = 0,
		.wValue = 0,
		.wIndex = 0,
		.wLength = length};
	usb_DefaultControlTransfer(netinfo.device, &out_ctrl, rndis_msg, 0, NULL);
}

void init_rndis_exchange() {
	rndis_init_msg_t rndis_initmsg = {
		.MessageType = RNDIS_INIT_MSG,
		.MessageLength = sizeof(rndis_init_msg_t),
		.RequestId = rndis_state.cur_request_id++,
		.MajorVersion = RNDIS_MAJOR_VERSION,
		.MinorVersion = RNDIS_MINOR_VERSION,
		.MaxTransferSize = MAX_RNDIS_TRANSFER_SIZE,
	};
	send_control_rndis(&rndis_initmsg, sizeof(rndis_init_msg_t));
	usb_ScheduleInterruptTransfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_wc_in), rndis_state.interrupt_buffer,
								  8, interrupt_handler, NULL);
}

void send_rndis_set_msg(uint32_t oid, const void *value, size_t value_size) {
	uint8_t rndis_set_filter_buffer[sizeof(rndis_set_msg_t) + value_size];
	rndis_set_msg_t *rndis_set_filter = (rndis_set_msg_t *)rndis_set_filter_buffer;
	rndis_set_filter->MessageType = RNDIS_SET_MSG;
	rndis_set_filter->MessageLength = sizeof(rndis_set_msg_t) + value_size;
	rndis_set_filter->RequestId = rndis_state.cur_request_id++;
	rndis_set_filter->Oid = oid;
	rndis_set_filter->InformationBufferLength = 4;
	rndis_set_filter->InformationBufferOffset = 20;
	rndis_set_filter->DeviceVcHandle = 0;
	memcpy(rndis_set_filter_buffer + sizeof(rndis_set_msg_t), value, value_size);
	send_control_rndis(rndis_set_filter_buffer, sizeof(rndis_set_msg_t) + value_size);
}

void send_rndis_keepalive_msg() {
	if(!rndis_state.has_keepalive_cmplt_received) {
		dbg_warn("The previous keepalive was unanswered");
		send_rndis_reset_msg();
	}

	rndis_keepalive_msg_t keepalive_msg = {
		.MessageLength = sizeof(rndis_keepalive_msg_t),
		.MessageType = RNDIS_KEEPALIVE_MSG,
		.RequestId = rndis_state.cur_request_id++,
	};

	send_control_rndis(&keepalive_msg, sizeof(rndis_keepalive_msg_t));

	rndis_state.has_keepalive_cmplt_received = false;
}


void send_rndis_keepalive_cmplt(uint32_t request_id) {
	rndis_keepalive_msg_t keepalive_msg = {
		.MessageLength = sizeof(rndis_keepalive_msg_t),
		.MessageType = RNDIS_KEEPALIVE_CMPLT,
		.RequestId = request_id,
	};

	send_control_rndis(&keepalive_msg, sizeof(rndis_keepalive_msg_t));
}

void send_rndis_reset_msg() {
	rndis_ctrl_msg_t reset_msg = {
		.MessageLength = sizeof(rndis_ctrl_msg_t),
		.MessageType = RNDIS_RESET_MSG,
		.RequestId = 0,  /* Reserved */
	};

	dbg_warn("Reset RNDIS /!\\");
	send_control_rndis(&reset_msg, sizeof(rndis_ctrl_msg_t));
	netinfo.state = STATE_USB_ENABLED;
}

// TODO use frame number instead of rtc_clock to handle time events (1 frame = 1ms ?)
// => would allow to send IN on interrupt every 9 frames as expected (read the value on conf?)

// Je pense ça peut être bien de créer une classe time_events qui gèrerait ce genre de chose:
//	-> du genre callback au bout d'un certain temps, executer une action tous les tant etc

usb_error_t interrupt_handler(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
							  usb_transfer_data_t *data) {
	(void)endpoint; (void)status; (void)transferred; (void)data;
	usb_error_t ret_val;
	static const usb_control_setup_t in_ctrl = {
		.bmRequestType = USB_DEVICE_TO_HOST | USB_CLASS_REQUEST | USB_RECIPIENT_INTERFACE,
		.bRequest = 1,
		.wValue = 0,
		.wIndex = 0,
		.wLength = 256};
	uint8_t in_buffer[256] = {0};
	size_t transf = 0;

	usb_DefaultControlTransfer(netinfo.device, &in_ctrl, in_buffer, 0, &transf);
	if(transf != 0) {
		ret_val = ctrl_rndis_callback(transf, in_buffer);
	} else {
		dbg_info("No data on ctrl endpoint");
		ret_val = USB_ERROR_FAILED;
	}
	usb_ScheduleInterruptTransfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_wc_in), rndis_state.interrupt_buffer,
								  8, interrupt_handler, NULL);
	return ret_val;
}

usb_error_t ctrl_rndis_callback(size_t transferred, void *data) {
	(void)transferred;  /* Unused parameter */
	rndis_ctrl_msg_t *rndis_msg = (rndis_ctrl_msg_t *)data;

	if(rndis_msg->MessageType & CMPLT_TYPE && ((rndis_ctrl_cmplt_t *)rndis_msg)->Status != RNDIS_STATUS_SUCCESS) {
		dbg_warn("An RNDIS error occurred");
		send_rndis_reset_msg();
		return USB_SUCCESS;
	}

	switch(rndis_msg->MessageType) {
		case RNDIS_INIT_CMPLT: {
			/* Checking everything's OK */
			const rndis_init_cmplt_t *init_cmplt = (rndis_init_cmplt_t *)data;
			if(init_cmplt->MessageLength != sizeof(rndis_init_cmplt_t) || init_cmplt->DeviceFlags != RNDIS_DF_CONNECTIONLESS \
			|| init_cmplt->MajorVersion != RNDIS_MAJOR_VERSION || init_cmplt->MinorVersion != RNDIS_MINOR_VERSION \
			|| init_cmplt->MaxPacketsPerTransfer == 0 || init_cmplt->MaxTransferSize < 536 + TCP_HEADERS_SIZE) {
				dbg_err("Invalid RNDIS Init response");
				send_rndis_reset_msg();
				return USB_SUCCESS;
			}

			rndis_state.max_transfer_size = min(init_cmplt->MaxTransferSize, MAX_RNDIS_TRANSFER_SIZE);
			const uint32_t filter_value = RNDIS_PACKET_TYPE_DIRECTED | RNDIS_PACKET_TYPE_ALL_MULTICAST |
										  RNDIS_PACKET_TYPE_BROADCAST | RNDIS_PACKET_TYPE_PROMISCUOUS;
			send_rndis_set_msg(OID_GEN_CURRENT_PACKET_FILTER, &filter_value, sizeof(uint32_t));
			break;
		}
		case RNDIS_QUERY_CMPLT:
			dbg_err("Not supported yet");
			break;
		case RNDIS_SET_CMPLT:  /* Only one Set for now */
			netinfo.state = STATE_RNDIS_DATA_INIT;
			break;
		case RNDIS_RESET_CMPLT:
			init_rndis_exchange();
			break;
		case RNDIS_INDICATE_MSG:
			dbg_warn("Device sent an Indicate Status Message: %lx", ((rndis_ctrl_cmplt_t *)rndis_msg)->Status);
			pause();
			break;
		case RNDIS_KEEPALIVE_MSG:  /* The device is conceited enough to send us a KEEPALIVE request... */
			send_rndis_keepalive_cmplt(rndis_msg->RequestId);
			break;
		case RNDIS_KEEPALIVE_CMPLT:
			rndis_state.has_keepalive_cmplt_received = true;
			break;
	/*
		case RNDIS_PACKET_MSG:
		case RNDIS_INIT_MSG:
		case RNDIS_HALT_MSG:
		case RNDIS_QUERY_MSG:
		case RNDIS_SET_MSG:
	*/
		default:
			dbg_warn("Unexpected RNDIS message: %lx", rndis_msg->MessageType);
			break;
	}

	return USB_SUCCESS;
}
