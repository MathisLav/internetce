#include <internet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "include/rndis.h"
#include "include/debug.h"
#include "include/core.h"
#include "include/scheduler.h"


/**********************************************************************************************************************\
 *                                                  Global Variables                                                  *
\**********************************************************************************************************************/

static rndis_state_t rndis_state = {
	.cur_request_id = 1,
	.max_transfer_size = 0,  /* Set later */
};

static const usb_control_setup_t in_setup_buffer = (usb_control_setup_t){
	.bmRequestType = USB_DEVICE_TO_HOST | USB_CLASS_REQUEST | USB_RECIPIENT_INTERFACE,
	.bRequest = 1,
	.wValue = 0,
	.wIndex = 0,
	.wLength = 128
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
		queued->send_once = true;  /* Send once */
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
	const usb_control_setup_t out_ctrl = {
		.bmRequestType = USB_HOST_TO_DEVICE | USB_CLASS_REQUEST | USB_RECIPIENT_INTERFACE,
		.bRequest = 0,
		.wValue = 0,
		.wIndex = 0,
		.wLength = length};
	void *buffer = malloc(sizeof(usb_control_setup_t) + length);
	void *data = buffer + sizeof(usb_control_setup_t);
	memcpy(buffer, &out_ctrl, sizeof(usb_control_setup_t));
	memcpy(data, rndis_msg, length);
	usb_ScheduleDefaultControlTransfer(netinfo.device, (usb_control_setup_t *)buffer, data, out_control_rndis_callback, buffer);
}

usb_error_t out_control_rndis_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
							  		   usb_transfer_data_t *data) {
	(void)endpoint;  /* Unused parameters */
	if(status & USB_ERROR_NO_DEVICE || transferred == 0) {
		dbg_warn("Lost connection (int)");
		netinfo.state = STATE_USB_LOST;
		return USB_ERROR_FAILED;
	}

	free(data);
	return USB_SUCCESS;
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
	rndis_state.has_keepalive_cmplt_received = true;
	send_control_rndis(&rndis_initmsg, sizeof(rndis_init_msg_t));
	poll_interrupt_scheduler();
}

void send_rndis_halt() {
	rndis_halt_msg_t rndis_haltmsg = {
		.MessageType = RNDIS_HALT_MSG,
		.MessageLength = sizeof(rndis_halt_msg_t),
		.RequestId = rndis_state.cur_request_id++,
	};
	send_control_rndis(&rndis_haltmsg, sizeof(rndis_halt_msg_t));
	netinfo.state = STATE_USB_LOST;
	dbg_warn("Halt RNDIS /!\\");
}

void send_rndis_set_msg(uint32_t oid, const void *value, size_t value_size) {
	uint8_t rndis_set_filter_buffer[sizeof(rndis_set_msg_t) + value_size];
	rndis_set_msg_t *rndis_set_filter = (rndis_set_msg_t *)rndis_set_filter_buffer;
	rndis_set_filter->MessageType = RNDIS_SET_MSG;
	rndis_set_filter->MessageLength = sizeof(rndis_set_msg_t) + value_size;
	rndis_set_filter->RequestId = rndis_state.cur_request_id++;
	rndis_set_filter->Oid = oid;
	rndis_set_filter->InformationBufferLength = value_size;
	rndis_set_filter->InformationBufferOffset = 20;
	rndis_set_filter->DeviceVcHandle = 0;
	memcpy(rndis_set_filter_buffer + sizeof(rndis_set_msg_t), value, value_size);
	send_control_rndis(rndis_set_filter_buffer, sizeof(rndis_set_msg_t) + value_size);
}

void send_rndis_keepalive_msg() {
	if(!rndis_state.has_keepalive_cmplt_received) {
		dbg_warn("The previous keepalive was unanswered");
		// Specs would want to do that but hey, as long as everything's working...
		// send_rndis_reset_msg(); 
		// return;
	}

	rndis_keepalive_msg_t keepalive_msg = {
		.MessageType = RNDIS_KEEPALIVE_MSG,
		.MessageLength = sizeof(rndis_keepalive_msg_t),
		.RequestId = rndis_state.cur_request_id++,
	};
	send_control_rndis(&keepalive_msg, sizeof(rndis_keepalive_msg_t));

	rndis_state.has_keepalive_cmplt_received = false;
}


void send_rndis_keepalive_cmplt(uint32_t request_id) {
	rndis_keepalive_msg_t keepalive_msg = {
		.MessageType = RNDIS_KEEPALIVE_CMPLT,
		.MessageLength = sizeof(rndis_keepalive_msg_t),
		.RequestId = request_id,
	};

	send_control_rndis(&keepalive_msg, sizeof(rndis_keepalive_msg_t));
	dbg_info("Keepalive rcvd");
}

void send_rndis_reset_msg() {
	rndis_reset_msg_t reset_msg = {
		.MessageType = RNDIS_RESET_MSG,
		.MessageLength = sizeof(rndis_ctrl_msg_t),
		.Reserved = 0,
	};

	dbg_warn("Reset RNDIS /!\\");
	send_control_rndis(&reset_msg, sizeof(rndis_reset_msg_t));
	netinfo.state = STATE_RNDIS_INIT;
}

usb_error_t interrupt_handler(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
							  usb_transfer_data_t *data) {
	(void)endpoint; (void)status; (void)transferred; (void)data;

	if(status & USB_ERROR_NO_DEVICE) {
		dbg_warn("Lost connection (int)");
		netinfo.state = STATE_USB_LOST;
		return USB_ERROR_FAILED;
	}

	uint8_t *buffer = malloc(RNDIS_CONTROL_BUFFER);
	usb_ScheduleDefaultControlTransfer(netinfo.device, &in_setup_buffer, buffer, ctrl_rndis_callback, buffer);
	poll_interrupt_scheduler();

	return USB_SUCCESS;
}

usb_error_t ctrl_rndis_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
								usb_transfer_data_t *data) {
	(void)transferred; (void)endpoint;  /* Unused parameter */

	free(data);

	if(status & USB_ERROR_NO_DEVICE) {
		dbg_warn("Lost connection (ctrl)");
		netinfo.state = STATE_USB_LOST;
		return USB_ERROR_FAILED;
	}

	rndis_ctrl_msg_t *rndis_msg = (rndis_ctrl_msg_t *)data;
	if(rndis_msg->MessageType & CMPLT_TYPE && rndis_msg->MessageType != RNDIS_RESET_CMPLT &&
	   ((rndis_ctrl_cmplt_t *)rndis_msg)->Status != RNDIS_STATUS_SUCCESS) {
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
			|| init_cmplt->MaxPacketsPerTransfer == 0 || init_cmplt->MaxTransferSize < 536 + TCP_HEADERS_SIZE \
			|| init_cmplt->Medium != RNDIS_MEDIUM_802_3) {
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
			/*
				Send Keepalives every SEND_KEEPALIVE_INTERVAL (5s).
				For now, keepalives are sent no matter if messages have been received in between.
			*/
			schedule(SEND_KEEPALIVE_INTERVAL, send_keepalive_scheduler, NULL, SEND_KEEPALIVE_SCHED_ID);
			break;
		case RNDIS_RESET_CMPLT:
			dbg_info("Received reset cmplt");
			if(((rndis_reset_cmplt_t *)rndis_msg)->Status != RNDIS_STATUS_SUCCESS) {
				dbg_err("Wow, this device is lost, amen...");
				send_rndis_halt();
			} else {
				flush_event_list();
				init_rndis_exchange();
			}
			break;
		case RNDIS_INDICATE_MSG:
			dbg_warn("Device sent an Indicate Status Message: %lx", ((rndis_ctrl_cmplt_t *)rndis_msg)->Status);
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

void poll_interrupt_scheduler() {
	usb_ScheduleInterruptTransfer(usb_GetDeviceEndpoint(netinfo.device, netinfo.ep_wc_in),
								  rndis_state.interrupt_buffer, 8, interrupt_handler, NULL);
}

web_status_t send_keepalive_scheduler(web_callback_data_t *user_data) {
	(void)user_data;  /* should be SEND_KEEPALIVE_SCHED_ID */
	send_rndis_keepalive_msg();
	return WEB_SUCCESS;
}
