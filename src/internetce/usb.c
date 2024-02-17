#include <internet.h>

#include "include/usb.h"
#include "include/core.h"
#include "include/debug.h"
#include "include/ethernet.h"


usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *data) {
	(void)data; /* Unused parameter */
	switch(event)
	{
		case USB_DEVICE_CONNECTED_EVENT:
			netinfo.device = (usb_device_t)event_data;
			netinfo.state = STATE_USB_CONNECTED;
			usb_ResetDevice(netinfo.device);
			break;
		case USB_DEVICE_ENABLED_EVENT:
			if(!(usb_GetRole() & USB_ROLE_DEVICE)) {
				netinfo.state = STATE_USB_ENABLED;
			} else {
				usb_DisableDevice(netinfo.device);
				netinfo.state = STATE_UNKNOWN;
			}
			break;
		case USB_DEVICE_DISABLED_EVENT:
		case USB_DEVICE_DISCONNECTED_EVENT:
			netinfo.state = STATE_USB_LOST;
			break;
		default:
			break;
	}
	monitor_usb_connection(event);

	return USB_SUCCESS;
}

web_status_t configure_usb_device() {
	rndis_init_msg_t rndis_initmsg = {RNDIS_INIT_MSG, 24, 0, 1, 0, MAX_SEGMENT_SIZE + 110};
	rndis_set_msg_t rndis_setpcktflt = {RNDIS_SET_MSG , 32, 4, 0x0001010e, 4, 20, 0, 0x2d};
	usb_control_setup_t out_ctrl = {0x21, 0, 0, 0, 0};
	usb_control_setup_t in_ctrl = {0xa1, 1, 0, 0, 256};
	uint8_t buffer[256] = {0};  /* Allocating 256 bytes for the messages buffer, should be enough */
	size_t len = 0;
	size_t total_length;
	bool is_wireless_int = false, is_cdc_int = false;
	uint8_t i = 0;

	/* First, let's retrieve the configuration descriptor total size */
	usb_GetDescriptor(netinfo.device, USB_CONFIGURATION_DESCRIPTOR, 0, buffer, 9, &len);
	if(len != 9)
		return WEB_ERROR_FAILED;
	total_length = ((usb_configuration_descriptor_t*)buffer)->wTotalLength;  /* More or less 40 bytes */
	if(total_length > 256)
		return WEB_NOT_ENOUGH_MEM;

	usb_GetDescriptor(netinfo.device, USB_CONFIGURATION_DESCRIPTOR, 0, buffer, total_length, &len);
	if(len != total_length)
		return WEB_ERROR_FAILED;

	/* Iterating through all the descriptors to see if there are an rndis and cdc interfaces */
	while(i < len) {
		usb_descriptor_t *usb_descr = (usb_descriptor_t*)(buffer + i);
		switch(usb_descr->bDescriptorType) {
			/* USB Interface Descriptor */
			case USB_INTERFACE_DESCRIPTOR: {
				usb_interface_descriptor_t *interface_desc = (usb_interface_descriptor_t*)usb_descr;
				if(interface_desc->bInterfaceClass    == USB_WIRELESS_CONTROLLER_CLASS &&
				   interface_desc->bInterfaceSubClass == WIRELESS_RNDIS_SUBCLASS &&
				   interface_desc->bInterfaceProtocol == WIRELESS_RNDIS_PROTOCOL)
				{
					is_wireless_int = true;
					is_cdc_int = false;
				} else if(interface_desc->bInterfaceClass    == USB_MISCELLANEOUS_CLASS &&
				   		  interface_desc->bInterfaceSubClass == MISC_RNDIS_SUBCLASS &&
				   		  interface_desc->bInterfaceProtocol == MISC_RNDIS_PROTOCOL)
				{
					is_wireless_int = true;
					is_cdc_int = false;
				} else if(interface_desc->bInterfaceClass == USB_CDC_DATA_CLASS &&
						  interface_desc->bInterfaceSubClass == 0x00 &&
						  interface_desc->bInterfaceProtocol == 0x00)
				{
					is_wireless_int = false;
					is_cdc_int = true;
				} else {
					is_wireless_int = false;
					is_cdc_int = false;
				}
				break;
			}
			/* USB Endpoint Descriptor */
			case USB_ENDPOINT_DESCRIPTOR: {
				usb_endpoint_descriptor_t *endpoint_desc = (usb_endpoint_descriptor_t*)usb_descr;
				if(is_wireless_int) {
					netinfo.ep_wc_in = endpoint_desc->bEndpointAddress;
				} else if(is_cdc_int && (endpoint_desc->bEndpointAddress & 0x80) != 0) {  /* IN endpoint */
					netinfo.ep_cdc_in = endpoint_desc->bEndpointAddress;
				} else if(is_cdc_int && (endpoint_desc->bEndpointAddress & 0x80) == 0) {  /* OUT endpoint */
					netinfo.ep_cdc_out = endpoint_desc->bEndpointAddress;
				}
				break;
			}
			/* Unknown, Unrelevant Descriptor */
			default:
				break;
		}

		i += usb_descr->bLength;
	}

	/* If one is missing, ignoring the device */
	if(netinfo.ep_wc_in == 0 || netinfo.ep_cdc_in == 0 || netinfo.ep_cdc_out == 0) {
		netinfo.state = STATE_UNKNOWN;
		netinfo.ep_wc_in = 0;
		netinfo.ep_cdc_in = 0;
		netinfo.ep_cdc_out = 0;
		return WEB_IGNORE;
	}

	/* Otherwise, let's goooo */
	if(usb_SetConfiguration(netinfo.device, (usb_configuration_descriptor_t*)buffer, len) != USB_SUCCESS)
		return WEB_ERROR_FAILED;

	/************** Configuration RNDIS ************/
	out_ctrl.wLength = 24;
	do {
		usb_DefaultControlTransfer(netinfo.device, &out_ctrl, &rndis_initmsg, 3, NULL);
		usb_DefaultControlTransfer(netinfo.device, &in_ctrl, buffer, 3, &len);
	} while(len == 0 || ((rndis_msg_t*)buffer)->MessageType != RNDIS_INIT_CMPLT);

	out_ctrl.wLength = 32;
	do {
		usb_DefaultControlTransfer(netinfo.device, &out_ctrl, &rndis_setpcktflt, 3, NULL);
		usb_DefaultControlTransfer(netinfo.device, &in_ctrl, buffer, 3, &len);
	} while(len == 0 || ((rndis_msg_t*)buffer)->MessageType != RNDIS_SET_CMPLT);

	return WEB_SUCCESS;
}

web_status_t packets_callback(size_t transferred, void *data) {
	if(transferred >= MAX_SEGMENT_SIZE + 110) {
		dbg_err("No memory");
		return WEB_NOT_ENOUGH_MEM;
	}
	/* Several messages can be queued in the same transfer */
	void *cur_packet = data;
	while(cur_packet < data + transferred) {
		eth_frame_t *frame = (eth_frame_t *)(data + sizeof(rndis_packet_msg_t));
		web_status_t ret_status = fetch_ethernet_frame(frame, ((rndis_packet_msg_t *)cur_packet)->DataLength);
		if(ret_status != WEB_SUCCESS) {
			return ret_status;
		}
		cur_packet = cur_packet + sizeof(rndis_packet_msg_t) + ((rndis_packet_msg_t *)cur_packet)->DataLength;
	}
	return WEB_SUCCESS;
}
