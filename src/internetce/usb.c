#include <internet.h>
#include <stdlib.h>
#include <stdio.h>

#include "include/usb.h"
#include "include/core.h"
#include "include/rndis.h"
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
			usb_RefDevice(netinfo.device);
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
			usb_UnrefDevice(netinfo.device);
			netinfo.device = NULL;
			break;
		default:
			break;
	}
	monitor_usb_connection(event);

	return USB_SUCCESS;
}

web_status_t configure_usb_device() {
	uint8_t buffer[256] = {0};  /* Allocating 256 bytes for the messages buffer, should be enough */
	size_t len = 0;
	size_t total_length;
	bool is_wireless_int = false, is_cdc_int = false;
	uint8_t i = 0;

	/* First, let's retrieve the configuration descriptor total size */
	usb_GetDescriptor(netinfo.device, USB_CONFIGURATION_DESCRIPTOR, 0, buffer, 9, &len);
	if(len != 9) {
		return WEB_ERROR_FAILED;
	}
	total_length = ((usb_configuration_descriptor_t*)buffer)->wTotalLength;  /* More or less 40 bytes */
	if(total_length > 256) {
		return WEB_NOT_ENOUGH_MEM;
	}

	usb_GetDescriptor(netinfo.device, USB_CONFIGURATION_DESCRIPTOR, 0, buffer, total_length, &len);
	if(len != total_length) {
		return WEB_ERROR_FAILED;
	}

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
	if(usb_SetConfiguration(netinfo.device, (usb_configuration_descriptor_t*)buffer, len) != USB_SUCCESS) {
		return WEB_ERROR_FAILED;
	}

	init_rndis_exchange();

	return WEB_SUCCESS;
}

usb_error_t packets_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
							 usb_transfer_data_t *data) {
	(void)endpoint;  /* Unused parameter */

	void *packet = *(void **)data;
	*(void **)data = NULL;

	if(status & USB_ERROR_NO_DEVICE) {
		dbg_warn("Lost connection (pckt)");
		netinfo.state = STATE_USB_LOST;
		free(packet);
		return USB_ERROR_FAILED;
	} else if(status != USB_SUCCESS) {
		dbg_warn("Packet callback returned %u", status);
		free(packet);
		return USB_SUCCESS;
	}

	/* Several messages can be queued in the same transfer */
	void *cur_packet = packet;
	while(cur_packet < packet + transferred) {
		eth_frame_t *frame = (eth_frame_t *)(cur_packet + sizeof(rndis_packet_msg_t));
		web_status_t ret_status = fetch_ethernet_frame(frame, ((rndis_packet_msg_t *)cur_packet)->DataLength);
		if(ret_status != WEB_SUCCESS) {
			return USB_ERROR_FAILED;
		}
		cur_packet = cur_packet + sizeof(rndis_packet_msg_t) + ((rndis_packet_msg_t *)cur_packet)->DataLength;
	}

	free(packet);
	return USB_SUCCESS;
}
