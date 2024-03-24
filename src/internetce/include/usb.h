/**
 * USB functions
 */

#ifndef INTERNET_USB
#define INTERNET_USB


#include <internet.h>


/**
 * Internal functions prototype
 */

usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *data);

web_status_t configure_usb_device();

usb_error_t packets_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
							 usb_transfer_data_t *data);


#endif // INTERNET_USB
