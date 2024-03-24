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

web_status_t packets_callback(size_t transferred, void *data);


#endif // INTERNET_USB
