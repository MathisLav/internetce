#include <internet.h>
#include <stdint.h>
#include <stdio.h>

#include "include/debug.h"
#include "include/core.h"


#if DEBUG_LEVEL >= DEBUG_ERRORS
void debug(const void *addr, size_t len) {
	uint8_t *content = (uint8_t *)addr;
	for(size_t i = 0; i < len; i++) {
		if(i && i % 8 == 0) {
			printf("\n");
		}
		printf("%.2X ", *(content + i));
	}
	printf("\n");
}

void printf_xy(unsigned int xpos, unsigned int ypos, const char *format, ...) {
	unsigned int x, y;
	os_GetCursorPos(&x, &y);
	os_SetCursorPos(xpos, ypos);
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	os_SetCursorPos(x, y);
}

void print_tcp_info(const tcp_segment_t *seg, tcp_exchange_t *tcp_exch, size_t length) {
	printf("TCP: ");
	if(seg->dataOffset_flags & htons(FLAG_TCP_SYN)) {
		printf("S");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_ACK)) {
		printf("A");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_RST)) {
		printf("R");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_FIN)) {
		printf("F");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_PSH)) {
		printf("P");
	}
	if(seg->dataOffset_flags & htons(FLAG_TCP_URG)) {
		printf("U");
	}
	if(tcp_exch->beg_ackn != 0) {
		printf(" (%lu+%d)", htonl(seg->seq_number) - tcp_exch->beg_ackn, length - 4 *
			   (seg->dataOffset_flags >> 4 & 0x0f));
	}
	printf(" a=%lu\n", htonl(seg->ack_number) - tcp_exch->beg_sn);
}
#endif

#if DEBUG >= DEBUG_VERBOSE
void monitor_usb_connection(usb_event_t event, device_state_t state) {
	static const char *usb_event_names[] = {
	        "USB_ROLE_CHANGED_EVENT",
			"USB_DEVICE_DISCONNECTED_EVENT",
			"USB_DEVICE_CONNECTED_EVENT",
			"USB_DEVICE_DISABLED_EVENT",
			"USB_DEVICE_ENABLED_EVENT",
			"USB_HUB_LOCAL_POWER_GOOD_EVENT",
			"USB_HUB_LOCAL_POWER_LOST_EVENT",
			"USB_DEVICE_RESUMED_EVENT",
			"USB_DEVICE_SUSPENDED_EVENT",
			"USB_DEVICE_OVERCURRENT_DEACTIVATED_EVENT",
			"USB_DEVICE_OVERCURRENT_ACTIVATED_EVENT",
			"USB_DEFAULT_SETUP_EVENT",
			"USB_HOST_CONFIGURE_EVENT",
			"USB_DEVICE_INTERRUPT",
			"USB_DEVICE_CONTROL_INTERRUPT",
			"USB_DEVICE_DEVICE_INTERRUPT",
			"USB_OTG_INTERRUPT",
			"USB_HOST_INTERRUPT",
			"USB_CONTROL_ERROR_INTERRUPT",
			"USB_CONTROL_ABORT_INTERRUPT",
			"USB_FIFO0_SHORT_PACKET_INTERRUPT",
			"USB_FIFO1_SHORT_PACKET_INTERRUPT",
			"USB_FIFO2_SHORT_PACKET_INTERRUPT",
			"USB_FIFO3_SHORT_PACKET_INTERRUPT",
			"USB_DEVICE_ISOCHRONOUS_ERROR_INTERRUPT",
			"USB_DEVICE_ISOCHRONOUS_ABORT_INTERRUPT",
			"USB_DEVICE_DMA_FINISH_INTERRUPT",
			"USB_DEVICE_DMA_ERROR_INTERRUPT",
			"USB_DEVICE_IDLE_INTERRUPT",
			"USB_DEVICE_WAKEUP_INTERRUPT",
			"USB_B_SRP_COMPLETE_INTERRUPT",
			"USB_A_SRP_DETECT_INTERRUPT",
			"USB_A_VBUS_ERROR_INTERRUPT",
			"USB_B_SESSION_END_INTERRUPT",
			"USB_OVERCURRENT_INTERRUPT",
			"USB_HOST_PORT_CONNECT_STATUS_CHANGE_INTERRUPT",
			"USB_HOST_PORT_ENABLE_DISABLE_CHANGE_INTERRUPT",
			"USB_HOST_PORT_OVERCURRENT_CHANGE_INTERRUPT",
			"USB_HOST_PORT_FORCE_PORT_RESUME_INTERRUPT",
			"USB_HOST_SYSTEM_ERROR_INTERRUPT",
	    };
	    if(event != USB_DEVICE_WAKEUP_INTERRUPT && event != USB_OTG_INTERRUPT && event != USB_DEVICE_DEVICE_INTERRUPT &&
		   event != USB_DEVICE_INTERRUPT && event != USB_HOST_INTERRUPT) {
	    	printf("%s\n", usb_event_names[event]);
	    }
		unsigned int x, y;
		os_GetCursorPos(&x, &y);
		os_SetCursorPos(0, 0);
		printf("%lu    ", usb_GetCycleCounter());
		switch(state) {
			case STATE_USB_CONNECTED:
				printf("CONNECTED   ");
				break;
			case STATE_USB_ENABLED:
				printf("ENABLED     ");
				break;
			case STATE_DHCP_CONFIGURING:
				printf("DHCP        ");
				break;
			case STATE_NETWORK_CONFIGURED:
				printf("NETWORK     ");
				break;
			case STATE_UNKNOWN:
				printf("UNKNOWN     ");
				break;
			case STATE_USB_LOST:
				printf("LOST        ");
				break;
			default:
				printf("???         ");
				break;
		}
		os_SetCursorPos(x, y);
}
#endif
