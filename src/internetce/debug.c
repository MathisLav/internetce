#include <internet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
#endif

#if DEBUG_LEVEL >= DEBUG_INFO
void print_tcp_info(const tcp_segment_t *seg, tcp_exchange_t *tcp_exch, size_t length, bool is_me) {
	if(is_me) {
		printf("SND:");
	} else {
		printf("RCV:");
	}
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

	uint32_t seq_number = htonl(seg->seq_number);
	uint32_t ack_number = htonl(seg->ack_number);
	if(is_me) {
		seq_number -= tcp_exch->beg_sn;
		ack_number -= tcp_exch->beg_ackn;
	} else {
		seq_number -= tcp_exch->beg_ackn;
		ack_number -= tcp_exch->beg_sn;
	}
	if(tcp_exch->beg_ackn != 0 && tcp_exch->beg_sn != 0) {
		printf(" (%lu+%d)", seq_number, length - 4 * (seg->dataOffset_flags >> 4 & 0x0f));
	}
	printf(" a=%lu\n", ack_number);
}

static alloced_mem_t *alloced_mem_list = NULL;
void *_malloc(size_t size, const char *id) {
	alloced_mem_t *alloced_mem = malloc(sizeof(alloced_mem_t));
	alloced_mem->next = alloced_mem_list;
	alloced_mem_list = alloced_mem;
	alloced_mem->ptr = malloc(size);
	if(id != NULL) {
		strncpy(alloced_mem->id, id, 10);
	} else {
		alloced_mem->id[0] = 0x00;
	}
	return alloced_mem->ptr;
}

void *_realloc(void *ptr, size_t size) {
	alloced_mem_t *cur_alloced = alloced_mem_list;
	while(cur_alloced) {
		if(cur_alloced->ptr == ptr) {
			void *new_ptr = realloc(ptr, size);
			if(new_ptr == NULL) {
				return NULL;
			}
			cur_alloced->ptr = new_ptr;
			return new_ptr;
		}
		cur_alloced = cur_alloced->next;
	}
	dbg_err("NOT FOUND REALLOC %p", ptr);
	return NULL;
}

void _free(void *ptr) {
	alloced_mem_t *cur_alloced = alloced_mem_list;
	alloced_mem_t *prev_alloced = NULL;
	while(cur_alloced) {
		if(cur_alloced->ptr == ptr) {
			free(ptr);
			if(prev_alloced) {
				prev_alloced->next = cur_alloced->next;
			} else {
				alloced_mem_list = cur_alloced->next;
			}
			free(cur_alloced);
			return;
		}
		prev_alloced = cur_alloced;
		cur_alloced = cur_alloced->next;
	}
	dbg_err("NOT FOUND %p", ptr);
}

void print_allocated_memory() {
	alloced_mem_t *cur_alloced = alloced_mem_list;
	if(alloced_mem_list == NULL) {
		printf("Good memory state!\n");
		return;
	}
	while(cur_alloced) {
		if(cur_alloced->id[0] != 0x00) {
			printf("%s ", cur_alloced->id);
		} else {
			debug(cur_alloced->ptr - 4, 15);
		}
		cur_alloced = cur_alloced->next;
	}
}
#else
void *_malloc(size_t size, const char *id) {
	(void)id;  /* Unused parameter */
	return malloc(size);
}

void *_realloc(void *ptr, size_t size) {
	return realloc(ptr, size);
}

void _free(void *ptr) {
	free(ptr);
}
#endif

#if DEBUG_LEVEL >= DEBUG_VERBOSE
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
			case STATE_USB_INITIALIZED:
				printf("INITIALIZED ");
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
