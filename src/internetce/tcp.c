#include <internet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "include/tcp.h"
#include "include/core.h"
#include "include/debug.h"
#include "include/transport_layer.h"
#include "include/http.h"
#include "include/ipv4.h"
#include "include/scheduler.h"


tcp_exchange_list_t *tcp_exchanges = NULL;


/**********************************************************************************************************************\
 *                                                  Public functions                                                  *
\**********************************************************************************************************************/

msg_queue_t *web_PushRawTCPSegment(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								   web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags,
								   size_t opt_size, const uint8_t *options) {
	void *buffer = _alloc_msg_buffer(data, length_data, TCP_HEADERS_SIZE + opt_size, true);
	if(buffer == NULL) {
		return NULL;
	}
	return _recursive_PushTCPSegment(buffer, buffer + TCP_HEADERS_SIZE + opt_size - 4, length_data,
									 ip_dst, port_src, port_dst, seq_number, ack_number, flags,
									 opt_size, options);
}

web_status_t web_SendRawTCPSegment(void *data, size_t length_data, uint32_t ip_dst, web_port_t port_src,
								   web_port_t port_dst, uint32_t seq_number, uint32_t ack_number, uint16_t flags,
								   size_t opt_size, const uint8_t *options) {
	msg_queue_t *queued = web_PushRawTCPSegment(data, length_data, ip_dst, port_src, port_dst, seq_number, ack_number,
											 	flags, opt_size, options);
	if(queued != NULL) {
		queued->send_once = true;  /* Send once */
	}
	return queued ? WEB_SUCCESS : WEB_NOT_ENOUGH_MEM;
}

web_status_t web_DeliverTCPSegment(tcp_exchange_t *tcp_exch, char *data, size_t length, uint16_t flags, size_t opt_size,
				  				   const uint8_t *options) {
	/* Default is FLAG_TCP_ACK */
	if(flags == FLAG_TCP_NONE) {
		flags = FLAG_TCP_ACK;
	}
	msg_queue_t *queued = web_PushRawTCPSegment(data, length, tcp_exch->ip_dst, tcp_exch->port_src, tcp_exch->port_dst,
												tcp_exch->cur_sn, tcp_exch->cur_ackn, flags, opt_size, options);
	if(queued == NULL) {
		return WEB_NOT_ENOUGH_MEM;
	}
	tcp_exch->cur_sn += length;
	if(flags & (FLAG_TCP_FIN | FLAG_TCP_SYN)) {
		/* The next ack number will be incremented */
		tcp_exch->cur_sn++;
	} else if(length == 0) {
		queued->send_once = true;  /* no data & flags != SF -> Send once (e.g RST or simple ACK segment) */
		return WEB_SUCCESS;
	}
	pushed_seg_list_t *new_seg = malloc(sizeof(pushed_seg_list_t));
	new_seg->next_rsn = (tcp_exch->cur_sn) - tcp_exch->beg_sn;
	new_seg->seg = queued;
	new_seg->next = tcp_exch->out_segments;
	tcp_exch->out_segments = new_seg;
	return WEB_SUCCESS;
}

tcp_exchange_t *web_TCPConnect(uint32_t ip_dst, web_port_t port_dst, web_port_callback_t *callback,
							   web_callback_data_t *user_data) {
	/* Core structure of a tcp exchange */
	tcp_exchange_list_t *tcp_exch_list = malloc(sizeof(tcp_exchange_list_t));
	tcp_exchange_t *tcp_exch = &tcp_exch_list->tcp_exch;
	memset(tcp_exch, 0, sizeof(tcp_exchange_t));
	tcp_exch->ip_dst = ip_dst;
	tcp_exch->port_src = web_RequestPort();
	tcp_exch->port_dst = port_dst;
	tcp_exch->cur_sn = random();
	tcp_exch->beg_sn = tcp_exch->cur_sn;
	tcp_exch->tcp_state = TCP_STATE_SYN_SENT;
	tcp_exch->callback = callback;
	tcp_exch->user_data = user_data;
	tcp_exch_list->next = tcp_exchanges;
	tcp_exchanges = tcp_exch_list;

    /* Initiating connection */
	web_ListenPort(tcp_exch->port_src, fetch_conntrack_tcp, tcp_exch);
	const uint8_t options[] = {0x02, 0x04, MAX_SEGMENT_SIZE / 256, MAX_SEGMENT_SIZE % 256};
	web_DeliverTCPSegment(tcp_exch, NULL, 0, FLAG_TCP_SYN, sizeof(options), options);

	/* Blocking until it receives an SYN/ACK */
	bool is_timeout = false;
	delay_event(TIMEOUT_NET * 1000, boolean_scheduler, boolean_destructor, &is_timeout);
	while(tcp_exch->tcp_state != TCP_STATE_ESTABLISHED) {
		web_WaitForEvents();
		if(is_timeout) {
			web_UnlistenPort(tcp_exch->port_src);
			if(tcp_exch->out_segments != NULL) {  /* Removing the SYN segment */
				free(tcp_exch->out_segments);
			}
			free(tcp_exch);
			return NULL;
		}
	}
	remove_event(&is_timeout);
	
	return tcp_exch;
}

void web_TCPClose(tcp_exchange_t *tcp_exch) {
	if(tcp_exch->tcp_state != TCP_STATE_ESTABLISHED && tcp_exch->tcp_state != TCP_STATE_CLOSE_WAIT) {
		return;
	}

	web_DeliverTCPSegment(tcp_exch, NULL, 0, FLAG_TCP_FIN | FLAG_TCP_ACK, 0, NULL);
	switch(tcp_exch->tcp_state) {
		case TCP_STATE_ESTABLISHED:
			tcp_exch->tcp_state = TCP_STATE_FIN_WAIT_1;
			break;
		case TCP_STATE_CLOSE_WAIT:
			tcp_exch->tcp_state = TCP_STATE_LAST_ACK;
			break;
		default:
			break;
	}

	/* Free the received segments to recover some space */
	tcp_segment_list_t *cur_seg = tcp_exch->in_segments;
	tcp_segment_list_t *next_seg = NULL;
	while(cur_seg) {
		next_seg = cur_seg->next;
		free(cur_seg->payload);
		free(cur_seg);
		cur_seg = next_seg;
	}
	tcp_exch->in_segments = NULL;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

void fetch_ack(tcp_exchange_t *tcp_exch, uint32_t ackn) {
	/**
	 *	Unofficial name: remove_tcp_segments_that_are_acked_by_ackn
	 *	Note: The segments in out_segments list are in descending order of sequence number.
	 */
	pushed_seg_list_t *cur_seg = tcp_exch->out_segments;
	pushed_seg_list_t *prev_seg = NULL;
	while(cur_seg && cur_seg->next_rsn > ackn - tcp_exch->beg_sn) {
		prev_seg = cur_seg;
		cur_seg = cur_seg->next;
	}

	if(!cur_seg) {
		return;
	}

	if(prev_seg) {
		prev_seg->next = NULL;
	} else {
		tcp_exch->out_segments = NULL;
	}

	pushed_seg_list_t *next_seg = NULL;
	while(cur_seg) {
		next_seg = cur_seg->next;
		web_PopMessage(cur_seg->seg);
		free(cur_seg);
		cur_seg = next_seg;
	}
}

msg_queue_t *_recursive_PushTCPSegment(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
									   web_port_t port_src, web_port_t port_dst, uint32_t seq_number,
									   uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options) {
	if(data - (sizeof(tcp_segment_t) + opt_size) < buffer) {
		dbg_err("Can't push TCP segment");
		free(buffer);
		return NULL;
	}

	size_t size_header = sizeof(tcp_segment_t) + opt_size;
	size_t size_all = length_data + size_header;
	tcp_segment_t *tcp_seg = (tcp_segment_t *)(data - size_header);
	tcp_seg->port_src = htons(port_src);
	tcp_seg->port_dst = htons(port_dst);
	tcp_seg->seq_number = htonl(seq_number);
	tcp_seg->ack_number = htonl(ack_number);
	tcp_seg->dataOffset_flags = htons(((size_header * 1024)) + flags);
	tcp_seg->windowSize = htons(TCP_WINDOW_SIZE);
	tcp_seg->checksum = 0x0000;
	tcp_seg->urgentPointer = 0x0000;

	if(options) {
		memcpy(tcp_seg + sizeof(tcp_segment_t), options, opt_size);
	}

	uint16_t chksm = transport_checksum(tcp_seg, size_all, netinfo.IP_addr, ip_dst, TCP_PROTOCOL);
	tcp_seg->checksum = chksm;

	return _recursive_PushIPv4Packet(buffer, tcp_seg, size_all, ip_dst, TCP_PROTOCOL);
}

web_status_t time_wait_scheduler(web_callback_data_t *user_data) {
	(void)user_data;  /* Unsed parameter */
	/*
		No Operation.
		Everything is done in the destructor, so the flush_event_list function frees all data structures too.
	*/
	return WEB_SUCCESS;
}

void time_wait_destructor(web_callback_data_t *user_data) {
	tcp_exchange_t *tcp_exch = (tcp_exchange_t *)user_data;
	dbg_info("Freeing connection %x", tcp_exch->port_src);

    /* Free the received segments */
	tcp_segment_list_t *cur_seg = tcp_exch->in_segments;
	tcp_segment_list_t *next_seg = NULL;
	while(cur_seg) {
		next_seg = cur_seg->next;
		free(cur_seg->payload);
		free(cur_seg);
		cur_seg = next_seg;
	}

	/* Free the sending segments */
	pushed_seg_list_t *cur_pushed = tcp_exch->out_segments;
	pushed_seg_list_t *next_pushed = NULL;
	while(cur_pushed) {
		next_pushed = cur_pushed->next;
		web_PopMessage(cur_pushed->seg);
		free(cur_pushed);
		cur_pushed = next_pushed;
	}

    /* Popping from the exchange list */
	tcp_exchange_list_t *cur_exch = tcp_exchanges;
	tcp_exchange_list_t *prev_exch = NULL;
	while(cur_exch) {
		if(&cur_exch->tcp_exch == tcp_exch) {
			if(prev_exch == NULL) {
				tcp_exchanges = cur_exch->next;
			} else {
				prev_exch->next = cur_exch->next;
			}
			free(cur_exch);
			break;
		}
		prev_exch = cur_exch;
		cur_exch = cur_exch->next;
	}

    web_UnlistenPort(tcp_exch->port_src);
    free(tcp_exch);
}

web_status_t add_in_segment(tcp_exchange_t *tcp_exch, tcp_segment_t *segment, size_t length) {
	/**
	 * Add the new segment to the in_segments list (if not already received).
	 * Return WEB_SUCCESS on success, an error otherwise.
	 */
	const void *payload = get_payload_addr(segment);
	const size_t payload_length = length - (payload - (void *)segment);
	if(payload_length == 0) {
		return WEB_SUCCESS;
	}
	void *response = malloc(payload_length);
	if(!response) {
		dbg_err("No memory");
		return WEB_NOT_ENOUGH_MEM;
	}
	memcpy(response, payload, payload_length);
	tcp_segment_list_t *new_segment_item = malloc(sizeof(tcp_segment_list_t));
	if(!new_segment_item) {
		dbg_err("No memory");
		return WEB_NOT_ENOUGH_MEM;
	}
	new_segment_item->relative_sn = htonl(segment->seq_number) - tcp_exch->beg_ackn;
	new_segment_item->pl_length = payload_length;
	new_segment_item->payload = response;

	/* Chaining the structure */
	tcp_segment_list_t *prev_el = NULL;
	tcp_segment_list_t *seg_after = tcp_exch->in_segments;
	while(seg_after && seg_after->relative_sn < new_segment_item->relative_sn) {
		prev_el = seg_after;
		seg_after = seg_after->next;
	}
	if(seg_after && seg_after->relative_sn == new_segment_item->relative_sn) {  /* deja vue */
		dbg_info("Segment received twice");
		free(new_segment_item->payload);
		free(new_segment_item);
		return WEB_SUCCESS;
	} else {
		new_segment_item->next = seg_after;
		if(prev_el) {
			prev_el->next = new_segment_item;
		} else {
			tcp_exch->in_segments = new_segment_item;
		}
	}

	tcp_segment_list_t *seg_to_ack = tcp_exch->in_segments;
	while(seg_to_ack->next && seg_to_ack->relative_sn + seg_to_ack->pl_length == seg_to_ack->next->relative_sn) {
		seg_to_ack = seg_to_ack->next;
	}
	tcp_exch->cur_ackn = tcp_exch->beg_ackn + seg_to_ack->relative_sn + seg_to_ack->pl_length;
	
	return WEB_SUCCESS;
}

web_status_t fetch_conntrack_tcp(web_port_t port, uint8_t protocol, void *data, size_t length,
								 web_callback_data_t *user_data) {
	if(protocol != TCP_PROTOCOL) {
		dbg_warn("Received a non-TCP packet on a TCP connection");
		return WEB_SUCCESS;
	}

	web_status_t ret_val = WEB_SUCCESS;
    tcp_exchange_t *tcp_exch = (tcp_exchange_t *)user_data;
	void *payload_addr = get_payload_addr(data);
	const size_t payload_size = length - (payload_addr - data);
	print_tcp_info(data, tcp_exch, length);  /* Only displayed when debug is enabled */

	if(tcp_exch->callback != NULL) {
		/* Creating and initializing the data list structure */
		ret_val = add_in_segment(tcp_exch, data, length);
		if(ret_val != WEB_SUCCESS) {
			web_TCPClose(tcp_exch);
			return ret_val;
		}
		fetch_tcp_flags(data, tcp_exch, payload_size != 0);  /* Sends an ACK if needed */

		/* Sending to the application the reordered list of payloads */
		tcp_segment_list_t *cur_seg = tcp_exch->in_segments;
		while(cur_seg != NULL && cur_seg->relative_sn < tcp_exch->cur_ackn - tcp_exch->beg_ackn) {
			ret_val = tcp_exch->callback(port, protocol, payload_addr, payload_size, tcp_exch->user_data);
			if(ret_val != WEB_SUCCESS) {
				break;
			}
			tcp_exch->in_segments = cur_seg->next;
			free(cur_seg->payload);
			free(cur_seg);
			cur_seg = tcp_exch->in_segments;
		}
	}

	return ret_val;
}

web_status_t fetch_raw_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	if(!transport_checksum((uint8_t*)seg, length, ip_src, ip_dst, TCP_PROTOCOL)) {
		return call_callbacks(TCP_PROTOCOL, seg, length, htons(seg->port_dst));
	} else {
		dbg_warn("Received bad checksumed TCP packet");
		return WEB_ERROR_FAILED;
	}
}

void fetch_tcp_flags(const tcp_segment_t *tcp_seg, tcp_exchange_t *tcp_exch, bool has_data) {
	/* If SYN/ACK */
	if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_SYN)) {
		tcp_exch->beg_ackn = htonl(tcp_seg->seq_number) + 1;
		tcp_exch->cur_ackn = tcp_exch->beg_ackn;
		tcp_exch->tcp_state = TCP_STATE_ESTABLISHED;
	}

	/* If RST */
	if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_RST)) {
		dbg_warn("RST received");
		tcp_exch->dirty = true;
		tcp_exch->tcp_state = TCP_STATE_CLOSED;
		return;
	}

	/* If ACK */
	if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_ACK)) {
		fetch_ack(tcp_exch, htonl(tcp_seg->ack_number));
		switch(tcp_exch->tcp_state) {
			case TCP_STATE_FIN_WAIT_1:
				dbg_verb("WAIT1 -> WAIT2");
				tcp_exch->tcp_state = TCP_STATE_FIN_WAIT_2;
				break;
			case TCP_STATE_CLOSING:
				dbg_verb("CLOSING -> TIME_WAIT");
				tcp_exch->tcp_state = TCP_STATE_TIME_WAIT;
				break;
			case TCP_STATE_LAST_ACK:
				/* The last ACK segment must be a segment with only the ACK flag set */
				if(tcp_seg->dataOffset_flags == htons(FLAG_TCP_ACK)) {
					dbg_verb("LAST_ACK -> CLOSED");
					tcp_exch->tcp_state = TCP_STATE_CLOSED;
					tcp_exch->dirty = true;
				}
				break;
			default:
				break;
		}
	}

	/* If FIN */
	if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_FIN)) {
		tcp_exch->cur_ackn++;
		switch(tcp_exch->tcp_state) {
			case TCP_STATE_FIN_WAIT_1:
			case TCP_STATE_CLOSING:  /* in case the previous ack did not reach its destination */
				tcp_exch->tcp_state = TCP_STATE_CLOSING;
				dbg_verb("WAIT1 -> CLOSING");
				break;
			case TCP_STATE_FIN_WAIT_2:
			case TCP_STATE_TIME_WAIT:
				tcp_exch->tcp_state = TCP_STATE_TIME_WAIT;
				// delay_event(TIMEOUT_TIME_WAIT * 1000, time_wait_scheduler, time_wait_destructor, tcp_exch);
				dbg_verb("WAIT2 -> TIME_WAIT");
				break;
			case TCP_STATE_ESTABLISHED:
				dbg_verb("EST -> LAST_ACK");
			case TCP_STATE_CLOSE_WAIT:
				tcp_exch->tcp_state = TCP_STATE_CLOSE_WAIT;
				break;
			default:
				dbg_verb("Unexpected FIN in %u state", tcp_exch->tcp_state);
				break;
		}
	}

	/* If the ACK flag is not the only one to be set or there is data to acknowledge, send an ack segment */
	if((has_data || tcp_seg->dataOffset_flags & htons(FLAG_TCP_MASK)) != htons(FLAG_TCP_ACK)) {
		web_DeliverTCPSegment(tcp_exch, NULL, 0, FLAG_TCP_ACK, 0, NULL);
	}
}
