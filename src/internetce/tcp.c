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
#include "include/crypto.h"


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

web_status_t web_DeliverTCPSegment(tcp_exchange_t *tcp_exch, void *data, size_t length, uint16_t flags) {
	/* Handling error cases */
	if(tcp_exch->tcp_state == TCP_STATE_CLOSED) {
		return WEB_ERROR_FAILED;
	} else if(length != 0 && flags & FLAG_TCP_SYN) {
		dbg_err("SYN segment with data");
		return WEB_ERROR_FAILED;
	}

	/* Default is FLAG_TCP_ACK */
	if(flags == FLAG_TCP_NONE) {
		flags = FLAG_TCP_ACK;
	}

	/* Handling SYN case (we need to send our MSS) */
	const uint8_t syn_default_options[] = {TCP_OPTION_MSS, 0x04, MAX_SEGMENT_SIZE / 256, MAX_SEGMENT_SIZE % 256};
	uint8_t *options = NULL;
	size_t opt_size = 0;
	if(flags & FLAG_TCP_SYN) {
		options = (uint8_t *)syn_default_options;
		opt_size = sizeof(syn_default_options);
	}

	/* Splitting data into TCP segments (with a payload size lower than the send MSS) */
	size_t sent = 0;
	do {
		/* Only setting the specified flags for the last sent segment (FIN or PSH for example) */
		const size_t to_send = min(length - sent, tcp_exch->send_mss);
		const uint16_t cur_flags = (sent + to_send == length) ? flags : FLAG_TCP_ACK;
		msg_queue_t *queued = web_PushRawTCPSegment(data + sent, to_send, tcp_exch->ip_dst, tcp_exch->port_src, tcp_exch->port_dst,
													tcp_exch->cur_sn, tcp_exch->cur_ackn, cur_flags, opt_size, options);
		if(queued == NULL) {
			return WEB_NOT_ENOUGH_MEM;
		}
		pushed_seg_list_t *new_seg = _malloc(sizeof(pushed_seg_list_t));
		if(new_seg == NULL) {
			web_PopMessage(queued);
			return WEB_NOT_ENOUGH_MEM;
		}
		// print_tcp_info((tcp_segment_t *)(queued->msg + IPV4_HEADERS_SIZE - 4), tcp_exch, to_send + sizeof(tcp_segment_t) + opt_size, true);

		if(cur_flags & (FLAG_TCP_FIN | FLAG_TCP_SYN)) {
			/* The next ack number will be incremented */
			tcp_exch->cur_sn++;
		} else if(to_send == 0) {
			queued->send_once = true;  /* no data & flags != SF -> Send once (e.g RST or simple ACK segment) */
		}
		tcp_exch->cur_sn += to_send;
		new_seg->next_rsn = (tcp_exch->cur_sn) - tcp_exch->beg_sn;
		new_seg->flags = cur_flags;
		new_seg->seg = queued;
		new_seg->next = tcp_exch->out_segments;
		tcp_exch->out_segments = new_seg;

		sent += to_send;
	} while(sent < length);

	return WEB_SUCCESS;
}

tcp_exchange_t *web_TCPConnect(uint32_t ip_dst, web_port_t port_dst, web_appli_callback_t *callback,
							   web_callback_data_t *user_data) {
	if(!rng_IsAvailable()) {
		dbg_err("Random module not ready yet");
		return NULL;
	}

	/* Core structure of a tcp exchange */
	tcp_exchange_list_t *tcp_exch_list = _malloc(sizeof(tcp_exchange_list_t));
	if(tcp_exch_list == NULL) {
		return NULL;
	}
	tcp_exchange_t *tcp_exch = &tcp_exch_list->tcp_exch;
	memset(tcp_exch, 0, sizeof(tcp_exchange_t));
	tcp_exch->ip_dst = ip_dst;
	tcp_exch->port_src = web_RequestPort();
	tcp_exch->port_dst = port_dst;
	rng_Random32b(&tcp_exch->cur_sn);  // Should not fail (if(!rng_IsAvailable())... above)
	tcp_exch->beg_sn = tcp_exch->cur_sn;
	tcp_exch->tcp_state = TCP_STATE_SYN_SENT;
	tcp_exch->callback = callback;
	tcp_exch->user_data = user_data;
	tcp_exch->send_mss = DEFAULT_MSS;
	tcp_exch_list->next = tcp_exchanges;
	tcp_exchanges = tcp_exch_list;

    /* Initiating connection */
	web_status_t ret_val = web_ListenPort(tcp_exch->port_src, fetch_conntrack_tcp, tcp_exch);
	if(ret_val != WEB_SUCCESS) {
		_free(tcp_exch_list);
		return NULL;
	}
	ret_val = web_DeliverTCPSegment(tcp_exch, NULL, 0, FLAG_TCP_SYN);
	if(ret_val != WEB_SUCCESS) {
		web_UnlistenPort(tcp_exch->port_src);
		_free(tcp_exch_list);
		return NULL;
	}

	/* Blocking until it receives an SYN/ACK */
	bool is_timeout = false;
	ret_val = delay_event(TIMEOUT_NET * 1000, boolean_scheduler, boolean_destructor, &is_timeout);
	if(ret_val != WEB_SUCCESS) {
		web_UnlistenPort(tcp_exch->port_src);
		_free(tcp_exch_list);
		return NULL;
	}
	while(tcp_exch->tcp_state != TCP_STATE_ESTABLISHED) {
		web_WaitForEvents();
		if(is_timeout || tcp_exch->tcp_state == TCP_STATE_CLOSED) {
			time_wait_destructor(tcp_exch);
			return NULL;
		}
	}
	remove_event(&is_timeout);
	
	return tcp_exch;
}

web_status_t web_TCPClose(tcp_exchange_t *tcp_exch, bool is_abort) {
	web_status_t ret_val = WEB_SUCCESS;
	if(tcp_exch->tcp_state == TCP_STATE_CLOSED) {
		/* Already received an RST from the server, _freeing memory */
		time_wait_destructor(tcp_exch);
	} else if(tcp_exch->tcp_state < TCP_STATE_ESTABLISHED) {
		/* Closing in a non-initialzed state */
		ret_val = web_SendRawTCPSegment(NULL, 0, tcp_exch->ip_dst, tcp_exch->port_src, tcp_exch->port_dst, tcp_exch->cur_sn,
							  			0, FLAG_TCP_RST, 0, NULL);
		if(ret_val != WEB_SUCCESS) {
			time_wait_destructor(tcp_exch);
			return ret_val;
		} else {
			tcp_exch->tcp_state = TCP_STATE_TIME_WAIT;
			ret_val = delay_event(TIMEOUT_TIME_WAIT * 1000, time_wait_scheduler, time_wait_destructor, tcp_exch);
			if(ret_val != WEB_SUCCESS) {
				time_wait_destructor(tcp_exch);
				return ret_val;
			}
		}
	} else if(is_abort) {
		/* The user asked to abort the connection (something went wrong on its side) */
		flush_sending_queue(tcp_exch);
		ret_val = web_DeliverTCPSegment(tcp_exch, NULL, 0, FLAG_TCP_RST | FLAG_TCP_ACK);
		if(ret_val != WEB_SUCCESS) {
			time_wait_destructor(tcp_exch);
			return ret_val;
		} else {
			tcp_exch->tcp_state = TCP_STATE_TIME_WAIT;
			ret_val = delay_event(TIMEOUT_TIME_WAIT * 1000, time_wait_scheduler, time_wait_destructor, tcp_exch);
			if(ret_val != WEB_SUCCESS) {
				time_wait_destructor(tcp_exch);
				return ret_val;
			}
		}
	} else if(tcp_exch->tcp_state == TCP_STATE_ESTABLISHED || tcp_exch->tcp_state == TCP_STATE_CLOSE_WAIT) {
		/* Normal closing */
		ret_val = web_DeliverTCPSegment(tcp_exch, NULL, 0, FLAG_TCP_FIN | FLAG_TCP_ACK);
		if(ret_val != WEB_SUCCESS) {
			time_wait_destructor(tcp_exch);
			return ret_val;
		}
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
	}
	tcp_exch->callback = NULL;
	return ret_val;
}


/**********************************************************************************************************************\
 *                                                  Private functions                                                 *
\**********************************************************************************************************************/

void fallback_no_memory(tcp_exchange_t *tcp_exch) {
	/* Fallback in case of lack of memory, so not using any malloc in there (no sending of segment etc) */
	tcp_exch->tcp_state = TCP_STATE_CLOSED;
	if(tcp_exch->callback != NULL) {
		tcp_exch->callback(tcp_exch->port_src, LINK_MSG_TYPE_RST, NULL, 0, tcp_exch->user_data);
	}
}

web_status_t fetch_ack(tcp_exchange_t *tcp_exch, uint32_t ackn) {
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
		return WEB_SUCCESS;
	}

	if(prev_seg) {
		prev_seg->next = NULL;
	} else {
		tcp_exch->out_segments = NULL;
	}

	pushed_seg_list_t *next_seg = NULL;
	bool is_dirty = false;
	while(cur_seg) {
		next_seg = cur_seg->next;
		if(cur_seg->flags & FLAG_TCP_FIN) {
			/* The server has acknowledged our FIN */
			switch(tcp_exch->tcp_state) {
				case TCP_STATE_FIN_WAIT_1:
					tcp_exch->tcp_state = TCP_STATE_FIN_WAIT_2;
					break;
				case TCP_STATE_LAST_ACK:
					tcp_exch->tcp_state = TCP_STATE_CLOSED;
					is_dirty = true;  /* The connection must be _freed */
					break;
				case TCP_STATE_CLOSING:
					tcp_exch->tcp_state = TCP_STATE_TIME_WAIT;
					web_status_t ret_val = delay_event(TIMEOUT_TIME_WAIT * 1000, time_wait_scheduler,
													   time_wait_destructor, tcp_exch);
					if(ret_val != WEB_SUCCESS) {
						/* OK because user has already closed the connection */
						is_dirty = true;
					}
					break;
				default:
					break;
			}
		}
		web_PopMessage(cur_seg->seg);
		_free(cur_seg);
		cur_seg = next_seg;
	}

	if(is_dirty) {
		time_wait_destructor(tcp_exch);
		return WEB_CONNECTION_TERMINATION_ERROR;
	}

	return WEB_SUCCESS;
}

msg_queue_t *_recursive_PushTCPSegment(void *buffer, void *data, size_t length_data, uint32_t ip_dst,
									   web_port_t port_src, web_port_t port_dst, uint32_t seq_number,
									   uint32_t ack_number, uint16_t flags, size_t opt_size, const uint8_t *options) {
	if(data - (sizeof(tcp_segment_t) + opt_size) < buffer) {
		dbg_err("Can't push TCP segment");
		_free(buffer);
		return NULL;
	}

	size_t size_header = sizeof(tcp_segment_t) + opt_size;
	size_t size_all = length_data + size_header;
	tcp_segment_t *tcp_seg = (tcp_segment_t *)(data - size_header);
	tcp_seg->port_src = htons(port_src);
	tcp_seg->port_dst = htons(port_dst);
	tcp_seg->seq_number = htonl(seq_number);
	tcp_seg->ack_number = htonl(ack_number);
	tcp_seg->dataOffset_flags = htons((size_header * 1024) + flags);
	tcp_seg->windowSize = htons(TCP_WINDOW_SIZE);
	tcp_seg->checksum = 0x0000;
	tcp_seg->urgentPointer = 0x0000;

	if(opt_size != 0) {
		memcpy((uint8_t *)tcp_seg + sizeof(tcp_segment_t), options, opt_size);
	}

	uint16_t chksm = transport_checksum(tcp_seg, size_all, netinfo.IP_addr, ip_dst, TCP_PROTOCOL);
	tcp_seg->checksum = chksm;

	return _recursive_PushIPv4Packet(buffer, tcp_seg, size_all, ip_dst, TCP_PROTOCOL);
}

void flush_tcp_connections() {
	while(tcp_exchanges != NULL) {
		time_wait_destructor(&tcp_exchanges->tcp_exch);
	}
}

void flush_sending_queue(tcp_exchange_t *tcp_exch) {
	pushed_seg_list_t *cur_pushed = tcp_exch->out_segments;
	pushed_seg_list_t *next_pushed = NULL;
	while(cur_pushed) {
		next_pushed = cur_pushed->next;
		web_PopMessage(cur_pushed->seg);
		_free(cur_pushed);
		cur_pushed = next_pushed;
	}
	tcp_exch->out_segments = NULL;
}

void flush_receiving_queue(tcp_exchange_t *tcp_exch) {
	/* Free the received segments */
	tcp_segment_list_t *cur_seg = tcp_exch->in_segments;
	tcp_segment_list_t *next_seg = NULL;
	while(cur_seg) {
		next_seg = cur_seg->next;
		if(cur_seg->payload != NULL) {
			_free(cur_seg->payload);
		}
		_free(cur_seg);
		cur_seg = next_seg;
	}
	tcp_exch->in_segments = NULL;
}

web_status_t time_wait_scheduler(web_callback_data_t *user_data) {
	(void)user_data;  /* Unsed parameter */
	/*
		No Operation.
		Everything is done in the destructor, so the flush_event_list function _frees all data structures too.
	*/
	return WEB_SUCCESS;
}

void time_wait_destructor(web_callback_data_t *user_data) {
	tcp_exchange_t *tcp_exch = (tcp_exchange_t *)user_data;
	dbg_info("Freeing port %x", tcp_exch->port_src);

    flush_receiving_queue(tcp_exch);

	flush_sending_queue(tcp_exch);

	web_UnlistenPort(tcp_exch->port_src);

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
			_free(cur_exch);
			break;
		}
		prev_exch = cur_exch;
		cur_exch = cur_exch->next;
	}
	/* tcp_exch has been _freed, do not put any clearing code here */
}

web_status_t add_in_segment(tcp_exchange_t *tcp_exch, tcp_segment_t *segment, size_t length) {
	/**
	 * Add the new segment to the in_segments list (if not already received).
	 * Return WEB_SUCCESS on success, an error otherwise.
	 */
	const void *payload = get_payload_addr(segment);
	const size_t payload_length = length - (payload - (void *)segment);
	if(payload_length == 0 && !(segment->dataOffset_flags & htons(FLAG_TCP_FIN | FLAG_TCP_SYN | FLAG_TCP_RST))) {
		return WEB_SUCCESS;
	}

	if(segment->dataOffset_flags & htons(FLAG_TCP_SYN)) {
		tcp_exch->beg_ackn = htonl(segment->seq_number);

		/* Trying to find relevant options (such as MSS) */
		uint8_t *options_start = (uint8_t *)segment + sizeof(tcp_segment_t);
		const size_t opt_size = (uint8_t *)get_payload_addr(segment) - options_start;
		uint8_t *options_ptr = options_start;
		while((size_t)(options_ptr - options_start) < opt_size && *options_ptr != 0x00) {
			if(*options_ptr == TCP_OPTION_MSS && *(options_ptr + 1) == 0x04) {
				tcp_exch->send_mss = htons(*(uint16_t *)(options_ptr + 2));
				dbg_info("Send MSS: %u", tcp_exch->send_mss);
			} else if(*options_ptr > 0x01) {
				dbg_info("Unsupported option: 0x%x", *options_ptr);
			}
			if(*options_ptr == 0x01) { /* No-op */
				options_ptr++;
			} else {
				options_ptr += *(options_ptr + 1);
			}
		}
	}

	void *response = NULL;
	if(payload_length != 0) {
		response = _malloc(payload_length);
		if(!response) {
			dbg_err("No memory");
			return WEB_NOT_ENOUGH_MEM;
		}
		memcpy(response, payload, payload_length);
	}
	tcp_segment_list_t *new_segment_item = _malloc(sizeof(tcp_segment_list_t));
	if(!new_segment_item) {
		dbg_err("No memory");
		return WEB_NOT_ENOUGH_MEM;
	}
	new_segment_item->relative_sn = htonl(segment->seq_number) - tcp_exch->beg_ackn;
	new_segment_item->pl_length = payload_length;
	new_segment_item->flags = segment->dataOffset_flags;
	new_segment_item->payload = response;

	if(tcp_exch->tcp_state >= TCP_STATE_ESTABLISHED && new_segment_item->relative_sn < tcp_exch->cur_ackn - tcp_exch->beg_ackn) {
		dbg_info("Segment received twice");
		if(new_segment_item->payload != NULL) {
			_free(new_segment_item->payload);
		}
		_free(new_segment_item);
		return WEB_SUCCESS;
	}

	/* Chaining the structure */
	tcp_segment_list_t *prev_el = NULL;
	tcp_segment_list_t *seg_after = tcp_exch->in_segments;
	while(seg_after && seg_after->relative_sn < new_segment_item->relative_sn) {
		prev_el = seg_after;
		seg_after = seg_after->next;
	}
	if(seg_after && seg_after->relative_sn == new_segment_item->relative_sn) {  /* deja vue */
		dbg_info("Segment received twice");
		if(new_segment_item->payload != NULL) {
			_free(new_segment_item->payload);
		}
		_free(new_segment_item);
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
	while(seg_to_ack->next && seg_to_ack->relative_sn + get_segment_sn_length(seg_to_ack->pl_length, seg_to_ack->flags) == \
		  seg_to_ack->next->relative_sn) {
		seg_to_ack = seg_to_ack->next;
	}
	tcp_exch->cur_ackn = tcp_exch->beg_ackn + seg_to_ack->relative_sn + get_segment_sn_length(
		seg_to_ack->pl_length,
		seg_to_ack->flags);

	return WEB_SUCCESS;
}

web_status_t send_rst_segment(uint32_t ip_dst, tcp_segment_t *received, size_t length) {
	web_status_t ret_val = WEB_SUCCESS;
	if(!(received->dataOffset_flags & htons(FLAG_TCP_RST))) {
		uint32_t ack_number = htonl(received->seq_number) + get_segment_sn_length(
			length - (get_payload_addr(received) - (char *)received),
			received->dataOffset_flags);
		uint32_t sequence_number = 0;
		unsigned int flags = FLAG_TCP_RST;
		if(received->dataOffset_flags & htons(FLAG_TCP_ACK)) {
			sequence_number = htonl(received->ack_number);
			flags |= FLAG_TCP_ACK;
		}
		ret_val = web_SendRawTCPSegment(NULL, 0, ip_dst, htons(received->port_dst), htons(received->port_src),
										sequence_number, ack_number, flags, 0, NULL);
	}
	return ret_val;
}

web_status_t fetch_conntrack_tcp(web_port_t port, uint8_t protocol, void *data, size_t length,
								 web_callback_data_t *user_data) {
	if(protocol != TCP_PROTOCOL) {
		dbg_warn("Received a non-TCP packet on a TCP connection");
		return WEB_SUCCESS;
	}

    tcp_exchange_t *tcp_exch = (tcp_exchange_t *)user_data;
	// print_tcp_info(data, tcp_exch, length, false);  /* Only displayed when debug is enabled */

	tcp_segment_t *tcp_seg = (tcp_segment_t *)data;
	void *payload_addr = get_payload_addr(data);
	const size_t payload_size = length - (payload_addr - data);

	/* Handling error cases */
	const uint32_t seq_number = htonl(tcp_seg->seq_number);
	const uint32_t ack_number = htonl(tcp_seg->ack_number);
	if(tcp_exch->tcp_state == TCP_STATE_CLOSED) {
		/* Only case: the layer received an RST segment and the user has not called close() yet */
		send_rst_segment(tcp_exch->ip_dst, (tcp_segment_t *)data, length);
		return WEB_ERROR_FAILED;
	} else if(tcp_exch->tcp_state >= TCP_STATE_ESTABLISHED) {
		bool is_valid = true;
		if(tcp_seg->dataOffset_flags & htons(FLAG_TCP_ACK) &&
		   ack_number - tcp_exch->beg_sn > tcp_exch->cur_sn - tcp_exch->beg_sn) {
			dbg_warn("Invalid ACK");
			is_valid = false;
		} else if((seq_number - tcp_exch->beg_ackn) + payload_size > (tcp_exch->cur_ackn - tcp_exch->beg_ackn) + TCP_WINDOW_SIZE) {
			dbg_warn("Out-of-window segment");
			is_valid = false;
		}
		if(!is_valid) {
			web_DeliverTCPSegment(tcp_exch, NULL, 0, FLAG_TCP_ACK);
			return WEB_ERROR_FAILED;
		}
	} else {  /* If the connection is in a non-synchronized state (during the 3-way handshake) */
		if(ack_number - tcp_exch->beg_sn > tcp_exch->cur_sn - tcp_exch->beg_sn) {
			dbg_warn("Invalid ACK (no-syn)");
			send_rst_segment(tcp_exch->ip_dst, (tcp_segment_t *)data, length);
			tcp_exch->tcp_state = TCP_STATE_CLOSED;
			return WEB_ERROR_FAILED;
		}
	}

	/* Creating and initializing the data list structure */
	web_status_t ret_val = add_in_segment(tcp_exch, data, length);
	if(ret_val != WEB_SUCCESS) {
		fallback_no_memory(tcp_exch);
		return ret_val;
	}

	ret_val = fetch_ack(tcp_exch, htonl(tcp_seg->ack_number));
	if(ret_val == WEB_CONNECTION_TERMINATION_ERROR) {
		return WEB_SUCCESS;
	}

	/* Sending to the application the reordered list of payloads */
	tcp_segment_list_t *cur_seg = tcp_exch->in_segments;
	bool is_sent_to_appli = false;
	while(cur_seg != NULL && cur_seg->relative_sn < tcp_exch->cur_ackn - tcp_exch->beg_ackn) {
		is_sent_to_appli = true;
		if(payload_size != 0 && tcp_exch->callback != NULL) {
			ret_val = tcp_exch->callback(port, LINK_MSG_TYPE_DATA, payload_addr, payload_size, tcp_exch->user_data);
			if(ret_val != WEB_SUCCESS) {
				return ret_val;
			}
		}

		/* Handle TCP flags (might call the appli callback) */
		ret_val = fetch_tcp_flags(cur_seg, tcp_exch);

		tcp_exch->in_segments = cur_seg->next;
		if(cur_seg->payload) {
			_free(cur_seg->payload);
		}
		_free(cur_seg);
		cur_seg = tcp_exch->in_segments;

		if(ret_val != WEB_SUCCESS) {
			break;
		}
	}

	/* Send an ACK if any data has been submitted to the appli layer */
	if(is_sent_to_appli && ret_val == WEB_SUCCESS) {
		ret_val = web_DeliverTCPSegment(tcp_exch, NULL, 0, FLAG_TCP_ACK);
		if(ret_val != WEB_SUCCESS) {
			fallback_no_memory(tcp_exch);
			return ret_val;
		}
	}

	return ret_val;
}

web_status_t fetch_raw_tcp_segment(tcp_segment_t *seg, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	if(!transport_checksum((uint8_t*)seg, length, ip_src, ip_dst, TCP_PROTOCOL)) {
		const int nb_matches = call_callbacks(TCP_PROTOCOL, seg, length, htons(seg->port_dst));
		if(nb_matches <= 0) {
			dbg_warn("No TCP callback for port %u", htons(seg->port_dst));
			send_rst_segment(ip_src, seg, length);
		}
		return WEB_SUCCESS;
	} else {
		dbg_warn("Bad checksumed TCP packet");
		return WEB_ERROR_FAILED;
	}
}

web_status_t fetch_tcp_flags(const tcp_segment_list_t *tcp_seg, tcp_exchange_t *tcp_exch) {
	/* If SYN/ACK */
	if(tcp_seg->flags & htons(FLAG_TCP_SYN)) {
		tcp_exch->tcp_state = TCP_STATE_ESTABLISHED;
	}

	/* If RST */
	if(tcp_seg->flags & htons(FLAG_TCP_RST)) {
		dbg_warn("RST received");
		if(tcp_exch->callback != NULL) {
			tcp_exch->callback(tcp_exch->port_src, LINK_MSG_TYPE_RST, NULL, 0, tcp_exch->user_data);
		}
		tcp_exch->tcp_state = TCP_STATE_CLOSED;
		flush_sending_queue(tcp_exch);
		return WEB_CONNECTION_TERMINATION_ERROR;
	}

	/* If FIN */
	if(tcp_seg->flags & htons(FLAG_TCP_FIN)) {
		switch(tcp_exch->tcp_state) {
			case TCP_STATE_FIN_WAIT_1:
				tcp_exch->tcp_state = TCP_STATE_CLOSING;
				dbg_verb("WAIT1 -> CLOSING");
			case TCP_STATE_CLOSING:  /* in case the previous ack did not reach its destination */
				break;
			case TCP_STATE_FIN_WAIT_2:
				tcp_exch->tcp_state = TCP_STATE_TIME_WAIT;
				/* OK because user has already asked for termination */
				web_status_t ret_val = delay_event(TIMEOUT_TIME_WAIT * 1000, time_wait_scheduler, time_wait_destructor, tcp_exch);
				if(ret_val != WEB_SUCCESS) {
					time_wait_destructor(tcp_exch);
					return ret_val;
				}
				dbg_verb("WAIT2 -> TIME_WAIT");
			case TCP_STATE_TIME_WAIT:
				break;
			case TCP_STATE_ESTABLISHED:
				dbg_verb("EST -> CLOSE_WAIT");
				if(tcp_exch->callback != NULL) {
					tcp_exch->callback(tcp_exch->port_src, LINK_MSG_TYPE_FIN, NULL, 0, tcp_exch->user_data);
				}
				tcp_exch->tcp_state = TCP_STATE_CLOSE_WAIT;
			case TCP_STATE_CLOSE_WAIT:
				break;
			default:
				dbg_verb("Unexpected FIN in %u state", tcp_exch->tcp_state);
				break;
		}
	}

	return WEB_SUCCESS;
}
