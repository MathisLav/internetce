/**
 * RNDIS related functions
 */

#ifndef INTERNET_RNDIS
#define INTERNET_RNDIS


#include <internet.h>
#include <stdint.h>


/**
 * Constants
 */

#define RNDIS_CONTROL_BUFFER			64  /* 64 should be enough */

#define MAX_RNDIS_TRANSFER_SIZE 		MAX_SEGMENT_SIZE + TCP_HEADERS_SIZE  // 1562B

#define SEND_KEEPALIVE_INTERVAL			5 * 1000  /* Send Keepalive every 5 seconds according to RNDIS requirements */

/* RNDIS version */
#define RNDIS_MAJOR_VERSION				0x01
#define RNDIS_MINOR_VERSION				0x00

/* Device flag */
#define RNDIS_DF_CONNECTIONLESS			0x01
#define RNDIS_DF_CONNECTION_ORIENTED	0x02

/* Medium */
#define RNDIS_MEDIUM_802_3				0x00000000

/* General OIDs */
#define OID_GEN_SUPPORTED_LIST			0x00010101
#define OID_GEN_HARDWARE_STATUS			0x00010102
#define OID_GEN_MEDIA_SUPPORTED			0x00010103
#define OID_GEN_MEDIA_IN_USE			0x00010104
#define OID_GEN_MAXIMUM_LOOKAHEAD		0x00010105
#define OID_GEN_MAXIMUM_FRAME_SIZE		0x00010106
#define OID_GEN_LINK_SPEED				0x00010107
#define OID_GEN_TRANSMIT_BUFFER_SPACE	0x00010108
#define OID_GEN_RECEIVE_BUFFER_SPACE	0x00010109
#define OID_GEN_TRANSMIT_BLOCK_SIZE		0x0001010A
#define OID_GEN_RECEIVE_BLOCK_SIZE		0x0001010B
#define OID_GEN_VENDOR_ID				0x0001010C
#define OID_GEN_VENDOR_DESCRIPTION		0x0001010D
#define OID_GEN_CURRENT_PACKET_FILTER	0x0001010E
#define OID_GEN_CURRENT_LOOKAHEAD		0x0001010F
#define OID_GEN_DRIVER_VERSION			0x00010110
#define OID_GEN_MAXIMUM_TOTAL_SIZE		0x00010111
#define OID_GEN_PROTOCOL_OPTIONS		0x00010112
#define OID_GEN_MAC_OPTIONS				0x00010113
#define OID_GEN_MEDIA_CONNECT_STATUS	0x00010114
#define OID_GEN_MAXIMUM_SEND_PACKETS	0x00010115
#define OID_GEN_VENDOR_DRIVER_VERSION	0x00010116
#define OID_GEN_SUPPORTED_GUIDS			0x00010117
#define OID_GEN_NETWORK_LAYER_ADDRESSES	0x00010118
#define OID_GEN_TRANSPORT_HEADER_OFFSET	0x00010119
#define OID_GEN_MACHINE_NAME			0x0001021A
#define OID_GEN_RNDIS_CONFIG_PARAMETER	0x0001021B
#define OID_GEN_VLAN_ID					0x0001021C

/* Values of RNDIS_OID_GEN_CURRENT_PACKET_FILTER */
#define RNDIS_PACKET_TYPE_DIRECTED		0x00000001
#define RNDIS_PACKET_TYPE_MULTICAST		0x00000002
#define RNDIS_PACKET_TYPE_ALL_MULTICAST	0x00000004
#define RNDIS_PACKET_TYPE_BROADCAST		0x00000008
#define RNDIS_PACKET_TYPE_SOURCE_ROUTING    0x00000010
#define RNDIS_PACKET_TYPE_PROMISCUOUS	0x00000020
#define RNDIS_PACKET_TYPE_SMT			0x00000040
#define RNDIS_PACKET_TYPE_ALL_LOCAL		0x00000080
#define RNDIS_PACKET_TYPE_GROUP			0x00001000
#define RNDIS_PACKET_TYPE_ALL_FUNCTIONAL    0x00002000
#define RNDIS_PACKET_TYPE_FUNCTIONAL	0x00004000
#define RNDIS_PACKET_TYPE_MAC_FRAME		0x00008000


/**
 * Type definitions
 */

/* struct rndis_state: Describe the current RNDIS state machine */
typedef struct rndis_state {
	unsigned int cur_request_id;        /* Current request ID */
	bool has_keepalive_cmplt_received;  /* Check that the previous keepalive message got a response */
    uint8_t interrupt_buffer[8];        /* Where to store the response in the interrupt endpoint */
	usb_control_setup_t ctrl_setup_buffer;
	size_t max_transfer_size;			/* Max RNDIS message size. The minimum value bewteen host & device's is chosen */
} rndis_state_t;


/**
 * Internal functions prototype
 */

msg_queue_t *_recursive_PushRNDISPacket(void *buffer, void *data, size_t length_data);

void send_control_rndis(void *rndis_msg, size_t length);

usb_error_t out_control_rndis_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
							  		   usb_transfer_data_t *data);

void init_rndis_exchange();

void send_rndis_set_msg(uint32_t oid, const void *value, size_t value_size);

void send_rndis_keepalive_msg();

void send_rndis_keepalive_cmplt(uint32_t request_id);

void send_rndis_reset_msg();

usb_error_t interrupt_handler(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
							  usb_transfer_data_t *data);

usb_error_t ctrl_rndis_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred,
								usb_transfer_data_t *data);

void poll_interrupt_scheduler();

web_status_t send_keepalive_scheduler(web_callback_data_t *user_data);


#endif // INTERNET_RNDIS
