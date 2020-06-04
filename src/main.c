/**
 *--------------------------------------
 * Lib Name: INTERNET
 * Author: Mathis Lavigne aka Epharius
 * License: 
 * Description: This librairy aim at allowing any program to access the internet.
 *--------------------------------------
 */

#include <tice.h>
#include <keypadc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <usbdrvce.h>


#define DEVICE			0x00
#define RNDIS_SUBCLASS	0x01
#define RNDIS_PROTOCOL	0x03

#define RNDIS_PACKET_MSG 	0x00000001
#define RNDIS_INIT_MSG		0x00000002
#define RNDIS_INIT_CMPLT	0x80000002
#define RNDIS_SET_MSG		0x00000005
typedef struct rndis_init_msg {
	uint32_t MessageType;		/**< RNDIS_INIT_MSG  */
	uint32_t MessageLength;		/**< 24  			*/
	uint32_t RequestId;
	uint32_t MajorVersion;
	uint32_t MinorVersion;
	uint32_t MaxTransferSize;
} rndis_init_msg_t;
typedef struct rndis_set_msg {
	uint32_t MessageType;		/**< RNDIS_INIT_MSG  */
	uint32_t MessageLength;		/**< 32  			*/
	uint32_t RequestId;
	uint32_t Oid;
	uint32_t InformationBufferLength;
	uint32_t InformationBufferOffset;
	uint32_t DeviceVcHandle;	/**< 0 				*/
	uint32_t OidValue;			/**< Oid value sent along with the message */
} rndis_set_msg_t;
typedef struct rndis_packet_msg {
	uint32_t MessageType;		/**< RNDIS_PACKET_MSG */
	uint32_t MessageLength;
	uint32_t DataOffset;
	uint32_t DataLength;
	uint32_t OOBDataOffset;
	uint32_t OOBDataLength;
	uint32_t NumOOBDataElements;
	uint32_t PerPacketInfoOffset;
	uint32_t PerPacketInfoLength;
	uint32_t VcHandle;		/**< Must be 0 */
	uint32_t Reserved;		/**< Must be 0 */
	/* Your data must be here /void data;/ */
} rndis_packet_msg_t;
typedef struct rndis_device {
	usb_device_t device;
	uint8_t router_MAC_addr[6];
	uint32_t DHCP_IP_addr;
	uint32_t DNS_IP_addr;
	bool connected;
	bool enabled;
	uint8_t int_cdc;
	uint8_t int_wc;
	uint8_t ep_cdc;
	uint8_t ep_wc;
} rndis_device_t;

typedef struct eth_frame {
	uint8_t MAC_dst[6];
	uint8_t MAC_src[6];		/**< MAC_ADDR		*/
	uint16_t Ethertype;		/**< 0x0800 : IPv4	*/
	/* Your data must be here /void data;/ */
	uint32_t crc;
} eth_frame_t;
typedef struct ipv4_packet { // MSB First
	uint8_t VerIHL;			/**< 0x45			*/
	uint8_t ToS;			/**< often 0		*/
	uint16_t TotalLength;	/**< less than 65K but MTU is often 576B (minimal required value) */
	uint16_t Id;			/**< Identification of a fragment */
	uint16_t FlagsFragmentOffset; /**< The first 3 bits are flags. The following bits are Fragment Offset */
	uint8_t TTL;			/**< Time To Live	*/
	uint8_t Protocol;		/**< TCP=0x06; UDP=0x11; ICMP=0x01 */
	uint16_t HeaderChecksum;/**< Checksum of this header */
	uint32_t IP_addr_src;
	uint32_t IP_addr_dst;
	/* Your data must be here /void data;/ */
} ipv4_packet_t;
typedef struct ipv6_packet {
	uint32_t VerTCFL;		/**< Version 4b (=6), Trafic class 8b, Flow Label 20b */
	uint16_t PayloadLength;
	uint8_t NextHeader;
	uint8_t HopLimit;
	uint8_t IP_addr_src[16];
	uint8_t IP_addr_dst[16];
	/* Your data must be here /void data;/ */
} ipv6_packet_t;
typedef struct udp_packet {
	uint16_t port_src;
	uint16_t port_dst;
	uint16_t length;
	uint16_t checksum;
} udp_packet_t;
typedef struct dhcp_message {
	uint8_t op; 	/**< 0x01 for us, 0x02 for the dhcp server */
	uint8_t htype;	/**< 0x01 */
	uint8_t hlen;	/**< 0x06 */
	uint8_t hops;	/**< 0x00 */
	uint32_t xid;	/**< Transaction ID */
	uint16_t secs;	
	uint16_t flags;	
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];/**< For MAC addrs, only the 6 first bytes are used */
	uint8_t zeros[192];/**< 0x00 */
	uint32_t magicCookie;/**< 0x63825363 */
	/* Options /void options;/ */
	// Must be 0xFF terminated
} dhcp_message_t;
typedef struct dns_query {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answerRRs;
	uint16_t authorityRRs;
	uint16_t additionalRRs;
	// queries
	// answers
	// authority
	// additional
} dns_query_t;
typedef struct tcp_segment {
	uint16_t port_src;
	uint16_t port_dst;
	uint32_t seq_number;
	uint32_t ack_number;
	uint16_t dataOffset_flags;
	uint16_t windowSize;
	uint16_t checksum;
	uint16_t urgentPointer;
	uint8_t options[];
} tcp_segment_t;

#define ipv6_addr		uint8_t*	


#define ETH_IPV4		0x0008		/* big endian stored */

#define ICMP_PROTOCOL	0x01
#define TCP_PROTOCOL	0x06
#define UDP_PROTOCOL	0x11

#define SERVER_DHCP_PORT	67
#define CLIENT_DHCP_PORT	68
#define DNS_PORT			53
#define HTTP_PORT			80
#define TCP_PORT			443

#define ERROR_DHCP_NACK		01

#define MAX_SEGMENT_SIZE	536		/* Default MSS */
#define TCP_WINDOW_SIZE		MAX_SEGMENT_SIZE*2 /* Considering the calculator is pretty slow */

#define FLAG_TCP_FIN	1 << 0
#define FLAG_TCP_SYN	1 << 1
#define FLAG_TCP_ACK	1 << 4



usb_error_t init_tcp_session(rndis_device_t *device, uint32_t ip_dst);
usb_error_t receive_tcp_segment(tcp_segment_t **tcp_segment, size_t *length, uint32_t expected_ip, rndis_device_t *device);
uint32_t send_dns_request(const char *addr, rndis_device_t *device);
usb_error_t dhcp_ip_request(rndis_device_t *device);
usb_error_t send_dhcp_request(uint8_t *data, size_t length, rndis_device_t *device);
void tcp_encpsulate(uint8_t **data, size_t *length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst, uint32_t ack_number, uint16_t flags);
uint16_t tcp_checksum(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst);
void udp_encapsulate(uint8_t **data, size_t *length, uint16_t port_src, uint16_t port_dst);
void send_icmpv6_init_message(rndis_device_t device);
void ipv6_encapsulate(uint8_t **data, size_t *length, ipv6_addr ip_src, ipv6_addr ip_dst);
void ipv4_encapsulate(uint8_t **data, size_t *length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol);
uint16_t ipv4_checksum(uint16_t *header, size_t length);
void ethernet_encapsulate(uint8_t **data, size_t *length, rndis_device_t *device);
uint32_t crc32b(uint8_t *data, size_t length);
usb_error_t rndis_send_packet(uint8_t **data, size_t *length, rndis_device_t *device);
usb_error_t rndis_init(rndis_device_t *device);
uint32_t getMyIPAddr();
static usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *device);
static usb_error_t transfer_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *completed);
static void debug(void *addr, size_t len);
static void disp(unsigned int val);
static uint8_t MAC_ADDR[6] = {0xDA, 0xA5, 0x59, 0x9b, 0x71, 0xa8};
static uint32_t IP_ADDR = 0;
static uint32_t seq_number = 0x12345678; // first client segment's sequence number (for TCP)

/*************************************************************\
 * à terme : - renvoyer les packets aux bout d'un certain temps
 *			 notamment dhcp qui fait souvent de la merde
 *			 - choisir seq_number aleatoirement
 *			 - 
\*************************************************************/

int main(void)
{
	rndis_device_t device;
	usb_error_t ret_err;

	os_ClrHome();
	boot_NewLine();
	os_PutStrFull("RNDIS : Connection...");
	boot_NewLine();
	
	ret_err = rndis_init(&device);
	if(ret_err != USB_SUCCESS) {
		if(ret_err == USB_ERROR_NOT_SUPPORTED) {
			os_PutStrFull("Device not compatible...");
			boot_NewLine();
			os_PutStrFull("Please read the README formore information.");
		} else if(ret_err == USB_ERROR_FAILED)
			os_PutStrFull("Error: Connection lost!");
		else
			os_PutStrFull("Canceled!");
		while(!os_GetCSC()) {}
		goto _end;
	}
	os_PutStrFull("RNDIS : Connected!");
	boot_NewLine();

	// Fait :		USB - RNDIS - Ethernet - IPv4 - UDP - DHCP - DNS
	// Maintenant : TCP -> HTTP

	// Ok donc j'ai résolu le bug... je me sens hyper con, le problème c'était ETH_IPV4
	// Mais bref, même si ça dit pas trop pourquoi ça marchait une fois sur 2 ça c'est fait.
	// Enfin, si tout était réglé ce serait trop facile : J'envoie une requête TCP SYN mais pas de réponse
	// ça peut venir du fait que ip_dst a une valeur cheloue (pourtant quand je debug(data) c'est une bonne valeur...)


	os_PutStrFull("Requesting IP address...");
	boot_NewLine();
	ret_err = dhcp_ip_request(&device);
	//if(ret_err != USB_SUCCESS) -> ne fonctionne pas ?
	//	goto _end;
	os_PutStrFull("Done!");
	boot_NewLine();
	os_PutStrFull("DNS Request...");
	boot_NewLine();
	uint32_t ip = 0;
	ip = send_dns_request("www.google.fr", &device);
	os_PutStrFull("Done!");
	boot_NewLine();
	os_PutStrFull("TCP SYN...");
	boot_NewLine();
	init_tcp_session(&device, ip);
	os_PutStrFull("Done!");
	boot_NewLine();

	// The End.
	_end:
	while(!os_GetCSC())
		usb_WaitForInterrupt();
	usb_Cleanup();
	return 0;
}


usb_error_t init_tcp_session(rndis_device_t *device, uint32_t ip_dst) {
	// Bon c'est cool tous les problèmes de merdes précédents ont été résolus.
	// Là faudrait juste checksum la réponse (oui la lib est minimaliste mais c'est le minimum)
	// Ce qui est moins cool c'est ce qui va venir... eh oui entre autre la window size !
	// Ça pose plein de question sur comment je vais fonctionner et jusqu'où va aller la lib :
	//		est-ce que j'autorise une window size assez grande ou je fonctionne en segment->ack ?
	//		je renvoie un paquet au bout de combien de temps ?
	//		comment je gère une erreur (checksum ou ack_number etc) ?
	//		est-ce que je gère la possibilité d'envoyer du multi-packet ?
	//		est-ce que je fais aussi une vérification qu'il a bien renvoyé un bon ack (= notre seq_number) ?
	//			faudra d'ailleurs pas oublier d'augmenter en conséquence notre sequence number juste ici...
	// Bref, TCP est de loin le protocole le plus complexe, devant IP, DHCP ou même HTTP.
	// A moi de choisir si je fais ça proprement ou pas (surement un truc entre les deux à définir).
	//
	// Note : Ce serait bien de se renseigner sur le site avec un nom du genre "tout sur tcp/ip" (voir tel.).

	// CDC Personnel (à restreindre ou à élargir en fonction)
	//  *	crucial
	// (*)	important
	// ~*~	facultatif
	//
	//		- ORGANISER une connexion
	//			 * 	Gérer les SYN, SYN/ACK, ACK du début de connexion
	//			(*)	Renvoyer un segment au bout d'un certain temps
	//			(*)	Terminer une connexion (FIN, FIN/ACK *2)
	//			~*~	Permettre la communication simultanée de plusieurs applications (utile seulement si la lib ne bloque pas l'application)
	//
	//		- ASSURER la réception des segments
	//			* Remettre les segments dans l'ordre, malgré leur arrivée asynchrone
	//			* Avoir un assez gros buffer pour recevoir un segment de taille maximale
	//				(Le buffer pour recevoir le fichier entier est à la charge de l'utilisateur)
	//			* ACK le serveur en bonne et due forme
	//
	//		- VERIFIER la conformité de la réponse
	//			*	Vérifier le checksum
	//			*	Prévenir le serveur (ne pas ACK) en cas de segment erronné
	//

	/* Handshaking... */
	/* SYN */
	debug(&ip_dst, 4);
	while(!os_GetCSC()) {}

	uint8_t *data = NULL;
	size_t length = 0;
	tcp_encpsulate(&data, &length, ip_dst, 0xec50, TCP_PORT, 0, FLAG_TCP_SYN);
	ipv4_encapsulate(&data, &length, IP_ADDR, ip_dst, TCP_PROTOCOL);
	ethernet_encapsulate(&data, &length, device);
	//os_ClrHome();
	//boot_NewLine();
	//debug(data, 72);
	//while(!os_GetCSC()) {}
	//os_ClrHome();
	//boot_NewLine();
	//debug(data+72, 72);
	//while(!os_GetCSC()) {}
	usb_error_t ret_err = rndis_send_packet(&data, &length, device);
	free(data);

	/* SYN ACK */
	tcp_segment_t *response = malloc(MAX_SEGMENT_SIZE+0x40); // The MAX_SEGMENT_SIZE does not take into account the TCP header (which is at most 0x40 bytes)
	receive_tcp_segment(&response, &length, ip_dst, device);
	if(/*tcp_checksum((uint8_t*)response, length, ip_dst, IP_ADDR) ||*/ !(response->dataOffset_flags&0x0200) || !(response->dataOffset_flags&0x1000)) {
		os_PutStrFull("SYN ACK FAILED");
		boot_NewLine();
		return USB_ERROR_FAILED;
	}
	uint16_t test = tcp_checksum((uint8_t*)response, length, ip_dst, IP_ADDR);
	debug(&test, 2);

	/* ACK */
	length = 0;
	data = NULL;
	tcp_encpsulate(&data, &length, ip_dst, 0xec50, TCP_PORT, response->seq_number+1, FLAG_TCP_ACK);
	free(response);
	return USB_SUCCESS;
}

usb_error_t receive_tcp_segment(tcp_segment_t **tcp_segment, size_t *length, uint32_t expected_ip, rndis_device_t *device) {
	uint8_t resp[MAX_SEGMENT_SIZE+100];
	size_t len;
	while(!os_GetCSC()) {
		usb_Transfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), resp, MAX_SEGMENT_SIZE+100, 3, &len);
		// Il manque l'info len qui est donnée dans le callback
		//transferred = false;
		//usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), resp, MAX_SEGMENT_SIZE+100, transfer_callback, &transferred);
		//do {
		//	usb_WaitForInterrupt();
		//	key = os_GetCSC();
		//} while(!key && !transferred);

		const eth_frame_t *ethernet_frame = (eth_frame_t*)(resp + sizeof(rndis_packet_msg_t));
		if(!memcmp(ethernet_frame->MAC_dst, MAC_ADDR, 6)) { // if it's for us (broadcast messages aren't interesting here)
			os_PutStrFull("eth");
			if(ethernet_frame->Ethertype == ETH_IPV4) {
				os_PutStrFull("ip");
				const ipv4_packet_t *ipv4_pckt = (ipv4_packet_t*)((uint8_t*)ethernet_frame+sizeof(eth_frame_t)-4); // -4=-crc
				if(ipv4_pckt->IP_addr_src == expected_ip && ipv4_pckt->Protocol == TCP_PROTOCOL) {
					os_PutStrFull("tcp");
					const tcp_segment_t *tcp_seg = (tcp_segment_t*)((uint8_t*)ipv4_pckt + (ipv4_pckt->VerIHL&0x0F)*4);
					if(tcp_seg->port_src/256 == TCP_PORT%256 && tcp_seg->port_src%256 == TCP_PORT/256) {
						*length = len-sizeof(rndis_packet_msg_t)-sizeof(eth_frame_t)+4-(ipv4_pckt->VerIHL&0x0F)*4;
						memcpy(*tcp_segment, tcp_seg, *length);
						return USB_SUCCESS;
					}
				}
			}
		}
	}
	return USB_IGNORE;
}


uint32_t send_dns_request(const char *addr, rndis_device_t *device) {
	size_t length = sizeof(dns_query_t)+strlen(addr)+2+4;
	uint8_t *query = calloc(length, 1); // 2=length byte at the begining of the string+0 terminated string
	query[2] = 0x01;
	query[5] = 0x01;

	// formating address for dns purposes
	char *cursor_qry = (char*)(query+sizeof(dns_query_t)+1);
	char *cursor_str = (char*)addr;
	uint8_t i = 1;
	while(*cursor_str) {
		if(*cursor_str == '.') {
			*(cursor_qry-i) = i-1;
			i = 0;
		} else
			*cursor_qry = *cursor_str;
		i++;
		cursor_str++;
		cursor_qry++;
	}
	*(cursor_qry-i) = i-1;
	*cursor_qry = 0;
	*(cursor_qry+2) = 1; // A (IPv4)
	*(cursor_qry+4) = 1; // IN (internet)

	udp_encapsulate(&query, &length, 0xd52f, DNS_PORT);
	ipv4_encapsulate(&query, &length, IP_ADDR, device->DNS_IP_addr, UDP_PROTOCOL);
	ethernet_encapsulate(&query, &length, device);
	usb_error_t ret_err = rndis_send_packet(&query, &length, device);
	free(query);
	if(ret_err)
		return -1;

	uint8_t answer[512];
	while(!os_GetCSC()) {
		usb_Transfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), answer, 512, 3, NULL);
		const eth_frame_t *ethernet_frame = (eth_frame_t*)(answer + sizeof(rndis_packet_msg_t));
		if(!memcmp(ethernet_frame->MAC_dst, MAC_ADDR, 6)) { // if it's for us (broadcast messages aren't interesting here)
			if(ethernet_frame->Ethertype == ETH_IPV4) {
				const ipv4_packet_t *ipv4_pckt = (ipv4_packet_t*)((uint8_t*)ethernet_frame+sizeof(eth_frame_t)-4); // -4=-crc
				if(ipv4_pckt->Protocol == UDP_PROTOCOL) {
					const udp_packet_t *udp_pckt = (udp_packet_t*)((uint8_t*)ipv4_pckt + (ipv4_pckt->VerIHL&0x0F)*4);
					if(udp_pckt->port_src/256 == DNS_PORT && udp_pckt->port_src%256 == 0x00) {
						const dns_query_t *dns_qry = (dns_query_t*)((uint8_t*)udp_pckt + sizeof(udp_packet_t));
						const uint8_t *resp = (uint8_t*)dns_qry + sizeof(dns_query_t) + (strlen(addr)+2+4);
						if((dns_qry->flags&0x8000) && (dns_qry->flags&0x0080) && !((dns_qry->flags&0x0F00) && *(resp+3)==0x01)) // if -it is a response -the recursion was available -no error occurred -the response is an IPv4 address
							return *((uint32_t*)(resp+12)); // we only take into account of the first answer
						else
							return USB_ERROR_FAILED; // the server reponse does not suit us
					}
				}
			}
		}
	}
	return USB_IGNORE;
}


usb_error_t dhcp_ip_request(rndis_device_t *device) {
	/**
	 *	Sends an IPv4 request to the local server.
	 *	The RNDIS device must have been initialized with rndis_init() first.
	 *	@param device The RNDIS Device to communicate with.
	 *	@return USB_SUCCESS or an error.
	 *	@output device correct attributes (router_MAC_addr, DNS_IP_addr, DHCP_IP_addr) and static variable IP_ADDR.
	 */
	// DHCP DISCOVERY
	static uint32_t xid = 0x03F82639;
	const uint8_t beg_header[] = {0x01, 0x01, 0x06, 0x00};
	const uint8_t options_disc[] = {53, 1, 1, 0x37, 3, 1, 3, 6, 0xFF, 0};
	const size_t length_disc = sizeof(dhcp_message_t)+sizeof(options_disc);
	uint8_t *data_disc = calloc(length_disc, 1);
	memcpy(data_disc, &beg_header, 4);
	((uint32_t*)data_disc)[1] = xid;
	memcpy(data_disc+28, &MAC_ADDR, 6);
	((uint32_t*)data_disc)[59] = 0x63538263;
	memcpy(data_disc+240, &options_disc, sizeof(options_disc));
	send_dhcp_request(data_disc, length_disc, device);

	// planning DHCP REQUEST data
	const uint8_t options_req[] = {53, 1, 3, 0x37, 3, 1, 3, 6, 54, 4, 0, 0, 0, 0, 50, 4, 0, 0, 0, 0, 0xFF};
	const size_t length_req = sizeof(dhcp_message_t)+21; //1=0xFF, 20=options
	uint8_t *data_req = calloc(length_req, 1);
	memcpy(data_req, &beg_header, 4);
	((uint32_t*)data_req)[1] = xid;
	memcpy(data_req+28, &MAC_ADDR, 6);
	((uint32_t*)data_req)[59] = 0x63538263;
	memcpy(data_req+240, &options_req, 21);

	
	bool completed = false;
	uint8_t dhcp_error = 0;
	uint8_t response[512];
	int key = 0;
	bool transferred;
	while(!key && !completed && !dhcp_error) {
		transferred = false;
		usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, (device->ep_cdc)|0x80), response, 512, transfer_callback, &transferred);
		do {
			usb_WaitForInterrupt();
			key = os_GetCSC();
		} while(!key && !transferred);

		const eth_frame_t *ethernet_frame = (eth_frame_t*)(response + sizeof(rndis_packet_msg_t));
		if(!memcmp(ethernet_frame->MAC_dst, MAC_ADDR, 6)) { // if it's for us (broadcast messages aren't interesting here)
			memcpy(device->router_MAC_addr, ethernet_frame->MAC_src, 6);
			if(ethernet_frame->Ethertype == ETH_IPV4) {
				const ipv4_packet_t *ipv4_pckt = (ipv4_packet_t*)((uint8_t*)ethernet_frame+sizeof(eth_frame_t)-4); // -4=-crc
				if(ipv4_pckt->Protocol == UDP_PROTOCOL) {
					const udp_packet_t *udp_pckt = (udp_packet_t*)((uint8_t*)ipv4_pckt + (ipv4_pckt->VerIHL&0x0F)*4);
					if(udp_pckt->port_dst == 0x4400) {
						const dhcp_message_t *dhcp_msg = (dhcp_message_t*)((uint8_t*)udp_pckt+sizeof(udp_packet_t));
						if(dhcp_msg->op == 0x02 && dhcp_msg->xid == xid) {
							IP_ADDR = dhcp_msg->yiaddr;
							device->DHCP_IP_addr = dhcp_msg->siaddr;
							const uint8_t *cur_opt = (uint8_t*)((uint8_t*)dhcp_msg+sizeof(dhcp_message_t));
							while(*cur_opt != 0xFF) {
								switch(*cur_opt) {
									case 53: // DHCP message type
										if(*(cur_opt+2) == 2) { // DHCP Offer
											((uint32_t*)(data_req+2))[62] = device->DHCP_IP_addr;
											((uint32_t*)data_req)[64] = IP_ADDR;
											delay(100); // that's funny but.. the calculator is too fast for some dhcp servers
											send_dhcp_request(data_req, length_req, device);
										} else if(*(cur_opt+2) == 5) // ACK
											completed = true;
										else if(*(cur_opt+2) == 6) // NACK
											dhcp_error = ERROR_DHCP_NACK;
										break;
									case 6: // DNS SERVER
										device->DNS_IP_addr = *((uint32_t*)(cur_opt+2)); // we only take the first entry
										break;
									case 51: // Lease time
										// nothing to do yet
										break;
									default:
										break;
								}
								cur_opt += *(cur_opt+1)+2;
							}
						}
					}
				}
			}
		}
	}
	xid++;
	//free(gogole);
	free(data_disc);
	free(data_req);
	if(!completed) {
		os_PutStrFull("An error occurred...");
		return USB_ERROR_FAILED;
	}
	return USB_SUCCESS;
}


usb_error_t send_dhcp_request(uint8_t *data, size_t length, rndis_device_t *device) {
	uint8_t *old_data = data;
	data = calloc(length, 1); // it needs to be allocated with malloc
	memcpy(data, old_data, length);
	udp_encapsulate(&data, &length, CLIENT_DHCP_PORT, SERVER_DHCP_PORT);
	ipv4_encapsulate(&data, &length, 0x00000000, 0xFFFFFFFF, UDP_PROTOCOL);
	ethernet_encapsulate(&data, &length, device);
	usb_error_t ret_err = rndis_send_packet(&data, &length, device);

	free(data);
	return ret_err;
}


void tcp_encpsulate(uint8_t **data, size_t *length, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst, uint32_t ack_number, uint16_t flags) {
	/**
	 *	Encapsulates data with a TCP header.
	 *	The current version is not able to break down data into several ipv4 packets.
	 *	Consequently, this lib is not aim at uploading large amount of data.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param ip_dst The IP of the target server.
	 *	@param port_dst The destination port. For example TCP_PORT (443) or HTTP (80).
	 *	@param ack_number The 32-bits number that must be written in the ACK field.
	 *	@param flags For example FLAG_TCP_ACK for acknowledging a segment.
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */

	//			Faire en sorte qu'on puisse mettre les options en paramètre plutôt
	uint8_t *old_data = *data;
	if(flags&FLAG_TCP_SYN)
		*data = calloc(*length+sizeof(tcp_segment_t)+4, 1);
	else
		*data = calloc(*length+sizeof(tcp_segment_t), 1);
	(*data)[0] = port_src/256;
	(*data)[1] = port_src%256;
	(*data)[2] = port_dst/256;
	(*data)[3] = port_dst%256;
	(*data)[4] = seq_number/16777216;
	(*data)[5] = seq_number/65536;
	(*data)[6] = seq_number/256;
	(*data)[7] = seq_number%256;
	(*data)[8] = ack_number/16777216;
	(*data)[9] = ack_number/65536;
	(*data)[10] = ack_number/256;
	(*data)[11] = ack_number%256;
	if(flags&FLAG_TCP_SYN)
		(*data)[12] = 0x70|(flags&0x0100);
	else
		(*data)[12] = 0x50|(flags&0x0100);
	(*data)[13] = flags&0x00FF;
	(*data)[14] = TCP_WINDOW_SIZE/256;	/* window size */
	(*data)[15] = TCP_WINDOW_SIZE%256;
	((uint16_t*)*data)[9] = 0x0000;		/* urgent pointer */
	
	if(flags&FLAG_TCP_SYN) {
		const uint8_t options[] = {0x02, 0x04, MAX_SEGMENT_SIZE/256, MAX_SEGMENT_SIZE%256};
		memcpy(*data+sizeof(tcp_segment_t), options, sizeof(options));
		if(*length)
			memcpy(*data+sizeof(tcp_segment_t)+4, old_data, *length);
	} else if(*length)
		memcpy(*data+sizeof(tcp_segment_t), old_data, *length);
	if(flags&FLAG_TCP_SYN)
		*length += sizeof(tcp_segment_t)+4;
	else
		*length += sizeof(tcp_segment_t);
	uint16_t chksm = tcp_checksum(*data, *length, IP_ADDR, ip_dst);
	(*data)[16] = chksm/256;
	(*data)[17] = chksm%256;
	if(old_data)
		free(old_data);
}

uint16_t tcp_checksum(uint8_t *data, size_t length, uint32_t ip_src, uint32_t ip_dst) {
	uint16_t chksmmsb = length/256 + (ip_dst/65536&0xff) + (ip_dst&0xff) + (ip_src/65536&0xff) + (ip_src&0xff);
	uint16_t chksmlsb = TCP_PROTOCOL + length%256 + (ip_dst/16777216&0xff) + (ip_dst/256&0xff) + (ip_src/16777216&0xff) + (ip_src/256&0xff);
	for(size_t i=0; i<length-1; i+=2) {
		chksmmsb += data[i];
		chksmlsb += data[i+1];
	}
	if(length%2)
		chksmmsb += data[length-1];
	chksmmsb += chksmlsb>>8;
	chksmlsb += chksmmsb>>8;
	return (uint16_t)~((chksmmsb<<8)+(chksmlsb&0x00FF));
}


void udp_encapsulate(uint8_t **data, size_t *length, uint16_t port_src, uint16_t port_dst) {
	/**
	 *	Encapsulates data with an UDP header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param port_dst The destination port. For example DHCP_PORT (68) or DNS_PORT (53).
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	uint8_t *old_data = *data;
	*data = calloc(*length+sizeof(udp_packet_t), 1);
	(*data)[0] = port_src/256;
	(*data)[1] = port_src%256;
	(*data)[2] = port_dst/256;
	(*data)[3] = port_dst%256;
	(*data)[4] = (*length+sizeof(udp_packet_t))/256;
	(*data)[5] = (*length+sizeof(udp_packet_t))%256;
	memcpy(*data+sizeof(udp_packet_t), old_data, *length);
	free(old_data);
	*length += sizeof(udp_packet_t);
}


void send_icmpv6_init_message(rndis_device_t device) {
	/**
	 *	Sends an ICMPv6 message, in order to résoudre ce putain de bug.
	 */
	/*size_t length = 16*4+4;
	uint8_t *msg = calloc(length, 1);
	const uint8_t icmp_msg[] = {};
	memcpy(msg, icmp_msg, sizeof(icmp_msg));

	const uint32_t ip_src[] = {0, 0, 0, 0};
	const uint8_t ip_dst[] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16};
	const uint8_t brdcst_addr[] = {0x33, 0x33, 0, 0, 0, 0x16};
	memcpy(device.router_MAC_addr, brdcst_addr, 6);
	ipv6_encapsulate(&data, &length, (ipv6_addr)ip_src, (ipv6_addr)ip_dst);
	ethernet_encapsulate(&data, &length, &device);
	rndis_send_packet(&data, &length, &device);

	free(msg);*/
}


void ipv6_encapsulate(uint8_t **data, size_t *length, ipv6_addr ip_src, ipv6_addr ip_dst) {
	/**
	 *	Encapsulates data with an IPv6 header.
	 *	This header is only aim at providing a way to make ICMPv6 messages.
	 *	Consequently Hop Limit is set to 1, NextHeader is set to 0 and an Hop-by-Hop option is put.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param ip_src Your IP or 0::0 if you have been attributed no IP yet (which will usually be the case).
	 *	@param ip_dst The IP of the target server (for broadcast messages : ff02::16).
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	const uint8_t hopByHopOption[] = {0x3a, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00};
	uint8_t *old_data = *data;
	*data = calloc(*length+sizeof(ipv6_packet_t)+8, 1); /* 8=Hop-by-Hop option */
	(*data)[0] = 0x06;
	((uint16_t*)*data)[2] = *length+8; /* 8=Hop-by-Hop option */
	(*data)[7] = 0x01; // Hop limit
	memcpy(*data+8, ip_src, 16);
	memcpy(*data+24, ip_dst, 16);
	memcpy(*data+sizeof(ipv6_packet_t), hopByHopOption, sizeof(hopByHopOption));
	memcpy(*data+sizeof(ipv6_packet_t)+8, old_data, *length);
	free(old_data);
	*length += sizeof(ipv6_packet_t)+8;
}


void ipv4_encapsulate(uint8_t **data, size_t *length, uint32_t ip_src, uint32_t ip_dst, uint8_t protocol) {
	/**
	 *	Encapsulates data with an IPv4 header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param device The device to communicate with. 
	 *	@param ip_src Your IP or 0.0.0.0 if you have been attributed no IP yet (for DHCP requests for example).
	 *	@param ip_dst The IP of the target server.
	 *	@param protocol Protocol of the data. For example ICMP_PROTOCOL (0x01), TCP_PROTOCOL (0x06) or UDP_PROTOCOL (0x11).
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	static uint16_t nbpacket = 0;
	const size_t size = *length+sizeof(ipv4_packet_t);
	const ipv4_packet_t packet = {0x45, 0, 0, 0, 0, 0x80, 0, 0, 0, 0};
	uint8_t *old_data = *data;
	*data = malloc(size);
	memcpy(*data, &packet, sizeof(ipv4_packet_t));
	(*data)[2] = size/256;
	(*data)[3] = size%256;
	(*data)[4] = nbpacket/256;
	(*data)[5] = nbpacket%256;
	(*data)[9] = protocol;
	((uint32_t*)*data)[3] = ip_src;
	((uint32_t*)*data)[4] = ip_dst;
	uint16_t chksm = ipv4_checksum((uint16_t*)*data, sizeof(ipv4_packet_t));
	(*data)[10] = chksm%256;
	(*data)[11] = chksm/256;
	memcpy(*data+sizeof(ipv4_packet_t), old_data, *length);
	free(old_data);
	*length = size;
	nbpacket++;
}

uint16_t ipv4_checksum(uint16_t *header, size_t length) {
	uint24_t sum = 0;
	for(size_t i=0; i<length/2; i++) 
		sum += header[i];
	return (uint16_t)~(sum+(sum >> 16));
}


void ethernet_encapsulate(uint8_t **data, size_t *length, rndis_device_t *device) {
	/**
	 *	Encapsulates data with an ethernet header.
	 *	@param **data Pointer of the data to be encapsulated, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param device RNDIS device to communicate with.
	 *	@output data points to the data encapsulated. length points to the new length of *data.
	 */
	uint8_t *old_data = *data;
	if(*length<46) // An ethernet frame must be at least 64B
		*data = calloc(64, 1);
	else
		*data = malloc(sizeof(eth_frame_t)+*length);
	memcpy(*data, device->router_MAC_addr, 6);
	memcpy(*data+6, MAC_ADDR, 6);
	((uint16_t*)*data)[6] = ETH_IPV4; // Ethertype : IPv4
	memcpy(*data+sizeof(eth_frame_t)-4, old_data, *length);
	if(*length<46)
		*length = 64;
	else
		*length += sizeof(eth_frame_t);
	uint32_t crc = crc32b(*data, *length-4);
	
	memcpy(*data+*length-4, &crc, 4);
	//(*data)[*length/4-1] = crc;
	free(old_data);
}


#define CRC_POLY 0xEDB88320
uint32_t crc32b(uint8_t *data, size_t length) {
	/**
	 *	Computes ethernet crc 32bits. The bytes must be written reversed in the frame.
	 *	Code found on stackoverflow.com (no licence was given to the code)
	 */
	// IL FAUT EN PARLER AVEC QUELQU'UN
	// LORS DE LA DEUXIÈME BOUCLE EMBRIQUÉE, IL A DIT NTM ET BOUCLE DANS LA VIDE
    uint32_t crc;
	size_t j;

    if(!data || !length)
        return 0;
    crc = 0xFFFFFFFF;
    for(j = 0; j < length; j++) {
        crc ^= data[j];
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
        crc = (crc & 1) ? ((crc >> 1) ^ CRC_POLY) : (crc >> 1);
    }
    return ~crc;
}


usb_error_t rndis_send_packet(uint8_t **data, size_t *length, rndis_device_t *device) {
	/**
	 *	Sends a packet to the device.
	 *	Blocks until the transfer finishes.
	 *	@param **data Pointer of the data to be sent, allocated with malloc.
	 *	@param length Points to the size of *data.
	 *	@param device The device to communicate with. 
	 *	@return USB_SUCCESS or an error.
	 */
	usb_error_t ret_err;
	uint8_t *old_data = *data;
	*data = malloc(sizeof(rndis_packet_msg_t)+*length);
	memset(*data, 0, sizeof(rndis_packet_msg_t));
	(*data)[0] = RNDIS_PACKET_MSG;
	(*data)[4] = (sizeof(rndis_packet_msg_t)+*length)%256;
	(*data)[5] = (sizeof(rndis_packet_msg_t)+*length)/256;
	(*data)[8] = 36;
	(*data)[12] = *length%256;
	(*data)[13] = *length/256;
	memcpy(*data+sizeof(rndis_packet_msg_t), old_data, *length);
	*length += sizeof(rndis_packet_msg_t);
	free(old_data);

	//ret_err = usb_Transfer(usb_GetDeviceEndpoint(device->device, device->ep_cdc), *data, *length, 3, &len);
	bool completed = false;
	ret_err = usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, device->ep_cdc), *data, *length, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	
	return ret_err;
}


usb_error_t rndis_init(rndis_device_t *device) {
	/**
		Waits until a rndis device is detected
		If any key is pressed, returns USB_IGNORE.
		If the RNDIS Device has been initialized properly, returns USB_SUCCESS.
		If not, returns an error.
	**/
	const rndis_init_msg_t rndis_initmsg = {RNDIS_INIT_MSG, 24, 0, 1, 0, 0x0400};
	const rndis_set_msg_t rndis_setpcktflt = {RNDIS_SET_MSG , 32, 1, 0x0001010e, 4, 20, 0, 0x2d};
	const usb_control_setup_t out_ctrl = {0x21, 0, 0, 0, 0};
	const usb_control_setup_t in_ctrl = {0xa1, 1, 0, 0, 0x0400};
	uint8_t desc[512];
	size_t len = 0;
	uint8_t cur_interface = 0; // b0 -> wc, b1 -> cdc
	bool completed;
	uint8_t i;
	device->int_wc = 0;
	device->int_cdc = 0;
	device->ep_wc = 0;
	device->ep_cdc = 0;
	device->enabled = false;

	_init:
	/*********** Connection ***********/
	device->connected = false;
	usb_Init(usbHandler, device, NULL, USB_DEFAULT_INIT_FLAGS);
	while(!os_GetCSC() && !device->connected)
		usb_WaitForInterrupt();
	if(!device->connected)
		return USB_IGNORE;
	usb_ResetDevice(device->device);
	while(!os_GetCSC() && !(device->enabled))
		usb_WaitForInterrupt();
	if(!device->enabled)
		return USB_IGNORE;

	/*********** Configuration USB ***********/
	usb_GetDescriptor(device->device, USB_CONFIGURATION_DESCRIPTOR, 0, desc, 512, &len);
	if(!len)
		return USB_ERROR_FAILED;
	i = 0;
	while(i<len) {
		if(*(desc+i+1)==USB_INTERFACE_DESCRIPTOR) {
			if(*(desc+i+5)==USB_WIRELESS_CONTROLLER_CLASS && *(desc+i+6)==RNDIS_SUBCLASS && *(desc+i+7)==RNDIS_PROTOCOL) {
				cur_interface = 1; // wireless controller
				device->int_wc = *(desc+i+2);
			} else if(*(desc+i+5)==USB_CDC_DATA_CLASS && *(desc+i+6)==0x00 && *(desc+i+7)==0x00) {
				cur_interface = 2; // cdc interface
				device->int_cdc = *(desc+i+2);
			} else
				cur_interface = 0;
		} else if(*(desc+i+1)==USB_ENDPOINT_DESCRIPTOR) {
			if(cur_interface == 1)
				device->ep_wc = *(desc+i+2) & 0x7F;
			else if(cur_interface == 2)
				device->ep_cdc = *(desc+i+2) & 0x7F;
		}
		i += *(desc+i);
	}
	if(!device->ep_wc || !device->ep_cdc) {
		device->connected = false;
		while(!os_GetCSC() && !device->connected)
			usb_WaitForInterrupt();
		if(!device->connected)
			return USB_IGNORE;
		goto _init;
	}
	if(USB_SUCCESS != usb_SetConfiguration(device->device, (usb_configuration_descriptor_t*)desc, len))
		return USB_ERROR_FAILED;


	/************** Configuration RNDIS ************/
	// Init Out
	completed = false;
	memcpy(desc, &out_ctrl, sizeof(usb_control_setup_t));
	desc[6] = 24; // wLength
	memcpy(desc+sizeof(usb_control_setup_t), &rndis_initmsg, sizeof(rndis_init_msg_t));
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	if(!completed)
		return USB_IGNORE;
	// Init In
	completed = false;
	memcpy(desc, &in_ctrl, sizeof(usb_control_setup_t));
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	if(!completed)
		return USB_IGNORE;
	// set OID_GEN_CURRENT_PACKET_FILTER with default value
	completed = false;
	memcpy(desc, &out_ctrl, sizeof(usb_control_setup_t));
	desc[6] = 32; // wLength
	memcpy(desc+sizeof(usb_control_setup_t), &rndis_setpcktflt, sizeof(rndis_setpcktflt));
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	if(!completed)
		return USB_IGNORE;
	memcpy(desc, &in_ctrl, sizeof(usb_control_setup_t));
	completed = false;
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &completed);
	while(!os_GetCSC() && !completed)
		usb_WaitForInterrupt();
	if(!completed)
		return USB_IGNORE;


	/*uint8_t desc[512];
	bool complete = false;
	const usb_control_setup_t out_ctrl = {0x21, 0, 0, 0, 0};
	const usb_control_setup_t in_ctrl = {0xa1, 1, 0, 0, 0x0400};
	const uint8_t machin[] = {0x04, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	complete = false;
	memcpy(desc, &out_ctrl, sizeof(usb_control_setup_t));
	desc[6] = 28; // wLength
	memcpy(desc+sizeof(usb_control_setup_t), machin, sizeof(machin));
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &complete);
	while(!os_GetCSC() && !complete)
		usb_WaitForInterrupt();
	if(!complete)
		return USB_IGNORE;

	memcpy(desc, &in_ctrl, sizeof(usb_control_setup_t));
	complete = false;
	usb_ScheduleTransfer(usb_GetDeviceEndpoint(device->device, 0), desc, 0, transfer_callback, &complete);
	while(!os_GetCSC() && !complete)
		usb_WaitForInterrupt();
	if(!complete)
		return USB_IGNORE;

	os_ClrHome();
	boot_NewLine();
	debug(desc, 72);
	while(!os_GetCSC()) {}*/


	memset(&(device->router_MAC_addr), 0xFF, 6);
	//srand(rtc_Time());
	//MAC_ADDR[5] = randInt(0, 0xFF);
	return USB_SUCCESS;
}


uint32_t getMyIPAddr() {
	return IP_ADDR;
}


static usb_error_t usbHandler(usb_event_t event, void *event_data, usb_callback_data_t *device) {
	static int nbdebug = 0;
	char tmp[30];
	unsigned int x, y;
	os_GetCursorPos(&x, &y);
	os_SetCursorPos(0, 0);
	sprintf(tmp, "%d", nbdebug++);
	os_PutStrFull(tmp);
	os_SetCursorPos(x, y);
	if(event == USB_DEVICE_CONNECTED_EVENT) {
		((rndis_device_t*)device)->device = (usb_device_t)event_data;
		((rndis_device_t*)device)->connected = true;
	} else if(event == USB_DEVICE_ENABLED_EVENT)
		((rndis_device_t*)device)->enabled = true;
	else if(event == USB_DEVICE_DISABLED_EVENT)
		((rndis_device_t*)device)->enabled = false;
	else if(event == USB_DEVICE_DISCONNECTED_EVENT)
		((rndis_device_t*)device)->connected = false;
	return USB_SUCCESS;
}

static usb_error_t transfer_callback(usb_endpoint_t endpoint, usb_transfer_status_t status, size_t transferred, usb_transfer_data_t *completed) {
	//char tmp[30];
	//sprintf(tmp, "CALLBACK ! %u - %u ", status, transferred);
	//os_PutStrFull(tmp);
	//boot_NewLine();
	if(!status)
		*((bool*)completed) = true;
	return USB_SUCCESS;
}


static void debug(void *addr, size_t len) {
	uint8_t *content = (uint8_t*)addr;
	char tmp[4];
	size_t i;
	const char *DIGITS = "0123456789ABCDEF";
	for(i=0; i<len; i++) {
		if(i && i%8 == 0)
			boot_NewLine();
		tmp[0] = ' ';
		tmp[1] = DIGITS[*(content+i)/16];
		tmp[2] = DIGITS[*(content+i)%16];
		tmp[3] = 0;
		os_PutStrFull(tmp);
	}
	boot_NewLine();
}

static void disp(unsigned int val) {
	uint24_t value = (uint24_t)val;
	char tmp[30];
	sprintf(tmp, "DISP : %u ", value);
	os_PutStrFull(tmp);
	boot_NewLine();
}
