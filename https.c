#include "https.h"

int ctr = 0;
packet_info *pktinfo = NULL;

typedef struct ProtocolVersion{
    uint8_t major;
    uint8_t minor;
} ProtocolVersion;

typedef enum ContentType{
	change_cipher_spec=20, alert=21, handshake=22, application_data=23
}ContentType;

typedef struct {
    uint8_t type;
    uint8_t major;
    uint8_t minor;
    uint16_t length;
}sniff_record;

struct handshake_protocol{
	uint8_t type;
	
	uint8_t byte1_len;
	uint8_t byte2_len;
	uint8_t byte3_len;

	ProtocolVersion version;
};

int length_from_handshake_protocol(struct handshake_protocol *hs){
	int result = (((int) hs->byte1_len) << 16) | (((int) hs->byte2_len) << 8) | ((int) hs->byte3_len);
	return result;
}

int parse_packet(const u_char *packet, const struct pcap_pkthdr *pkthdr, packet_info *pktinfo);

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const  u_char *packet){
	ctr++;
	memset(pktinfo, 0, sizeof(packet_info));
	parse_packet(packet, pkthdr, pktinfo);
}

int main(int argc, char *argv[]){

	fprintf(stderr, "%d\n", sizeof(sniff_record));

	pcap_t *handle; 
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_offline(argv[1], errbuf);
	pktinfo = (packet_info *) calloc(sizeof(packet_info), 1);

	if (handle == NULL) { 
      fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf); 
      return(2); 
    } 

    pcap_loop(handle, -1, callback, NULL);
    printf("%d\n", ctr);

	return 0;
}

char* version(uint8_t major, uint8_t minor){

	if(major == 3){
		switch(minor){
			case 0:
				return "SSL_3";
				break;
			case 3:
				return "TLS_1.2";
				break;
			case 2:
				return "TLS_1.1";
				break;
			case 1:
				return "TLS_1.0";
				break;
			default:
				return "Others";
				break;
		}
	}

	return "Others";
}

char* content_type(sniff_record *record){
	switch(record->type){
		case 20:
			return "Change Cipher Spec";
			break;
		case 21:
			return "Alert";
			break;
		case 22:
			return "Handshake";
			break;
		case 23:
			return "Application Data";
			break;
		default:
			return "Others";
			break;
	}
	return NULL;
}

char* handshake_type(struct handshake_protocol *hs){
	switch(hs->type){
		case 0:
			return "Hello Request";
			break;
		case 1:
			return "Client Hello";
			break;
		case 2:
			return "Server Hello";
			break;
		case 11:
			return "Certificate";
			break;
		case 12:
			return "Server Key Exchange";
			break;
		case 13:
			return "Certificate Request";
			break;
		case 14:
			return "Server Hello Done";
			break;
		case 15:
			return "Certificate Verify";
			break;
		case 16:
			return "Client Key Exchange";
			break;
		case 20:
			return "Finished";
			break;
		default:
			return "Others";
			break;
	}
	return NULL;
}













int parse_packet(const u_char *packet, const struct pcap_pkthdr *pkthdr, packet_info *pktinfo){
	
	
	memset(pktinfo->url, 0, URL_SIZE);
	pktinfo->ethernet = (struct sniff_ethernet*)(packet);
	pktinfo->ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	pktinfo->size_ip = IP_HL(pktinfo->ip)*4;

	if (pktinfo->size_ip < 20) {		
		return 1;
	}

	if(pkthdr->caplen < (SIZE_ETHERNET + pktinfo->size_ip + 20)){
		
		fprintf(stderr, "DEBUG/ finish parse_packet(). pkthdr->caplen < (SIZE_ETHERNET + pktinfo->size_ip + 20)\n");
		
		return 1;
	}

	pktinfo->tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + pktinfo->size_ip);
	pktinfo->size_tcp = TH_OFF(pktinfo->tcp)*4;

	pktinfo->port_src = ntohs(pktinfo->tcp->th_sport);       /* source port */
	pktinfo->port_dst = ntohs(pktinfo->tcp->th_dport);       /* destination port */
      
    if (pktinfo->size_tcp < 20) {
    	
		fprintf(stderr, "DEBUG/ finish parse_packet(). pktinfo->size_tcp < 20\n");
		
	    return 1;
    }

    pktinfo->payload = (u_char *)(packet + SIZE_ETHERNET + pktinfo->size_ip + pktinfo->size_tcp);
    pktinfo->size_payload = pkthdr->len - SIZE_ETHERNET - pktinfo->size_ip - pktinfo->size_tcp;
    pktinfo->ts = pkthdr->ts;
	inet_ntop(AF_INET, &(pktinfo->ip->ip_src), pktinfo->ip_addr_src, 16);
    inet_ntop(AF_INET, &(pktinfo->ip->ip_dst), pktinfo->ip_addr_dst, 16);

    if(pktinfo->size_payload <= 0){    	
		//fprintf(stderr, "DEBUG/ finish parse_packet(). pktinfo->size_payload <= 0\n");
    	return 1;
    }

    //SSL
    sniff_record *record = (sniff_record*) calloc(1, sizeof(sniff_record));
    memcpy(record, pktinfo->payload, 5);

    struct handshake_protocol *hs = (struct handshake_protocol*) calloc(1, sizeof(struct handshake_protocol));
    memcpy(hs, pktinfo->payload+5, 6);

    fprintf(stderr, "%ld.%06ld | %d | %d | ", pktinfo->ts.tv_sec, pktinfo->ts.tv_usec, pktinfo->size_ip, pktinfo->size_tcp);
    fprintf(stderr, "%s %u | %s %u | ", 
    	pktinfo->ip_addr_src, pktinfo->port_src, pktinfo->ip_addr_dst, pktinfo->port_dst);
    fprintf(stderr, "%s %s %d | ", content_type(record), version(record->major, record->minor), record->length);
    fprintf(stderr, "%s %d %s\n", handshake_type(hs), length_from_handshake_protocol(hs), version(hs->version.major, hs->version.minor));

	//fprintf(stderr, "DEBUG/ finish parse_packet().\n");

	return 0;
}