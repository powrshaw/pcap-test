#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>


void mac_parse(const u_char* packet);
void ip_parse(const u_char* packet);
void pdata_parse(const u_char* packet);

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		printf("%u bytes captured\n", header->caplen);
		mac_parse(packet);
		ip_parse(packet);
		pdata_parse(packet);
	}

	pcap_close(pcap);
}

void mac_parse(const u_char* packet)
{
	struct libnet_ethernet_hdr * mac_parse = (struct libnet_ethernet_hdr*)(packet);
	uint16_t ether_type;
	printf( "dst MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
			mac_parse->ether_dhost[0],
			mac_parse->ether_dhost[1],
			mac_parse->ether_dhost[2],
			mac_parse->ether_dhost[3],
			mac_parse->ether_dhost[4],
			mac_parse->ether_dhost[5]);

	// print src mac address
	printf( "src MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
			mac_parse->ether_shost[0],
			mac_parse->ether_shost[1],
			mac_parse->ether_shost[2],
			mac_parse->ether_shost[3],
			mac_parse->ether_shost[4],
			mac_parse->ether_shost[5]);


}

void ip_parse(const u_char* packet)
{
	struct libnet_ipv4_hdr * ip_parse = (struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr));

	uint32_t src_ip_n = ip_parse -> ip_src.s_addr;
	uint32_t dst_ip_n = ip_parse -> ip_dst.s_addr;


	/*int v;
	  unsigned char* temp = &src_ip_n;
	  for(int i=0;i<2;i++) {
	  v = *(temp+i);
	 *(temp+i)=*(temp+3-i);
	 *(temp+3-i) = v;

	 }
*/

	/*uint32_t src_ip_h = ntohl(src_ip_n);
	uint32_t dst_ip_h = ntohl(dst_ip_n);
	 */
	uint8_t src_ip_h[] = {(src_ip_n & 0xff)
			, ((src_ip_n >> 8) & 0xff)
			, ((src_ip_n >> 16) & 0xff)
			, ((src_ip_n >> 24) & 0xff) 
	};
	uint8_t dst_ip_h[] = {(dst_ip_n & 0xff)
			, ((dst_ip_n >> 8) & 0xff)
			, ((dst_ip_n >> 16) & 0xff)
			, ((dst_ip_n >> 24) & 0xff) 
	};


	printf("src IP : ");
	for(int i=0;i<4;i++)
	{
		printf("%d",*(src_ip_h+i));
		if(i!=3)
			printf(".");
		else
			printf("\n");
	}	    

	printf("dst IP : ");
	for(int i=0;i<4;i++)
	{
		printf("%d",*(dst_ip_h+i));
		if(i!=3)
			printf(".");
		else
			printf("\n");
	}	    
	return;
}


void pdata_parse(const u_char* packet)
{
	struct libnet_tcp_hdr * parse = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr)
								             + sizeof(struct libnet_ipv4_hdr));

	uint16_t src_port_n = parse -> th_sport;
	uint16_t dst_port_n = parse -> th_dport;

	uint16_t src_port_h = ntohs(src_port_n);
	uint16_t dst_port_h = ntohs(dst_port_n);

	printf("src PORT : %d\n", src_port_h);
	printf("dst PORT : %d\n", dst_port_h);


	uint64_t* d_off = (uint64_t*)(packet + sizeof(struct libnet_ethernet_hdr)
						       + sizeof(struct libnet_ipv4_hdr)
						       + sizeof(struct libnet_tcp_hdr));

	if((*d_off) == 0)
		printf("NO DATA");
	else
	{
		printf("Data : ");
		for(int i=0;i<2;i++)		
			printf("%#x ", *(d_off+i));
	}	
	printf("\n\n");
	return;
}
