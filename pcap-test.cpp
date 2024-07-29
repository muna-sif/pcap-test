#include <pcap.h>
#include <stdint.h>
#include <stdio.h>

struct libnet_ethernet_hdr {
	uint8_t ether_dhost[6];
	uint8_t ether_shost[6];
	uint16_t ether_type;
};

struct libnet_ipv4_hdr {
	uint8_t ip_hl : 4;
	uint8_t ip_v : 4;
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t flags;
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	uint8_t ip_src[4];
	uint8_t ip_dst[4];
};

struct libnet_tcp_hdr {
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
	uint8_t th_hl : 4;
	uint16_t flags;
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
	uint8_t data[20];
};

uint16_t my_ntohs(uint16_t n) {
    return ((n >> 8) & 0x00FF) |
           ((n << 8) & 0xFF00);
}

void print_tcp_data(libnet_tcp_hdr *p, uint8_t len) {
	uint8_t data = *p->data;

	printf("data(%d) : ", len);
	if (len > 20){
		len = 20;
		printf("\nlength restricted : 20bytes\n");
	}
	for (uint8_t i = 0; i < len; ++i) {
		printf("\\x%02x", p->data[i]);
	}
	printf("\n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
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

	uint8_t ipv4_len;
	uint8_t tcp_len;
	uint8_t data_len;

	if (res == 0) continue;
   	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		break;
	}

	libnet_ethernet_hdr* ether = (libnet_ethernet_hdr*)packet;
	if (ether->ether_type != 8) continue;

	libnet_ipv4_hdr* ipv4 = (libnet_ipv4_hdr*) (packet + 14);
	if (ipv4->ip_p != 6) continue;
	ipv4_len = ipv4->ip_hl * 4;

	libnet_tcp_hdr* tcp = (libnet_tcp_hdr*) (packet + 14 + ipv4_len);
	tcp_len = (tcp->flags) * 4;

	printf("\n%u bytes captured\n", header->caplen);

	uint8_t *smac = ether->ether_shost;
	uint8_t *dmac = ether->ether_dhost;
	printf("source mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
	 smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
	printf("dest mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
	 dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);
	
	uint8_t *ip_src = ipv4->ip_src;
	uint8_t *ip_dst = ipv4->ip_dst;
	printf("source ip : %u.%u.%u.%u\n",
	 ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
	printf("dest ip : %u.%u.%u.%u\n",
	 ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3]);
	
	uint16_t th_sport = my_ntohs(tcp->th_sport);
	uint16_t th_dport = my_ntohs(tcp->th_dport);
	printf("source port : %d\n", th_sport);
	printf("dest port : %d\n", th_dport);
	
	data_len = header->caplen - (14 + ipv4_len + tcp_len);
	print_tcp_data(tcp, data_len);
	}

	pcap_close(pcap);
	return 0;
}
