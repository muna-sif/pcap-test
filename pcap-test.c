#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[6];
	u_int8_t  ether_shost[6];
    u_int16_t ether_type;
};

struct libnet_ipv4_hdr
{
	u_int8_t ip_hl:4;      /* header length */
    u_int8_t ip_v:4;       /* version */
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_flag;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    uint8_t ip_src[4];
	uint8_t	ip_dst[4];		/* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_len : 4;        /* data offset */
    u_int8_t  th_flags : 12;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;	/* urgent pointer */
	uint8_t data[10];
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

void print_mac(libnet_ethernet_hdr *p){
	uint8_t *dhost = p->ether_dhost;
	uint8_t *shost = p->ether_shost;

	printf("dest mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
		   	dhost[0], dhost[1], dhost[2], dhost[3], dhost[4], dhost[5]);
	printf("source mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
			shost[0], shost[1], shost[2], shost[3], shost[4], shost[5]);
}

void print_ip(libnet_ipv4_hdr *p) {
	uint8_t *ip_src = p->ip_src;
	uint8_t *ip_dst = p->ip_dst;

	printf("source ip : %u.%u.%u.%u\n",
		   	ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
	printf("destination ip : %u.%u.%u.%u\n",
		   	ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
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
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
	}
	pcap_close(pcap);
}
