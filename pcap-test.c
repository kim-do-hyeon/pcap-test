// Requirement : sudo apt-get install libpcap-dev libnet1-dev
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <libnet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
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

void print_hex(const u_char* data, int len) {
    for (int i = 0; i < len && i < 20; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
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

        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4));
		const u_char* payload = packet + sizeof(struct libnet_ethernet_hdr) + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);
		int payload_len = header->caplen - (payload - packet);
        printf("Ethernet Header\n");
		printf("   | - Soucre Information\n");
		printf("       | - Source IP Address       : %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("       | - Source MAC Address      : %02X:%02X:%02X:%02X:%02X:%02X \n",
               eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
               eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
		printf("       | - Source Port             : %u\n", ntohs(tcp_hdr->th_sport));
		printf("       | - Protocol                : %u\n", (unsigned int)ip_hdr->ip_p);
		printf("   |   \n");
		printf("   | - Desination Information\n");
		printf("       | - Destination IP Address  : %s\n", inet_ntoa(ip_hdr->ip_dst));
        printf("       | - Destination MAC Address : %02X:%02X:%02X:%02X:%02X:%02X \n",
               eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
               eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
		printf("       | - Destination Port        : %u\n", ntohs(tcp_hdr->th_dport));
		printf("    |    \n");
		printf("    | - Payload (first 20 bytes):\n");
		print_hex(payload, payload_len);
    }

    pcap_close(pcap);
    return 0;
}
