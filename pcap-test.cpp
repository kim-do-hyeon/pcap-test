#include <pcap.h>
#include <stdio.h>

struct Param {
	char *dev{nullptr};

	bool parse(int argc, char* argv[]) {
		if (argc != 2) {
			usage();
			return false;
		}
		dev = argv[1];
		return true;
	}

	static void usage() {
		printf("syntax: pcap-test <interface>\n");
		printf("sample: pcap-test wlan0\n");
	}
};


int main(int argc, char* argv[]) {
	Param param;
	if (!param.parse(argc, argv))
		return -1;

	char* dev = param.dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);
    }

    pcap_close(pcap);
}
