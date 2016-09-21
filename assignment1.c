#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	struct ether_header *ether;
	struct ip *ipv4;
	struct tcphdr *tcp;
	int ip_hl, tcp_hl, total_hl, data_size;
	int i;

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
	

	while(1)
	{
		packet = pcap_next(handle, &header);

		if(packet != NULL)
		{
			printf("\n\n");
			ether = (struct ether_header*)packet;
			printf("src mac: %s\n", ether_ntoa(ether->ether_shost));
			printf("dst mac: %s\n", ether_ntoa(ether->ether_dhost));

			//printf("ethernet type: %x\n", ether->ether_type);
			//printf("ethernet type: %x\n", ntohs(ether->ether_type));
			if(ntohs(ether->ether_type) != ETHERTYPE_IP)
				continue;

			ipv4 = (struct ip*)(packet+14);
			printf("src ip: %s\n", inet_ntoa(ipv4->ip_src));
			printf("dst ip: %s\n", inet_ntoa(ipv4->ip_dst));

			//printf("ip type: %x\n", ipv4->ip_p);
			//printf("ip type: %x\n", ntohs(ipv4->ip_p));
			if(ipv4->ip_p != IPPROTO_TCP)
				continue;

			ip_hl = 4*ipv4->ip_hl;
			tcp = (struct tcphdr*)(packet+14+ip_hl);
			printf("src port: %d\n",ntohs(tcp->th_sport));
			printf("dst port: %d\n",ntohs(tcp->th_dport));

			tcp_hl = 4*tcp->th_off;

			total_hl = 14 +ip_hl + tcp_hl;
			data_size = header.caplen - total_hl;
			for(i=total_hl;i<header.caplen;i++)
				printf("hexa decimal value: %02x\n",packet[i]);

		}
	}
	
	return(0);
}
