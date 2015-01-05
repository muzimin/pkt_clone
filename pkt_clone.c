#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <netdb.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>

/* 802.1Q VLAN tags are 4 bytes long. */
#define VLAN_HDRLEN 4

/* This is the decimal equivalent of the VLAN tag's ether frame type */
#define VLAN_ETHERTYPE 33024

char *interface = NULL;
char *filter = NULL;
u_int8_t ttl = 64;
u_int8_t min_ttl = 15;


pcap_t *handle = NULL;
unsigned short checksum(unsigned short *buf,int nword)
{
    unsigned long sum;
    
    for(sum=0;nword>0;nword--)
        sum += *buf++;
    sum = (sum>>16) + (sum&0xffff);
    sum += (sum>>16);
    
    return ~sum;
}

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	struct ether_header *ethh;		/* net/ethernet.h */
	u_char * my_packet;

	if (header->len != header->caplen) 
		return;

	my_packet = (u_char *)packet;

	/* Extract the ethernet header from the packet. */
	ethh = (struct ether_header*) my_packet;
	if(ntohs(ethh->ether_type) == VLAN_ETHERTYPE) { /* strip the vlan tags */
		ethh = (struct ether_header*) (packet + VLAN_HDRLEN);
		my_packet += VLAN_HDRLEN;
	}

	if(ntohs(ethh->ether_type) != ETHERTYPE_IP) 
		return;

	struct iphdr *iph;			/* netinet/ip.h */
	iph = (struct iphdr*)(my_packet + sizeof(struct ether_header));

	if(iph->ttl != ttl || iph->ttl <min_ttl) 
		return;

	/* break loop */



#if 0
	--iph->ttl;
	iph->check = 0;
	iph->check = checksum((unsigned short*)iph,10);


	//XXX check udp
	struct udphdr *udp;
	udp = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
	udp->check = 0;
#endif

	// TLL -- & change check sum 
	u_int32_t check = iph->check;
	check += htons(0x0100);
	iph->check = check + (check>=0xFFFF);
	--iph->ttl;

#if 0

	struct sockaddr_in to_addr;
	int bytes_sent;
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	int one = 1;
	const int *val = &one;

	if (sock < 0) {
		fprintf(stderr, "Error creating socket");
		return;
	}

	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0){
		fprintf(stderr, "Error at setsockopt()");
		return;
	}



	uint16_t packlen = ntohs(iph->tot_len);
	memset((void *) &to_addr, 0, sizeof(struct sockaddr_in));
	to_addr.sin_family = AF_INET;
	to_addr.sin_addr.s_addr = iph->daddr;
	to_addr.sin_port = htons(53);

	bytes_sent = sendto(sock, iph, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
	if(bytes_sent < 0)
		fprintf(stderr, "Error sending data");


	//	usleep(200*1000);
	//	pcap_inject(handle, packet, header->len );
	//	printf("len:%d, caplen:%d \n", header->len, header->caplen );

	close(sock);
#else

	int ret = pcap_inject(handle, packet, header->len); 
	if(ret == -1)  
		printf("error: %s\n",pcap_geterr(handle)); 

#endif


}

void run_filter()
{
	char errbuf[PCAP_ERRBUF_SIZE]; /* pcap error messages buffer */
	struct bpf_program fp;         /* compiled filter */
//	pcap_t *handle;


	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	handle = pcap_open_live(interface, /* device to sniff on */
			1500,                    /* maximum number of bytes to capture per packet */
			1,                       /* promisc - 1 to set card in promiscuous mode, 0 to not */
			0,                       /* to_ms - amount of time to perform packet capture in milliseconds */
						/* 0 = sniff until error */
			errbuf);                 /* error message buffer if something goes wrong */

	if (handle == NULL)   /* there was an error */
	{
		fprintf (stderr, "%s", errbuf);
		exit (1);
	}

	if (strlen(errbuf) > 0)
	{
		fprintf (stderr, "Warning: %s", errbuf);  /* a warning was generated */
		errbuf[0] = 0;    /* reset error buffer */
	}


	/* compiles the filter expression */
	if(pcap_compile(handle, &fp, filter, 0, 0) == -1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		exit(-1);
	}

	/* applies the filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
		exit(-1);
	}

	/* loops through the packets */
	pcap_loop(handle, -1, handle_packet, NULL);

	/* frees the compiled filter */
	pcap_freecode(&fp);

	/* closes the handler */
	pcap_close(handle);
}


int main(int argc, char **argv){

	if ( argc == 3 ) {
		interface = argv[1];
		filter = argv[2];
	}
	else {
		fprintf(stderr, "\nUsage: %s interface 'filter'\n\n", argv[0]);
		fprintf(stderr, "e.g.: %s eth0 'udp and dst port domain'\n\n", argv[0]);
		exit(-1);
	} 

	run_filter();
 
	exit(0);
}
