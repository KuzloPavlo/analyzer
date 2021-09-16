#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 

#include <netinet/tcp.h>
#include <netinet/ip.h>


int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;
	const u_char* packet = NULL;
	struct pcap_pkthdr pkthdr;
	struct ip *iphdr = NULL;
	struct tcphdr* tcphdr = NULL;

    /* grab a device to peak into... */
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
		printf("%s\n",errbuf); 
		exit(1); 
	}

    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    if(descr == NULL)
    { 
		printf("pcap_open_live(): %s\n",errbuf); 
		exit(1); 
	}

    /* Lets try and compile the program.. non-optimized */
    if(pcap_compile(descr,&fp,"(tcp[13] == 2) or (tcp[13] == 18) or (tcp[13] == 16)",0,netp) == -1)
    {
		 fprintf(stderr,"Error calling pcap_compile\n"); 
		 exit(1); 
	}

    /* set the compiled program as the filter */
    if(pcap_setfilter(descr,&fp) == -1)
    { 
		fprintf(stderr,"Error setting filter\n"); 
		exit(1); 
	}
    
	while(1)
	{
		packet = pcap_next(descr,&pkthdr);

		if(packet)
		{
			iphdr = (struct ip *)(packet + 14);
			tcphdr = (struct tcphdr *)(packet + 14 +20); 

			if(tcphdr->th_flags == 2)
			{
				fprintf(stderr
						,"SYN %s:%d -> %s:%d\n"
						, inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport)
						, inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
			}

			if(tcphdr->th_flags == 18)
			{
				fprintf(stderr
						,"SYN/ACK %s:%d -> %s:%d\n"
						, inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport)
						, inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
			}

			if(tcphdr->th_flags == 16)
			{
				fprintf(stderr
						,"SUCCESS %s:%d -> %s:%d\n"
						, inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport)
						, inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
			}
		}
	}
    return 0;
}