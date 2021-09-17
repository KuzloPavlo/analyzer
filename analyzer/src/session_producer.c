#include "analyzer/session_producer.h"

#include <netinet/tcp.h>
#include <netinet/ip.h>

void produce_sessions(pcap_t* descr, struct session_tree_node* session_set)
{
    const u_char* packet = NULL;
	struct pcap_pkthdr pkthdr;
	struct ip *iphdr = NULL;
	struct tcphdr* tcphdr = NULL;

	char src[24]; // = "255.255.255.255:65535";
	char dst[24]; // = "255.255.255.255:65535";
	char src_dst[64]; // = "255.255.255.255:65535 -> 255.255.255.255:65535";

	while(1)
	{
		packet = pcap_next(descr,&pkthdr);

		if(packet)
		{
			iphdr = (struct ip *)(packet + 14);
			tcphdr = (struct tcphdr *)(packet + 14 +20); 

			// send:SYN
			if(tcphdr->th_flags == 2)
			{
				sprintf(src
						,"%s:%d"
						, inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
				sprintf(dst
						,"%s:%d"
						, inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));

				sprintf(src_dst, "%s -> %s", src, dst);
				
				// maybe lock session_set access 
				session_set = add_node(session_set, src_dst);
				// unlock
			}

			// recv:SYN/ACK
			if(tcphdr->th_flags == 18)
			{
				sprintf(src
						,"%s:%d"
						, inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
				sprintf(dst
						,"%s:%d"
						, inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));

				sprintf(src_dst, "%s -> %s", src, dst);

				struct session_tree_node* res =  find_node(session_set, src_dst);

				if(res)
				{
					// lock session_set access
					res->session_.got_syn_ack = true;
					// unlock
				}
			}

			// send:ACK
			if(tcphdr->th_flags == 16)
			{
				sprintf(src
						,"%s:%d"
						, inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport));
				sprintf(dst
						,"%s:%d"
						, inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));

				sprintf(src_dst, "%s -> %s", src, dst);

				struct session_tree_node* res =  find_node(session_set, src_dst);

				if(res && !res->session_.printed && res->session_.got_syn_ack)
				{
					// lock session_set access
					res->session_.sent_ack = true;
					// unlock

					// TODO send event to consumer about shared data changes
				}
			}

			if(tcphdr->th_flags == 4)
			{
				// TODO: add check for reset intialized by remote peer
			}
		}
	}
}