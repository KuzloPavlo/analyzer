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

	struct session session;
	
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

				sprintf(session.src_dst, "%s -> %s", src, dst);
				session.printed = false;
				session.got_syn_ack = false;

				session_set = add_node(session_set, session);

				fprintf(stderr, "SYN %s\n", session.src_dst);
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

				sprintf(session.src_dst, "%s -> %s", src, dst);

				struct session_tree_node* res =  find_node(session_set, session.src_dst);

				if(res)
				{
					res->session_.got_syn_ack = true;
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

				sprintf(session.src_dst, "%s -> %s", src, dst);

				//TODO: remove session from the session_set
				struct session_tree_node* res =  find_node(session_set, session.src_dst);

				if(res && !res->session_.printed && res->session_.got_syn_ack)
				{
					fprintf(stderr, "SUCCESS %s\n", res->session_.src_dst);
					res->session_.printed = true;
				}
			}

			if(tcphdr->th_flags == 4)
			{
				fprintf(stderr
						,"RST %s:%d -> %s:%d\n"
						, inet_ntoa(iphdr->ip_src), ntohs(tcphdr->th_sport)
						, inet_ntoa(iphdr->ip_dst), ntohs(tcphdr->th_dport));
			}
		}
	}
}