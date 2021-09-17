#include "analyzer/session_producer.h"
#include "analyzer/session_tree.h"


#include <netinet/tcp.h>
#include <netinet/ip.h>

void produce_sessions(pcap_t* descr, struct thread_context* th_context)
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
				th_context->session_set_ = add_node(th_context->session_set_, src_dst);
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

				struct session_tree_node* res =  find_node(th_context->session_set_, src_dst);

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

				struct session_tree_node* res =  find_node(th_context->session_set_, src_dst);

				if(res && !res->session_.printed && res->session_.got_syn_ack)
				{
					// lock session_set access
					res->session_.sent_ack = true;
					// unlock

					pthread_mutex_lock(th_context->lock_);
					pthread_cond_signal(th_context->cond_);
					pthread_mutex_unlock(th_context->lock_);
				}
			}

			if(tcphdr->th_flags == 4)
			{
				// TODO: add check for reset intialized by remote peer
			}
		}
	}
}