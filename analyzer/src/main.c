#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ether.h> 

#include "analyzer/session_consumer.h"
#include "analyzer/session_producer.h"
#include "analyzer/session_tree.h"
#include "analyzer/thread_context.h"

int main(int argc,char **argv)
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    pthread_t consumer_tid;


    struct session_tree_node session_set = create_tree();
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    struct thread_context th_context;
    th_context.session_set_ = &session_set;
    th_context.cond_ = &cond;
    th_context.lock_ = &lock;

    
    run_consumer(&th_context, &consumer_tid);

    /*
	pcap_if_t *interfaces,*temp;
    int i=0;
    
	if(!pcap_findalldevs(&interfaces,errbuf))
	{
		for(temp=interfaces;temp;temp=temp->next)
    {
        printf("\n%d  :  %s",i++,temp->name);
    }
	}*/

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
    if(pcap_compile(descr,&fp,"(tcp[13] == 2) or (tcp[13] == 18) or (tcp[13] == 16) or (tcp[13] == 4)",0,netp) == -1)
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

	produce_sessions(descr, &th_context);

    //TODO wait consumer thread here
  
    return 0;
}