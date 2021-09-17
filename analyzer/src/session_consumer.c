#include "analyzer/session_consumer.h"
#include "analyzer/session_tree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

void* consumer_thread_fn(void* session_set)
{
    consume_sessions(session_set);
}

void run_consumer(struct session_tree_node* session_set)
{
    pthread_t tid; 
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_create(&tid,&attr, consumer_thread_fn, session_set);
}

void check_session(struct session_tree_node* ses)
{
    // 3-way handshake richd
    if(!ses->session_.printed && ses->session_.got_syn_ack && ses->session_.sent_ack)
	{
		fprintf(stderr, "SUCCESS %s\n", ses->session_.src_dst);

        //TODO: remove session from the session_set
		ses->session_.printed = true;
	}

    // report failed on timeout
    if(!ses->session_.printed && !ses->session_.got_syn_ack)
	{
		fprintf(stderr, "FAILED %s\n", ses->session_.src_dst);

        //TODO: remove session from the session_set
		ses->session_.printed = true;
	}
}

void consume_sessions(struct session_tree_node* session_set)
{
    int keep_alive_timeout = 10;

    while(1)
    {
        // TODO add multithreading
        // wake up on event about shared data changes
        // or by keep_alive_timeout
        sleep(keep_alive_timeout);

        // maybe lock session_set access
        traversal_tree(session_set, check_session);
        // unlock
    }
}