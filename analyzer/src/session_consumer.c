#include "analyzer/session_consumer.h"
#include "analyzer/session_tree.h"
#include "analyzer/keep_alive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void* consumer_thread_fn(void* th_context)
{
    consume_sessions(th_context);
}

void run_consumer(struct thread_context* th_context, pthread_t* tid)
{
    pthread_create(tid,NULL, consumer_thread_fn, th_context);
}

void check_session(struct session_tree_node* ses)
{
    // 3-way handshake richd
    if(!ses->session_.printed && ses->session_.got_syn_ack && ses->session_.sent_ack)
	{
        //TODO: remove session from the session_set
		ses->session_.printed = true;

		fprintf(stderr, "SUCCESS %s\n", ses->session_.src_dst);
	}

    // report failed on timeout
    if( !ses->session_.printed 
        && !ses->session_.got_syn_ack 
        && (current_timestamp().tv_sec > ses->session_.expired_at_.tv_sec))
	{
        //TODO: remove session from the session_set
		ses->session_.printed = true;

		fprintf(stderr, "FAILED %s\n", ses->session_.src_dst);
	}
}

void consume_sessions(struct thread_context* th_context)
{
    while(1)
    {
        pthread_mutex_lock(th_context->lock_);
        
        struct timespec ts = calculate_timestamp(keep_alive_timeout_ms);

        int n = pthread_cond_timedwait(th_context->cond_, th_context->lock_, &ts);
        if(n == 0)
        {
            //TODO Change logic for proccessing the changed session
        }
        else if (n == ETIMEDOUT)
        {
            
        }
        
        // maybe lock session_set access
        traversal_tree(th_context->session_set_, check_session);
        // unlock

        pthread_mutex_unlock(th_context->lock_);
    }
}