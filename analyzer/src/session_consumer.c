#include "analyzer/session_consumer.h"
#include "analyzer/session_tree.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void check_session(struct session_tree_node* ses)
{
    // if(!ses->session_.printed && ses->session_.got_syn_ack)
	// {
	// 	fprintf(stderr, "SUCCESS %s\n", ses->session_.src_dst);
	// 	ses->session_.printed = true;
	// }

    if(!ses->session_.printed && !ses->session_.got_syn_ack)
	{
		fprintf(stderr, "FAILED %s\n", ses->session_.src_dst);
		ses->session_.printed = true;
	}

    fprintf(stderr, "consume_sessions %s\n", ses->session_.src_dst);
}

void consume_sessions(struct session_tree_node* session_set)
{
    while(1)
    {
        // TODO add event
        sleep(10);

        fprintf(stderr, "consume_sessions %d \n",session_set );
        traversal_tree(session_set, check_session);
    }
}