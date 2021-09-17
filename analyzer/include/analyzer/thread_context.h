#pragma once

#include <pthread.h>
//#include <unistd.h>

struct thread_context
{
    struct session_tree_node* session_set_;
    pthread_cond_t* cond_;  // = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t* lock_; // = PTHREAD_MUTEX_INITIALIZER;
};