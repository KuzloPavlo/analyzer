#pragma once

#include "thread_context.h"
#include <pthread.h>

void run_consumer(struct thread_context* th_context, pthread_t* tid);

void consume_sessions(struct thread_context* th_context);