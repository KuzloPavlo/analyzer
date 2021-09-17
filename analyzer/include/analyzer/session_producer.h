#pragma once
#include "thread_context.h""

#include <pcap.h>

void produce_sessions(pcap_t* descr, struct thread_context* th_context);
