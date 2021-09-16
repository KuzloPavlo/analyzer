#pragma once
#include "session_tree.h"

#include <pcap.h>

void produce_sessions(pcap_t* descr, struct session_tree_node* session_set);
