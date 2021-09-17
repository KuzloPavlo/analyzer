#pragma once
#include <stdbool.h>
#include <time.h>

struct session
{
    char src_dst[64]; //"255.255.255.255:65535 -> 255.255.255.255:65535";
    bool got_syn_ack;
    bool sent_ack; 
    bool printed; 
    struct timespec expired_at_; 
};