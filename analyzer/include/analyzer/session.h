#pragma once
#include <stdbool.h>

struct session
{
    char src_dst[64]; //"255.255.255.255:65535 -> 255.255.255.255:65535";
    bool got_syn_ack;
    bool printed; 
};