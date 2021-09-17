#include "analyzer/keep_alive.h"

#include <sys/time.h>
#include <stdio.h>
#include <time.h>

extern int keep_alive_timeout_ms = 10000;

struct timespec calculate_timestamp(int time_ms)
{
    struct timeval tv;
    struct timespec ts;

    gettimeofday(&tv, NULL);
    ts.tv_sec = time(NULL) + time_ms / 1000;
    ts.tv_nsec = tv.tv_usec * 1000 + 1000 * 1000 * (time_ms % 1000);
    ts.tv_sec += ts.tv_nsec / (1000 * 1000 * 1000);
    ts.tv_nsec %= (1000 * 1000 * 1000);

    return ts;
}

struct timespec current_timestamp()
{
    struct timespec cr;
    
    clock_gettime(CLOCK_REALTIME, &cr);

    return cr;
}