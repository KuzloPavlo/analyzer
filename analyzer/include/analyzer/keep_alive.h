#pragma once

int keep_alive_timeout_ms; // = 10000;

struct timespec calculate_timestamp(int time_ms);
struct timespec current_timestamp();