#pragma once

#include "timespec.h"
#include <stdint.h>
#include <sys/types.h>

struct packet {
	struct timespec timestamp;
	ssize_t len;
	uint8_t *data;
    uint8_t family;
};


struct in6_addr packet_get_src(const uint8_t packet[]);
struct in6_addr packet_get_dst(const uint8_t packet[]);
