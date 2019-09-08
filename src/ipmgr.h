/*
 * Copyright (c) 2015, Nils Schneider <nils@nilsschneider.net>
 * Copyright (c) 2017,2018, Christof Schulze <christof@christofschulze.com>
 *
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include "taskqueue.h"
#include "time.h"
#include "types.h"
#include "vector.h"

#include <netinet/in.h>
#include <stdint.h>
#define PACKET_TIMEOUT \
	5  // drop packet after it sat in the unknown destination-queue for this
	   // amount of time
#define SEEK_INTERVAL 3  // retry a seek every n seconds

struct unknown_address {
	struct in6_addr address;
	taskqueue_t *check_task;
	VECTOR(struct packet) packets;
};

typedef struct {
	char *ifname;
	VECTOR(struct unknown_address) addrs;
	VECTOR(struct packet) output_queue;
	int fd;
} ipmgr_ctx;

struct ns_task {
	struct in6_addr address;
	struct timespec interval;
	ipmgr_ctx *ctx;
	int retries_left;
	bool force;
};

struct ip_task {
	struct in6_addr address;
	ipmgr_ctx *ctx;
};

bool ipmgr_init(ipmgr_ctx *ctx, char *tun_name, unsigned int mtu);
void ipmgr_route_appeared(ipmgr_ctx *ctx, const struct in6_addr *destination);
void ipmgr_handle_in(ipmgr_ctx *ctx, int fd);
void ipmgr_handle_out(ipmgr_ctx *ctx, int fd);
void ipmgr_seek_address(struct in6_addr *addr);
struct ns_task *create_ns_task(struct in6_addr *dst, struct timespec tv,
			       int retries, bool force);
void ipmgr_ns_task(void *d);
