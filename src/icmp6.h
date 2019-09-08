/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#pragma once

#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include "common.h"
#include "ipmgr.h"

typedef struct {
	char *clientif;
	int fd;  // used to learn addresses from NA and send solicitations
	int unreachfd6;  // used to send ICMP6 destination unreachable
	int unreachfd4;  // used to send ICMP destination unreachable
	int nsfd;	// used to read NS from clients to learn ip addresses
	unsigned int ifindex;
	bool ok;
	bool ndp_disabled;
	uint8_t mac[ETH_ALEN];
} icmp6_ctx;

void icmp6_handle_in(icmp6_ctx *ctx);
void icmp6_handle_ns_in(icmp6_ctx *ctx);
void icmp6_send_solicitation(icmp6_ctx *ctx, const struct in6_addr *addr);
void icmp6_init(icmp6_ctx *ctx);
void icmp6_interface_changed(icmp6_ctx *ctx, int type,
			     const struct ifinfomsg *msg);
int icmp6_send_dest_unreachable(const struct in6_addr *addr,
				const struct packet *data);
int icmp_send_dest_unreachable(const struct in6_addr *addr,
			       const struct packet *data);
void icmp6_setup_interface(icmp6_ctx *ctx);
