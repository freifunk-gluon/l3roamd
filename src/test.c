/*
 * Copyright (c) 2015, Nils Schneider <nils@nilsschneider.net>
 *
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

// TODO EPOLLOUT beim schreiben auf den tunfd

#include "alloc.h"
#include "config.h"
#include "error.h"
#include "icmp6.h"
#include "icmp6.h"
#include "intercom.h"
#include "ipmgr.h"
#include "l3roamd.h"
#include "packet.h"
#include "prefix.h"
#include "routemgr.h"
#include "socket.h"
#include "types.h"
#include "util.h"
#include "vector.h"
#include "version.h"

#define SIGTERM_MSG "Exiting. Removing routes for prefixes and clients.\n"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

l3ctx_t l3ctx = {};

#include "util.h"
int tests_run = 0;
#define FAIL() printf("\nfailure in %s() line %d\n", __func__, __LINE__)
#define _assert(test)             \
	do {                      \
		if (!(test)) {    \
			FAIL();   \
			return 1; \
		}                 \
	} while (0)
#define _verify(test)             \
	do {                      \
		int r = test();   \
		tests_run++;      \
		if (r)            \
			return r; \
	} while (0)

int test_vector_init() {
	VECTOR(int) v;
	// initializing vector with bogus values
	v.desc.length = 5;
	v.desc.allocated = 12;

	VECTOR_INIT(v);
	_assert(v.desc.length == 0);
	_assert(v.desc.allocated == 0);

	VECTOR_ADD(v, 12);
	_assert(v.desc.length == 1);

	return 0;
}

int test_ntohl_ipv4() {
	struct in_addr address;
	inet_pton(AF_INET, "1.2.3.4", &address);
	uint32_t reverse = ntohl(address.s_addr);

	char str[16];
	inet_ntop(AF_INET, &reverse, str, 16);
	printf("address: 1.2.3.4, reverse address: %s\n", str);

	_assert(strncmp(str, "4.3.2.1", 7) == 0);

	return 0;
}
int test_mac() {
	uint8_t mac1[ETH_ALEN] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa};
	uint8_t mac2[ETH_ALEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
	uint8_t mac3[ETH_ALEN] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5};
	char str[120];
	snprintf(str, 120, "testing mac address to string conversion for: %s, %s, %s", print_mac(mac1), print_mac(mac2),
		 print_mac(mac3));
	printf("%s\n", str);
	_assert(strncmp(str,
			"testing mac address to string conversion for: "
			"ff:fe:fd:fc:fb:fa, 00:01:02:03:04:05, "
			"a0:a1:a2:a3:a4:a5",
			120) == 0);

	return 0;
}

int test_icmp_dest_unreachable4() {
	struct in6_addr addr = {};

	struct packet data = {};
	data.len = 12;
	uint8_t actualdata[data.len];
	memcpy(actualdata, "xxxxxxxxxxxxx", data.len);
	data.data = actualdata;
	data.family = 4;

	if (inet_pton(AF_INET6, "::ffff:192.168.12.15", &addr) != 1)
		return 1;

	l3ctx.clientif_set = true;
	l3ctx.icmp6_ctx.clientif = strdupa("tst1");

	icmp6_init(&l3ctx.icmp6_ctx);

	return icmp_send_dest_unreachable(&addr, &data);
}

int all_tests() {
	_verify(test_vector_init);
	_verify(test_ntohl_ipv4);
	_verify(test_mac);
	_verify(test_icmp_dest_unreachable4);
	return 0;
}

int main(__attribute__((__unused__)) int argc, __attribute__((__unused__)) char **argv) {
	int result = all_tests();
	if (result == 0)
		printf("PASSED\n");
	else
		printf("FAILED\n");
	printf("Tests run: %d\n", tests_run);

	return result != 0;
}
