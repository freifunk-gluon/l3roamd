/*
   Copyright (c) 2015, Nils Schneider <nils@nilsschneider.net>
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
   */

// TODO EPOLLOUT beim schreiben auf den tunfd

#include "version.h"
#include "vector.h"
#include "ipmgr.h"
#include "error.h"
#include "icmp6.h"
#include "routemgr.h"
#include "intercom.h"
#include "config.h"
#include "socket.h"
#include "prefix.h"
#include "l3roamd.h"
#include "types.h"
#include "alloc.h"
#include "util.h"

#define SIGTERM_MSG "Exiting. Removing routes for prefixes and clients.\n"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <fcntl.h>
#include <signal.h>


l3ctx_t l3ctx = {};


#include "util.h"
int tests_run = 0;
#define FAIL() printf("\nfailure in %s() line %d\n", __func__, __LINE__)
#define _assert(test) do { if (!(test)) { FAIL(); return 1; } } while(0)
#define _verify(test) do { int r=test(); tests_run++; if(r) return r; } while(0)


int test_ntohl_ipv4() {
	struct in_addr address;
	inet_pton(AF_INET, "1.2.3.4", &address );
	uint32_t reverse = ntohl(address.s_addr);
	
	char str[16];
	inet_ntop(AF_INET, &reverse, str, 16);
	printf("address: 1.2.3.4, reverse address: %s\n", str);
	if (strncmp(str,"4.3.2.1", 7) != 0 ) {
		FAIL();
		return 1;
	}
	return 0;
}

int all_tests() {

    _verify(test_ntohl_ipv4);
    return 0;
}

int main(int argc, char **argv) {
    int result = all_tests();
    if (result == 0)
        printf("PASSED\n");
    printf("Tests run: %d\n", tests_run);

    return result != 0;
}
