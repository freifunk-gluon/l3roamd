

#include "util.h"
#include <arpa/inet.h>
#include <stdio.h>
#include "l3roamd.h"
#include "error.h"

/* print a human-readable representation of an in6_addr struct to stdout
** */
static char ipaddress_buffer[INET6_ADDRSTRLEN+1];

const char *print_ip4(const struct in_addr *addr) {
	return inet_ntop(AF_INET, &(addr->s_addr), ipaddress_buffer, INET6_ADDRSTRLEN);
}
const char *print_ip(const struct in6_addr *addr) {
	return inet_ntop(AF_INET6, &(addr->s6_addr), ipaddress_buffer, INET6_ADDRSTRLEN);
}

void mapv4_v6(const struct in_addr *src, struct in6_addr *dst) {
	memcpy(dst, &l3ctx.clientmgr_ctx.v4prefix,12);
	memcpy(&(dst->s6_addr)[12], src, 4);
}


void log_debug(const char *format, ...) {
	if (!l3ctx.debug)
		return;
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

void log_verbose(const char *format, ...) {
	if (!l3ctx.verbose)
		return;
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

