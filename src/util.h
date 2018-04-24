#pragma once
#include <netinet/in.h>
#include <stdbool.h>

void mapv4_v6(const struct in_addr *src, struct in6_addr *dst);
const char *print_ip4(const struct in_addr *addr);
const char* print_ip(const struct in6_addr *addr);
void log_verbose(const char *format, ...);
void log_debug(const char *format, ...);

bool address_is_ipv4(const struct in6_addr *ip);
