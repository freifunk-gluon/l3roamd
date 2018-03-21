#pragma once
#include <netinet/in.h>

void print_ip4(const struct in_addr *addr, const char *term);
void print_ip(const struct in6_addr *addr, const char *term);

