#pragma once
#include <netinet/in.h>
#include <stdbool.h>
#include <linux/rtnetlink.h>

struct in_addr extractv4_v6(const struct in6_addr *src);
void mapv4_v6(const struct in_addr *src, struct in6_addr *dst);
const char *print_ip4(const struct in_addr *addr);
const char* print_ip(const struct in6_addr* addr);
void log_verbose(const char *format, ...);
void log_debug(const char *format, ...);
void log_error(const char *format, ...);

void add_fd ( int efd, int fd, uint32_t events );
void del_fd ( int efd, int fd );
void interfaces_changed ( int type, const struct ifinfomsg *msg );

bool address_is_ipv4(const struct in6_addr *ip);
