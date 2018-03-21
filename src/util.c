

#include "util.h"
#include <arpa/inet.h>
#include <stdio.h>

/* print a human-readable representation of an in6_addr struct to stdout
** */
void print_ip4(const struct in_addr *addr, const char *term) {
	char a1[INET_ADDRSTRLEN+1];
	inet_ntop(AF_INET, &(addr->s_addr), a1, INET_ADDRSTRLEN);
	printf("%s%s", a1, term);
}
void print_ip(const struct in6_addr *addr, const char *term) {
	char a1[INET6_ADDRSTRLEN+1];
	inet_ntop(AF_INET6, &(addr->s6_addr), a1, INET6_ADDRSTRLEN);
	printf("%s%s", a1, term);
}

