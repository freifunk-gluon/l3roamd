/*
   Copyright (c) 2017,2018, Christof Schulze <christof.schulze@gmx.net>
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

#include "clientmgr.h"
#include "routemgr.h"
#include "icmp6.h"
#include "timespec.h"
#include "error.h"
#include "l3roamd.h"
#include "util.h"
#include "ipmgr.h"
#include "prefix.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>

/* Static functions used only in this file. */
static const char *state_str(enum ip_state state);

void mac_addr_n2a(char *mac_addr, unsigned char *arg) {
	int i, l;

	l = 0;
	for (i = 0; i < 6; i++) {
		if (i == 0) {
			sprintf(mac_addr+l, "%02x", arg[i]);
			l += 2;
		} else {
			sprintf(mac_addr+l, ":%02x", arg[i]);
			l += 3;
		}
	}
}


//struct in6_addr node_client_mcast_ip_from_mac(uint8_t mac[6]) {
//	char addr_str[INET6_ADDRSTRLEN];
//	snprintf(&addr_str[0], INET6_ADDRSTRLEN, "ff02::1:ff%02x:%02x%02x", mac[3], mac[4], mac[5]);
//}

int address_allocate(struct in_addr *addrp, unsigned char *mac) {
	// Find a free address like dnsmasq would. There is no collision checking
	// can we actually query dnsmasq for the address it sends out?
	struct in_addr start, addr;
	int i, pass;
	unsigned int j;

	/* hash mac: use the SDBM hashing algorithm. */
	for (j = 0, i = 0; i < 6; i++)
		j = mac[i] + (j << 6) + (j << 16) - j;

	/* j == 0 is marker */
	if (j == 0)
		j = 1;

	for (pass = 0; pass <= 1; pass++) {
		start.s_addr = htonl(ntohl(l3ctx.clientmgr_ctx.start.s_addr) + ((j) % (1 + ntohl(l3ctx.clientmgr_ctx.end.s_addr) - ntohl(l3ctx.clientmgr_ctx.start.s_addr))));

		/* iterate until we find a free address. */
		addr = start;

		do {
			/* Addresses which end in .255 and .0 will not be allocated by dnsmasq*/	    
			if ((ntohl(addr.s_addr) & 0xff) != 0xff && ((ntohl(addr.s_addr) & 0xff) != 0x0))
			{
				print_ip4(&addr, " <<< generated an IP-address for client\n");
				*addrp = addr;
				return 1;
			}
			else {
				// We could check if the address is used already here but would probably get in conflict with dnsmasq
				printf("WARNING address ends with 0 or ff\n");
				print_ip4(&addr, "\n");
				addr.s_addr = htonl(ntohl(addr.s_addr) + 1);

				if (addr.s_addr == htonl(ntohl(l3ctx.clientmgr_ctx.end.s_addr) + 1))
					addr = start;
			}
		} while (addr.s_addr != start.s_addr);
	}

	return 0;
}


struct in6_addr mac2specialipv6(uint8_t mac[6]) {
	// generate the node-client-ip based on the scheme: CLIENTNODEIPPREFIX/48 + CLIENTMAC + CLIENTIP
	struct in6_addr address = l3ctx.clientmgr_ctx.node_client_prefix.prefix;
	struct in_addr v4addr;

	address_allocate(&v4addr, mac);

	for (int i = 0;i<6;i++)
		address.s6_addr[6+i] = mac[i];

	for (int i=0;i<4;i++)
		address.s6_addr[12+i] = (v4addr.s_addr >> (i*8) ) & 0xff;

	return address;
}

void print_client(struct client *client) {
	char ifname[IFNAMSIZ];
	char mac_str[18];

	mac_addr_n2a(mac_str, client->mac);
	printf("Client %s", mac_str);

	if (client_is_active(client))
		printf(" (active");
	else
		printf(" (______");

	if (client->ifindex != 0) {
		if_indextoname(client->ifindex, ifname);
		printf(", %s/%i)\n", ifname, client->ifindex);
	} else {
		printf(")\n");
	}

	for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
		struct client_ip *addr = &VECTOR_INDEX(client->addresses, i);

		char str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr->addr, str, INET6_ADDRSTRLEN);

		switch (addr->state) {
			case IP_INACTIVE:
				printf("  %s  %s\n", state_str(addr->state), str);
				break;
			case IP_ACTIVE:
				printf("  %s    %s (%ld.%.9ld)\n", state_str(addr->state), str, addr->timestamp.tv_sec, addr->timestamp.tv_nsec);
				break;
			case IP_TENTATIVE:
				printf("  %s %s (tries left: %d)\n", state_str(addr->state), str, addr->tentative_retries_left);
				break;
			default:
				exit_error("Invalid IP state - exiting due to memory corruption");
		}
	}
}

bool ip_is_active(const struct client_ip *ip) {
	if (ip->state == IP_ACTIVE || ip->state == IP_TENTATIVE)
		return true;
	return false;
}

/** Check whether a client is currently active.
    A client is considered active when at least one of its IP addresses is
    currently active or tentative.
    */
bool client_is_active(const struct client *client) {
	for (int i = VECTOR_LEN(client->addresses)-1;i>=0; i--) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

		if (ip_is_active(ip))
			return true;
	}

	return false;
}


int bind_to_address(struct in6_addr *address) {
	int fd;
	rtnl_add_address(&l3ctx.routemgr_ctx, address);

	struct sockaddr_in6 server_addr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(INTERCOM_PORT),
		.sin6_addr = *address,
	};

	fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("creating socket for listening on node-client-IP failed:");
		exit_error("creating socket for intercom on node-client-IP");
	}

	int one = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one , sizeof(one)) < 0 ) {
		perror("could not set SO_REUSEADDR");
		exit_error("setsockopt: SO_REUSEADDR");
	}
	if (setsockopt(fd, SOL_IP, IP_FREEBIND, &one , sizeof(one)) < 0 ) {
		perror("could not set IP_FREEBIND");
		exit_error("setsockopt: IP_FREEBIND");
	}

	if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		printf("Could not bind to socket %i on special ip for address: ", fd);
		print_ip(address, " exiting.\n");
		exit_error("bind socket to node-client-IP failed.");
	}

	add_fd(l3ctx.efd, fd, EPOLLIN);
	return fd;
}


/** Adds the special node client IP address.
*/
void add_special_ip(clientmgr_ctx *ctx, struct client *client) {
	if (client == NULL) // this can happen if the client was removed before the claim cycle was finished
		return;

	if (client->node_ip_initialized) {
		char mac_str[18];
		mac_addr_n2a(mac_str, client->mac);
		printf("we already initialized the special client [%s] not doing it again\n", mac_str);
		return;
	}

	struct in6_addr address = mac2specialipv6(client->mac);
	client->fd = bind_to_address(&address);

	// TODO: remove the next 2 lines after everyone has upgraded
	address = mac2ipv6(client->mac, &ctx->node_client_prefix);
	client->fd2 = bind_to_address(&address);

	client->node_ip_initialized = true;
}

/** close and remove an fd from a client
**/
void close_client_fd(int *fd) {
	if (*fd>0) {
		del_fd(l3ctx.efd, *fd);
		while (close(*fd)) {
			printf("could not close client fd %i", *fd);
			perror("close ");
		}
		*fd=-1;
	}
}

/** Removes the special node client IP address.
*/
void remove_special_ip(clientmgr_ctx *ctx, struct client *client) {
	struct in6_addr address = mac2specialipv6(client->mac);
	printf("Removing special address: ");
	print_ip(&address, "\n");
	close_client_fd(&client->fd);
	rtnl_remove_address(CTX(routemgr), &address);

	// TODO: remove the next 3 lines after everyone has upgraded
	address = mac2ipv6(client->mac, &ctx->node_client_prefix);
	close_client_fd(&client->fd2);
	rtnl_remove_address(CTX(routemgr), &address);

	client->node_ip_initialized = false;
}

/** Given an IP address returns the client-object of a client.
    Returns NULL if no object is found.
    */
struct client_ip *get_client_ip(struct client *client, const struct in6_addr *address) {
	for (int i = VECTOR_LEN(client->addresses)-1;i>=0; i--) {
		struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

		if (memcmp(address, &e->addr, sizeof(struct in6_addr)) == 0)
			return e;
	}

	return NULL;
}

/** Removes an IP address from a client. Safe to call if the IP is not
    currently present in the clients list.
    */
void delete_client_ip(struct client *client, const struct in6_addr *address, bool cleanup) {
	for (int i = VECTOR_LEN(client->addresses)-1;i>=0; i--) {
		struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

		if (memcmp(address, &e->addr, sizeof(struct in6_addr)) == 0) {
			client_ip_set_state(&l3ctx.clientmgr_ctx, client, get_client_ip(client,address), IP_INACTIVE);
			if (cleanup)
				VECTOR_DELETE(client->addresses, i);
		}
	}

	char str[INET6_ADDRSTRLEN+1];
	inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
	printf("\x1b[31mDeleted IP %s from client %zi addresses are still assigned\x1b[0m ", str, VECTOR_LEN(client->addresses));
	print_client(client);

}

/** Adds a route.
*/
void client_add_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
	routemgr_insert_neighbor(&l3ctx.routemgr_ctx, client->ifindex, &ip->addr , client->mac);
	printf("adding route for "); 
	print_ip(&ip->addr, "");
	if (clientmgr_is_ipv4(ctx, &ip->addr)) {
		printf(" (IPv4)\n");
		struct in_addr ip4 = {
			.s_addr = ip->addr.s6_addr[12] << 24 | ip->addr.s6_addr[13] << 16 | ip->addr.s6_addr[14] << 8 | ip->addr.s6_addr[15]
		};

		routemgr_insert_route(CTX(routemgr), ctx->export_table, ctx->nat46ifindex, &ip->addr, 128);
		routemgr_insert_route4(CTX(routemgr), ctx->export_table, client->ifindex, &ip4);
	} else {
		printf(" (IPv6)\n");
		routemgr_insert_route(CTX(routemgr), ctx->export_table, client->ifindex, &ip->addr, 128);
	}
}

/** Remove a route.
  */
void clientmgr_client_remove_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
	if (clientmgr_is_ipv4(ctx, &ip->addr)) {
		struct in_addr ip4 = {
			.s_addr = ip->addr.s6_addr[12] << 24 | ip->addr.s6_addr[13] << 16 | ip->addr.s6_addr[14] << 8 | ip->addr.s6_addr[15]
		};

		routemgr_remove_route(CTX(routemgr), ctx->export_table, &ip->addr, 128);
		routemgr_remove_route4(CTX(routemgr), ctx->export_table, &ip4);
		routemgr_remove_neighbor4(CTX(routemgr), client->ifindex, &ip4, client->mac);
	} else {
		routemgr_remove_route(CTX(routemgr), ctx->export_table, &ip->addr, 128);
		routemgr_remove_neighbor(CTX(routemgr), client->ifindex, &ip->addr, client->mac);
	}
}

/** Given a MAC address returns a client object.
    Returns NULL if the client is not known.
    */
struct client *findinvector(void *_vector, const uint8_t mac[6]) {
	VECTOR(struct client) *vector = _vector;
	for (int i = VECTOR_LEN(*vector) -1 ; i>=0; i--) {
		struct client *e = &VECTOR_INDEX(*vector, i);

		if (e->mac && memcmp(mac, e->mac, sizeof(uint8_t) * 6) == 0)
			return e;
	}

	return NULL;
}

struct client *get_client(const uint8_t mac[6]) {
	return findinvector(&l3ctx.clientmgr_ctx.clients, mac);
}

struct client *get_client_old(const uint8_t mac[6]) {
	return findinvector(&l3ctx.clientmgr_ctx.oldclients, mac);
}

/** Given an ip-address, this returns true if there is a local client connected having this IP-address and false otherwise
*/
bool clientmgr_is_known_address(clientmgr_ctx *ctx, const struct in6_addr *address, struct client **client) {

	// TODO: we probably should make this more efficient for large lists of clients and IP addresses at one point.
	for (int i = VECTOR_LEN(ctx->clients) - 1; i>=0; i--) {
		struct client *c = &VECTOR_INDEX(ctx->clients, i);

		for (int j = VECTOR_LEN(c->addresses)-1; j>=0; j--) {
			struct client_ip *a = &VECTOR_INDEX(c->addresses, j);
			if ( !memcmp(address, &a->addr, sizeof(struct in6_addr))) {
				if (l3ctx.debug) {
					char mac_str[18];
					mac_addr_n2a(mac_str, c->mac);
					print_ip(address, " is attached to local client ");
					printf("%s\n", mac_str);
				}

				if (client) {
					*client = c;
				}
				return true;
			}
		}
	}

	if (l3ctx.debug)
		print_ip(address, " is not assigned to any of the local clients\n");

	return false;
}

struct client *create_client(client_vector *vector, const uint8_t mac[6],const unsigned int ifindex) {
	struct client _client = {};
	memcpy(_client.mac, mac, sizeof(uint8_t) * 6);
	VECTOR_ADD(*vector, _client);
	struct client *client = &VECTOR_INDEX(*vector, VECTOR_LEN(*vector) - 1);
	client->ifindex = ifindex;
	client->node_ip_initialized = false;
	return client;
}

/** Get a client or create a new, empty one.
  */
struct client *get_or_create_client(clientmgr_ctx *ctx, const uint8_t mac[6], unsigned int ifindex) {
	struct client *client = get_client(mac);

	if (client == NULL) {
		client = create_client(&l3ctx.clientmgr_ctx.clients, mac, ifindex);
	}

	return client;
}

/** Remove all client routes - used when exiting l3roamd
**/
void clientmgr_purge_clients(clientmgr_ctx *ctx) {
	struct client *client;

	for (int i=VECTOR_LEN(ctx->clients)-1;i>=0;i--) {
		client=&VECTOR_INDEX(ctx->clients, i);
		clientmgr_delete_client(ctx, client->mac);
	}
}

void client_copy_to_old(struct client *client) {
	struct timespec then;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	then.tv_sec = now.tv_sec + OLDCLIENTS_KEEP_SECONDS;
	then.tv_nsec = 0;
	
	struct client *_client = create_client(&l3ctx.clientmgr_ctx.oldclients,  client->mac, client->ifindex);
	_client->timeout = then;

	for (int i=VECTOR_LEN(client->addresses)-1;i>=0;i--) {
		VECTOR_ADD(_client->addresses, VECTOR_INDEX(client->addresses, i));
	}

	if (l3ctx.debug) {
		printf("copied client to old-queue:\n");
		print_client(_client);
	}
}


/** This will set all IP addresses of the client to IP_INACTIVE and remove the special IP & route
*/
void client_deactivate(struct client *client) {
	struct client *_client = get_client(client->mac);
	client_copy_to_old(_client);
	for (int i=VECTOR_LEN(_client->addresses) - 1; i>=0; i--) {
		struct client_ip *ip = &VECTOR_INDEX(_client->addresses, i);
		if (ip)
			client_ip_set_state(&l3ctx.clientmgr_ctx, _client, ip, IP_INACTIVE);
	}
	remove_special_ip(&l3ctx.clientmgr_ctx, _client);
}


/** Given a MAC address deletes a client. Safe to call if the client is not
  known.
  */
void clientmgr_delete_client(clientmgr_ctx *ctx, uint8_t mac[6]) {
	struct client *client = get_client(mac);
	char mac_str[18];
	mac_addr_n2a(mac_str, mac);
	

	if (client == NULL) {
		if (l3ctx.debug) {
			printf("Client [%s] unknown: cannot delete\n", mac_str);
		}
		return;
	}

	printf("\033[34mREMOVING client %s and invalidating its IP-addresses\033[0m\n", mac_str);
	print_client(client);

	client_copy_to_old(client);

	remove_special_ip(ctx, client);

	if (VECTOR_LEN(client->addresses) > 0) {
		for (int i = VECTOR_LEN(client->addresses)-1; i >= 0; i--) {
			struct client_ip *e = &VECTOR_INDEX(client->addresses, i);
			client_ip_set_state(CTX(clientmgr), client, e, IP_INACTIVE);
			delete_client_ip(client, &e->addr, true);
		}
	}

	for (int i=VECTOR_LEN(ctx->clients)-1;i>=0;i--) {
		if (memcmp(&(VECTOR_INDEX(ctx->clients, i).mac), mac, sizeof(uint8_t)*6) == 0) {
			VECTOR_DELETE(ctx->clients, i);
			break;
		}
	}
}

const char *state_str(enum ip_state state) {
	switch (state) {
		case IP_INACTIVE:
			return "\x1b[31mINACTIVE\x1b[0m";
		case IP_ACTIVE:
			return "\x1b[32mACTIVE\x1b[0m";
		case IP_TENTATIVE:
			return "\x1b[33mTENTATIVE\x1b[0m";
		default:
			return "\x1b[35m(INVALID)\x1b[0m";
	}
}

/** Change state of an IP address. Trigger all side effects like resetting
    counters, timestamps and route changes.
  */
void client_ip_set_state(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip, enum ip_state state) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	bool nop = false;

	switch (ip->state) {
		case IP_INACTIVE:
			switch (state) {
				case IP_INACTIVE:
					nop = true;
					break;
				case IP_ACTIVE:
					client_add_route(ctx, client, ip);
					ip->timestamp = now;
					break;
				case IP_TENTATIVE:
					ip->timestamp = now;
					ipmgr_seek_address(&l3ctx.ipmgr_ctx, &ip->addr);
					break;
			}
			break;
		case IP_ACTIVE:
			switch (state) {
				case IP_INACTIVE:
					ip->timestamp = now;
					clientmgr_client_remove_route(ctx, client, ip);
					break;
				case IP_ACTIVE:
					nop = true;
					ip->timestamp = now;
					break;
				case IP_TENTATIVE:
					ip->timestamp = now;
					ipmgr_seek_address(&l3ctx.ipmgr_ctx, &ip->addr);
					break;
			}
			break;
		case IP_TENTATIVE:
			switch (state) {
				case IP_INACTIVE:
					ip->timestamp = now;
					clientmgr_client_remove_route(ctx, client, ip);
					break;
				case IP_ACTIVE:
					ip->timestamp = now;
					client_add_route(ctx, client, ip);
					break;
				case IP_TENTATIVE:
					nop = true;
					ip->timestamp = now;
					break;
			}
			break;
	}

	if (!nop || l3ctx.debug) {
		print_ip(&ip->addr, "");
		printf(" changes from %s to %s\n", state_str(ip->state), state_str(state));
	}

	ip->state = state;
}

/** Check whether an IP address is contained in a client prefix.
  */
bool clientmgr_valid_address(clientmgr_ctx *ctx, struct in6_addr *address) {
	for (int i = VECTOR_LEN(ctx->prefixes) - 1; i>=0; i--) {
		struct prefix *_prefix = &VECTOR_INDEX(ctx->prefixes, i);
		if (prefix_contains(_prefix, address))
			return true;
	}

	return clientmgr_is_ipv4(ctx, address);
}

/** Check whether an IP address is contained in the IPv4 prefix.
  */
bool clientmgr_is_ipv4(clientmgr_ctx *ctx, struct in6_addr *address) {
	return prefix_contains(&ctx->v4prefix, address);
}

/** Remove an address from a client identified by its MAC.
**/
void clientmgr_remove_address(clientmgr_ctx *ctx, struct client *client, struct in6_addr *address) {
	if (l3ctx.debug) {
		char str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
		char strmac[18];
		mac_addr_n2a(strmac, client->mac);
		printf("clientmgr_remove_address: %s is running for client %s",str, strmac);
	}

	if (client) {
		delete_client_ip(client, address, true);
	}

	if (!client_is_active(client)) {
		printf("no active IP-addresses left in client. Deleting client.\n");
		clientmgr_delete_client(&l3ctx.clientmgr_ctx, client->mac);
	}
}

/** Add a new address to a client identified by its MAC.
 */
void clientmgr_add_address(clientmgr_ctx *ctx, struct in6_addr *address, uint8_t *mac, unsigned int ifindex) {

	if (!clientmgr_valid_address(ctx, address) ) {
		if (l3ctx.debug) {
			printf("address is not within a client-prefix and not ll-address, not adding: ");
			print_ip(address, "\n");
		}
		return;
	}
	
	char mac_str[18] = "";

	if (l3ctx.debug) {
		mac_addr_n2a(mac_str, mac);
		char ifname[IFNAMSIZ];
		char str[INET6_ADDRSTRLEN];

		if_indextoname(ifindex, ifname);
		inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);

		printf("clientmgr_add_address: %s [%s] is running for interface %i %s\n",str, mac_str, ifindex, ifname);
	}

	struct client *client = get_or_create_client(ctx, mac, ifindex);
	struct client_ip *ip = get_client_ip(client, address);
	client->ifindex = ifindex; // client might have roamed to different interface on the same node

	bool was_active = client_is_active(client);
	bool ip_is_new = ip == NULL;

	if (ip_is_new) {
		struct client_ip _ip = {};
		memcpy(&_ip.addr, address, sizeof(struct in6_addr));
		VECTOR_ADD(client->addresses, _ip);
		ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);
		print_client(client);
	}
	client_ip_set_state(ctx, client, ip, IP_ACTIVE);

	if (!was_active) {
		struct in6_addr address = mac2specialipv6(client->mac);
		intercom_claim(CTX(intercom), &address, client); // this will set the special_ip after the claiming cycle
	}

	// this will set NUD_REACHABLE for the clients address we are working on	
	routemgr_insert_neighbor(&l3ctx.routemgr_ctx, client->ifindex, address, client->mac);
}

/** Notify the client manager about a new MAC (e.g. a new wifi client).
  */
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex) {
	if (memcmp(mac , "\x00\x00\x00\x00\x00\x00", 6) == 0)
		return;

	struct client *client = get_or_create_client(ctx, mac, ifindex);

	if (client_is_active(client)) {
		if (l3ctx.debug) {
			char mac_str[18];
			mac_addr_n2a(mac_str, client->mac);
			printf("client[%s] was detected earlier, not re-adding\n", mac_str);
		}
		return;
	}


	char ifname[IFNAMSIZ];
	if_indextoname(ifindex, ifname);
	char mac_str[18];
	mac_addr_n2a(mac_str, client->mac);

	printf("\033[34mnew client %s on %s\033[0m\n", mac_str, ifname);

	client->ifindex = ifindex;

	struct in6_addr address = mac2specialipv6(client->mac);
	intercom_claim(CTX(intercom), &address, client);
	// intercom_claim(CTX(intercom), NULL, client);

	for (int i = VECTOR_LEN(client->addresses)-1; i >= 0; i--) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

		if (ip->state == IP_TENTATIVE || ip->state == IP_INACTIVE)
			client_ip_set_state(ctx, client, ip, IP_TENTATIVE);
	}

	// prefix does not matter here, icmp6_send_solicitation will overwrite the first 13 bytes of the address.
	icmp6_send_solicitation(CTX(icmp6), &address);
}

void free_client_addresses(struct client *client) {
	if (VECTOR_LEN(client->addresses) > 0) {
		for (int i=VECTOR_LEN(client->addresses)-1; i>=0; i--) {
			VECTOR_DELETE(client->addresses, i);
		}
	}
}

void purge_oldclientlist_from_old_clients() {
	struct client *_client = NULL;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	if (l3ctx.debug)
		printf("Purging old clients\n");

	for (int i = VECTOR_LEN(l3ctx.clientmgr_ctx.oldclients)-1;i>=0;i--) {
		_client = &VECTOR_INDEX(l3ctx.clientmgr_ctx.oldclients, i);

		if (timespec_cmp(_client->timeout, now) <= 0) {
			if (l3ctx.debug) {
				printf("removing client from old-queue\n");
				print_client(_client);
			}

			free_client_addresses(_client);
			VECTOR_DELETE(l3ctx.clientmgr_ctx.oldclients, i);
		}
	}
}

void purge_oldclients_task() {
	purge_oldclientlist_from_old_clients();

	post_task(&l3ctx.taskqueue_ctx, OLDCLIENTS_KEEP_SECONDS, 0, purge_oldclients_task, NULL, NULL);
}

/** Handle claim (info request).
  */
void clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[6]) {
	bool old = false;
	struct client *client = get_client(mac);
	if (client == NULL) {
		client = get_client_old(mac);
		old = true;
	}

	if (l3ctx.debug) {
		printf("handle claim for client: ");
		if (client)
			print_client(client);
		else
			printf("unknown\n");
	}

	if (client == NULL)
		return;

//	bool active = client_is_active(client);

	intercom_info(CTX(intercom), sender, client, true);
//	if (active)
//		return;
	if (!old) {
		printf("Dropping client %02x:%02x:%02x:%02x:%02x:%02x in response to claim from sender",  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		print_ip(sender, "\n");
		clientmgr_delete_client(ctx, client->mac);
	}
}

/** Handle incoming client info.
  */
void clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client, bool relinquished) {
	struct client *client = get_client(foreign_client->mac);
	if (l3ctx.debug) {
		printf("handling info message in clientmgr_handle_info() for foreign_client ");
		print_client(foreign_client);
	}

	if (client == NULL) {
		if (l3ctx.debug)
			printf("received info message for client but client is either not locally connected - discarding message\n");
		return;
	}

	for (int i = VECTOR_LEN(foreign_client->addresses) - 1; i >= 0; i--) {
		struct client_ip *foreign_ip = &VECTOR_INDEX(foreign_client->addresses, i);
		struct client_ip *ip = get_client_ip(client, &foreign_ip->addr);

		// Skip if we already know this IP address
		if (ip != NULL)
			continue;

//		VECTOR_ADD(client->addresses, *foreign_ip);
//		ip = &VECTOR_INDEX(client->addresses, VECTOR_LEN(client->addresses) - 1);
//		client_ip_set_state(ctx, client, ip, IP_ACTIVE);
	
		clientmgr_add_address(ctx, &foreign_ip->addr, foreign_client->mac, l3ctx.icmp6_ctx.ifindex);
	}

	if (relinquished)
		add_special_ip(ctx, client);

	printf("Client information merged into local client ");
	print_client(client);
	printf("\n");
}

void clientmgr_init() {
	post_task(&l3ctx.taskqueue_ctx, OLDCLIENTS_KEEP_SECONDS, 0, purge_oldclients_task, NULL, NULL);
}
