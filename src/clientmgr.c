/*
 * Copyright (c) 2017,2018, Christof Schulze <christof@christofschulze.com>
 *
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "clientmgr.h"
#include "error.h"
#include "icmp6.h"
#include "ipmgr.h"
#include "l3roamd.h"
#include "prefix.h"
#include "routemgr.h"
#include "timespec.h"
#include "util.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

static const char *state_str(enum ip_state state);

// struct in6_addr node_client_mcast_ip_from_mac(uint8_t mac[ETH_ALEN]) {
//	char addr_str[INET6_ADDRSTRLEN];
//	snprintf(&addr_str[0], INET6_ADDRSTRLEN, "ff02::1:ff%02x:%02x%02x",
// mac[3], mac[4], mac[5]);
//}

// generate mac-based ipv6-address in prefix link-local-address-style
struct in6_addr mac2ipv6(uint8_t mac[ETH_ALEN], struct prefix *prefix) {
	struct in6_addr address = prefix->prefix;

	address.s6_addr[8] = mac[0] ^ 0x02;
	address.s6_addr[9] = mac[1];
	address.s6_addr[10] = mac[2];
	address.s6_addr[11] = 0xff;
	address.s6_addr[12] = 0xfe;
	address.s6_addr[13] = mac[3];
	address.s6_addr[14] = mac[4];
	address.s6_addr[15] = mac[5];

	return address;
}

char *print_client(struct client *client) {
	// re-using the string-buffer from util.c. I am not sure I really do like this.
	int maxlength = STRBUFLEN;
	char tmpbuf[maxlength];
	int offset = 0;
	extern union buffer strbuffer;

	offset += snprintf(&tmpbuf[offset], maxlength - offset, "Client %s %s", print_mac(client->mac),
			   client_is_active(client) ? "(active)" : "(______)");

	if (client->ifindex != 0) {
		char ifname[IFNAMSIZ];
		if_indextoname(client->ifindex, ifname);
		offset += snprintf(&tmpbuf[offset], maxlength - offset, " on %s (%i)\n", ifname, client->ifindex);
	} else {
		offset += snprintf(&tmpbuf[offset], maxlength - offset, "\n");
	}

	for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
		struct client_ip *addr = &VECTOR_INDEX(client->addresses, i);

		switch (addr->state) {
			case IP_INACTIVE:
				offset += snprintf(&tmpbuf[offset], maxlength - offset, "  %s  %s\n",
						   state_str(addr->state), print_ip(&addr->addr));
				break;
			case IP_ACTIVE:
				offset += snprintf(&tmpbuf[offset], maxlength - offset, "  %s  %s (%s)\n",
						   state_str(addr->state), print_ip(&addr->addr),
						   print_timespec(&addr->timestamp));
				break;
			case IP_TENTATIVE:
				offset += snprintf(&tmpbuf[offset], maxlength - offset, "  %s %s (tries left: %d)\n",
						   state_str(addr->state), print_ip(&addr->addr),
						   addr->tentative_retries_left);
				break;
			default:
				exit_bug("Invalid IP state %i- exiting due to memory corruption", addr->state);
		}
	}

	memcpy(strbuffer.allofit, tmpbuf, STRBUFLEN);
	return strbuffer.allofit;
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
	for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

		if (ip_is_active(ip)) {
			return true;
		}
	}

	return false;
}

int bind_to_address(struct in6_addr *address) {
	int fd;
	rtnl_add_address(&l3ctx.routemgr_ctx, address);

	struct sockaddr_in6 server_addr = {
	    .sin6_family = AF_INET6, .sin6_port = htons(INTERCOM_PORT), .sin6_addr = *address,
	};

	fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		perror("creating socket for listening on node-client-IP failed:");
		exit_error("creating socket for intercom on node-client-IP");
	}

	int one = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
		perror("could not set SO_REUSEADDR");
		exit_error("setsockopt: SO_REUSEADDR");
	}
	if (setsockopt(fd, SOL_IP, IP_FREEBIND, &one, sizeof(one)) < 0) {
		perror("could not set IP_FREEBIND");
		exit_error("setsockopt: IP_FREEBIND");
	}

	if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		fprintf(stderr, "Could not bind to socket %i on special ip for address: %s. exiting.\n", fd,
			print_ip(address));
		exit_error("bind socket to node-client-IP failed.");
	}

	add_fd(l3ctx.efd, fd, EPOLLIN);
	return fd;
}

/** Adds the special node client IP address.
*/
void add_special_ip(clientmgr_ctx *ctx, struct client *client) {
	if (client == NULL)  // this can happen if the client was removed before
		// the claim cycle was finished
		return;

	if (client->node_ip_initialized) {
		log_error("we already initialized the special client [%s] not doing it again\n",
			  print_mac(client->mac));
		return;
	}

	struct in6_addr address = mac2ipv6(client->mac, &ctx->node_client_prefix);
	client->fd = bind_to_address(&address);

	client->node_ip_initialized = true;
}

/** close and remove an fd from a client
**/
void close_client_fd(int *fd) {
	log_debug("closing client fd %i\n", *fd);

	if (*fd > 0) {
		del_fd(l3ctx.efd, *fd);
		while (close(*fd)) {
			fprintf(stderr, "could not close client fd %i", *fd);
			perror("close ");
		}
		*fd = -1;
	}
}

/** Removes the special node client IP address.
*/
void remove_special_ip(clientmgr_ctx *ctx, struct client *client) {
	struct in6_addr address = mac2ipv6(client->mac, &ctx->node_client_prefix);
	log_verbose("Removing special address: %s\n", print_ip(&address));
	close_client_fd(&client->fd);
	routemgr_remove_route(&l3ctx.routemgr_ctx, ctx->export_table, &address, 128);
	rtnl_remove_address(&l3ctx.routemgr_ctx, &address);
	// remove route
	client->node_ip_initialized = false;
}

/** Given an IP address returns the client-object of a client.
  Returns NULL if no object is found.
  */
struct client_ip *get_client_ip(struct client *client, const struct in6_addr *address) {
	for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
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
	for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
		struct client_ip *e = &VECTOR_INDEX(client->addresses, i);

		if (memcmp(address, &e->addr, sizeof(struct in6_addr)) == 0) {
			client_ip_set_state(&l3ctx.clientmgr_ctx, client, get_client_ip(client, address), IP_INACTIVE);
			if (cleanup)
				VECTOR_DELETE(client->addresses, i);
		}
	}

	log_verbose("\x1b[31mDeleted IP %s from client, %zi addresses are still assigned\x1b[0m ", print_ip(address),
		    VECTOR_LEN(client->addresses));
}

/** Adds a route and a neighbour entry
*/
static void client_add_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
	if (address_is_ipv4(&ip->addr)) {
		struct in_addr ip4 = extractv4_v6(&ip->addr);
		log_verbose("Adding neighbor and route for IP (IPv4): %s\n", print_ip4(&ip4));
		routemgr_insert_neighbor4(&l3ctx.routemgr_ctx, client->ifindex, &ip4, client->mac);
		routemgr_insert_route4(&l3ctx.routemgr_ctx, ctx->export_table, client->ifindex, &ip4, 32);
	} else {
		log_verbose("Adding neighbour and route for IP (IPv6) %s\n", print_ip(&ip->addr));
		routemgr_insert_neighbor(&l3ctx.routemgr_ctx, client->ifindex, &ip->addr, client->mac);
		routemgr_insert_route(&l3ctx.routemgr_ctx, ctx->export_table, client->ifindex, &ip->addr, 128);
	}
}

/** Remove a route.
*/
static void client_remove_route(clientmgr_ctx *ctx, struct client *client, struct client_ip *ip) {
	if (address_is_ipv4(&ip->addr)) {
		struct in_addr ip4 = extractv4_v6(&ip->addr);
		routemgr_remove_route4(&l3ctx.routemgr_ctx, ctx->export_table, &ip4, 32);
		routemgr_remove_neighbor4(&l3ctx.routemgr_ctx, client->ifindex, &ip4, client->mac);
	} else {
		routemgr_remove_route(&l3ctx.routemgr_ctx, ctx->export_table, &ip->addr, 128);
		routemgr_remove_neighbor(&l3ctx.routemgr_ctx, client->ifindex, &ip->addr, client->mac);
	}
}

/** Given a MAC address returns a client object.
  Returns NULL if the client is not known.
  */
struct client *findinvector(void *_vector, const uint8_t mac[ETH_ALEN]) {
	VECTOR(struct client) *vector = _vector;
	for (int _vector_index = VECTOR_LEN(*vector) - 1; _vector_index >= 0; _vector_index--) {
		struct client *e = &VECTOR_INDEX(*vector, _vector_index);

		if (memcmp(mac, e->mac, sizeof(uint8_t) * 6) == 0)
			return e;
	}

	return NULL;
}

struct client *get_client(const uint8_t mac[ETH_ALEN]) {
	return findinvector(&l3ctx.clientmgr_ctx.clients, mac);
}

struct client *get_client_old(const uint8_t mac[ETH_ALEN]) {
	return findinvector(&l3ctx.clientmgr_ctx.oldclients, mac);
}

/** Given an ip-address, this returns true if there is a local client connected
 * having this IP-address and false otherwise
 */
bool clientmgr_is_known_address(clientmgr_ctx *ctx, const struct in6_addr *address, struct client **client) {
	for (int i = VECTOR_LEN(ctx->clients) - 1; i >= 0; i--) {
		struct client *c = &VECTOR_INDEX(ctx->clients, i);

		for (int j = VECTOR_LEN(c->addresses) - 1; j >= 0; j--) {
			struct client_ip *a = &VECTOR_INDEX(c->addresses, j);
			if (!memcmp(address, &a->addr, sizeof(struct in6_addr))) {
				log_debug("%s is attached to local client %s\n", print_ip(address), print_mac(c->mac));

				if (client) {
					*client = c;
				}
				return true;
			}
		}
	}

	log_debug("%s is not attached to any of the local clients\n", print_ip(address));

	return false;
}

struct client *create_client(client_vector *vector, const uint8_t mac[ETH_ALEN], const unsigned int ifindex) {
	struct client _client = {};
	memcpy(_client.mac, mac, sizeof(uint8_t) * 6);
	_client.ifindex = ifindex;
	_client.node_ip_initialized = false;
	_client.platprefix = l3ctx.clientmgr_ctx.platprefix;
	_client.claimed = false;
	VECTOR_INIT(_client.addresses);
	VECTOR_ADD(*vector, _client);
	struct client *client = &VECTOR_INDEX(*vector, VECTOR_LEN(*vector) - 1);

	return client;
}

/** Get a client or create a new, empty one.
*/
struct client *get_or_create_client(const uint8_t mac[ETH_ALEN], unsigned int ifindex) {
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

	for (int i = VECTOR_LEN(ctx->clients) - 1; i >= 0; i--) {
		client = &VECTOR_INDEX(ctx->clients, i);
		clientmgr_delete_client(ctx, client->mac);
	}
}

void client_copy_to_old(struct client *client) {
	struct timespec then;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	then.tv_sec = now.tv_sec + OLDCLIENTS_KEEP_SECONDS;
	then.tv_nsec = now.tv_nsec;

	struct client *_client = create_client(&l3ctx.clientmgr_ctx.oldclients, client->mac, client->ifindex);
	_client->timeout = then;
	_client->platprefix = client->platprefix;

	for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
		VECTOR_ADD(_client->addresses, VECTOR_INDEX(client->addresses, i));
	}

	log_debug("copied client[%s] to old-queue:\n", print_client(client));
}

/** This will set all IP addresses of the client to IP_INACTIVE and remove the
 * special IP & route
 */
void client_deactivate(struct client *client) {
	struct client *_client = get_client(client->mac);
	client_copy_to_old(_client);
	for (int i = VECTOR_LEN(_client->addresses) - 1; i >= 0; i--) {
		struct client_ip *ip = &VECTOR_INDEX(_client->addresses, i);
		if (ip)
			client_ip_set_state(&l3ctx.clientmgr_ctx, _client, ip, IP_INACTIVE);
	}
	VECTOR_FREE(_client->addresses);
	remove_special_ip(&l3ctx.clientmgr_ctx, _client);
}

/** Given a MAC address deletes a client. Safe to call if the client is not
  known.
  */
void clientmgr_delete_client(clientmgr_ctx *ctx, uint8_t mac[ETH_ALEN]) {
	struct client *client = get_client(mac);

	if (!client) {
		log_debug("Client [%s] unknown: cannot delete\n", print_mac(mac));
		return;
	}

	log_verbose("\033[34mREMOVING client %s and invalidating its IP-addresses\033[0m\n", print_client(client));

	intercom_remove_claim(&l3ctx.intercom_ctx, client);

	client_copy_to_old(client);

	remove_special_ip(ctx, client);

	if (VECTOR_LEN(client->addresses) > 0) {
		for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
			struct client_ip *e = &VECTOR_INDEX(client->addresses, i);
			client_ip_set_state(&l3ctx.clientmgr_ctx, client, e, IP_INACTIVE);
			delete_client_ip(client, &e->addr, true);
		}
	}
	VECTOR_FREE(client->addresses);

	for (int i = VECTOR_LEN(ctx->clients) - 1; i >= 0; i--) {
		if (memcmp(&(VECTOR_INDEX(ctx->clients, i).mac), mac, sizeof(uint8_t) * 6) == 0) {
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
TODO: we really should update the neighbour-table here too instead of
clientmgr_add_client et al.
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
					ipmgr_seek_address(&ip->addr);
					break;
			}
			break;
		case IP_ACTIVE:
			switch (state) {
				case IP_INACTIVE:
					ip->timestamp = now;
					client_remove_route(ctx, client, ip);
					break;
				case IP_ACTIVE:
					nop = true;
					ip->timestamp = now;
					break;
				case IP_TENTATIVE:
					ip->timestamp = now;
					ipmgr_seek_address(&ip->addr);
					break;
			}
			break;
		case IP_TENTATIVE:
			switch (state) {
				case IP_INACTIVE:
					ip->timestamp = now;
					client_remove_route(ctx, client, ip);
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

	if (!nop || l3ctx.debug)
		log_error("%s changes from %s to %s\n", print_ip(&ip->addr), state_str(ip->state), state_str(state));

	ip->state = state;
}

/** Check whether an IP address is contained in a client prefix.
*/
bool clientmgr_valid_address(clientmgr_ctx *ctx, const struct in6_addr *address) {
	for (int i = VECTOR_LEN(ctx->prefixes) - 1; i >= 0; i--) {
		struct prefix *_prefix = &VECTOR_INDEX(ctx->prefixes, i);
		if (prefix_contains(_prefix, address)) {
			log_debug("Address %s is in the client prefix %s\n", print_ip(address), print_ip(&_prefix->prefix));
			return true;
		}
	}

	log_debug("Address %s is not found to be in any of the client prefixes\n", print_ip(address));

	return false;
}

/** Remove an address from a client identified by its MAC.
**/
void clientmgr_remove_address(clientmgr_ctx *ctx, struct client *client, struct in6_addr *address) {
	log_debug("clientmgr_remove_address: %s is running for client %s\n", print_ip(address), print_mac(client->mac));

	if (client) {
		delete_client_ip(client, address, true);
	}

	if (!client_is_active(client)) {
		log_verbose("no active IP-addresses left in client. Deleting client. %s\n", print_mac(client->mac));
		clientmgr_delete_client(ctx, client->mac);
	}
}

void cancel_client_neigh_removal(struct client_ip *ip) {
	if (ip->removal_task) {
		log_debug("cancelling ip removal for %s\n", print_ip(&ip->addr));
		drop_task(ip->removal_task);
		ip->removal_task = NULL;
	}
}

/** Add a new address to a client identified by its MAC.
*/
void clientmgr_add_address(clientmgr_ctx *ctx, const struct in6_addr *address, const uint8_t *mac,
			   const unsigned int ifindex) {
	if (!clientmgr_valid_address(ctx, address)) {
		log_debug(
		    "address is not within a client-prefix and not an "
		    "ll-address. Not adding %s to client %s\n",
		    print_ip(address), print_mac(mac));
		return;
	}

	if (l3ctx.debug) {
		char ifname[IFNAMSIZ];
		if_indextoname(ifindex, ifname);
		log_debug(
		    "clientmgr_add_address: %s [%s] is running for interface "
		    "%s(%i)\n",
		    print_ip(address), print_mac(mac), ifname, ifindex);
	}

	struct client *client = get_or_create_client(mac, ifindex);
	struct client_ip *ip = get_client_ip(client, address);

	client->ifindex = ifindex;  // client might have roamed to different interface on the same node

	bool ip_is_new = ip == NULL;

	if (ip_is_new) {
		struct client_ip _ip = {};
		memcpy(&_ip.addr, address, sizeof(struct in6_addr));
		ip = VECTOR_ADD(client->addresses, _ip);
		log_verbose("created new client: %s\n", print_client(client));
	} else {
		cancel_client_neigh_removal(ip);
	}

	client_ip_set_state(ctx, client, ip, IP_ACTIVE);

	if (!client->claimed) {
		struct in6_addr address = mac2ipv6(client->mac, &ctx->node_client_prefix);
		intercom_claim(&l3ctx.intercom_ctx, &address, client);  // this will set the special_ip after claiming
	}
}

/** Notify the client manager about a new MAC (e.g. a new wifi client).
*/
void clientmgr_notify_mac(clientmgr_ctx *ctx, uint8_t *mac, unsigned int ifindex) {
	if (memcmp(mac, "\x00\x00\x00\x00\x00\x00", 6) == 0)
		return;

	struct client *client = get_or_create_client(mac, ifindex);

	if (client->claimed || client_is_active(client)) {
		log_debug("client[%s] was detected earlier, not re-adding\n", print_mac(client->mac));
		return;
	}

	char ifname[IFNAMSIZ];
	if_indextoname(ifindex, ifname);

	log_verbose("\033[34mnew client %s on %s\033[0m\n", print_mac(client->mac), ifname);

	client->ifindex = ifindex;

	struct in6_addr address = mac2ipv6(client->mac, &ctx->node_client_prefix);

	if (!client->claimed)
		intercom_claim(&l3ctx.intercom_ctx, &address, client);

	for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);

		if (ip->state == IP_TENTATIVE || ip->state == IP_INACTIVE)
			client_ip_set_state(ctx, client, ip, IP_TENTATIVE);
	}

	// prefix does not matter here, icmp6_send_solicitation will overwrite
	// the first 13 bytes of the address.
	icmp6_send_solicitation(&l3ctx.icmp6_ctx, &address);
}

void free_client_addresses(struct client *client) {
	if (VECTOR_LEN(client->addresses) > 0) {
		for (int i = VECTOR_LEN(client->addresses) - 1; i >= 0; i--) {
			VECTOR_DELETE(client->addresses, i);
		}
	}
}

void purge_oldclientlist_from_old_clients() {
	struct client *_client = NULL;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	log_debug("Purging old clients\n");

	for (int i = VECTOR_LEN(l3ctx.clientmgr_ctx.oldclients) - 1; i >= 0; i--) {
		_client = &VECTOR_INDEX(l3ctx.clientmgr_ctx.oldclients, i);

		if (timespec_cmp(_client->timeout, now) <= 0) {
			log_debug("removing client from old-queue: %s\n", print_client(_client));

			free_client_addresses(_client);
			VECTOR_DELETE(l3ctx.clientmgr_ctx.oldclients, i);
		}
	}
}

void purge_oldclients_task() {
	purge_oldclientlist_from_old_clients();

	post_task(&l3ctx.taskqueue_ctx, OLDCLIENTS_KEEP_SECONDS, 0, purge_oldclients_task, NULL, NULL);
}

/** Handle claim (info request). return true if we acted on a local client,
 * false otherwise
 */
bool clientmgr_handle_claim(clientmgr_ctx *ctx, const struct in6_addr *sender, uint8_t mac[ETH_ALEN]) {
	bool old = false;
	struct client *client = get_client(mac);
	if (client == NULL) {
		client = get_client_old(mac);
		old = true;
	}

	log_debug("handling claim for %sclient %s\n", old ? "old " : " ", client ? print_client(client) :  "unknown"); 

	if (!client)
		return false;

	intercom_info(&l3ctx.intercom_ctx, sender, client);

	if (!old) {
		log_verbose("Dropping client %s in response to claim from sender %s\n", print_mac(mac), print_ip(sender));
		clientmgr_delete_client(ctx, client->mac);
	}
	return true;
}

/** Handle incoming client info. return true if we acted on local client, false
 * otherwise
 */
bool clientmgr_handle_info(clientmgr_ctx *ctx, struct client *foreign_client) {
	struct client *client = get_client(foreign_client->mac);
	if (client == NULL) {
		log_debug(
		    "received info message for client %s but client is not "
		    "locally connected - discarding message\n",
		    print_mac(foreign_client->mac));
		return false;
	}

	log_debug("handling info message in clientmgr_handle_info() for foreign_client %s\n",
		  print_client(foreign_client));

	for (int i = VECTOR_LEN(foreign_client->addresses) - 1; i >= 0; i--) {
		struct client_ip *foreign_ip = &VECTOR_INDEX(foreign_client->addresses, i);
		bool is_client_ip_known = get_client_ip(client, &foreign_ip->addr);

		if (!is_client_ip_known)
			continue;

		clientmgr_add_address(ctx, &foreign_ip->addr, foreign_client->mac, l3ctx.icmp6_ctx.ifindex);
	}

	add_special_ip(ctx, client);

	log_verbose("Client information merged into local client %s\n", print_client(client));
	return true;
}

void clientmgr_init() {
	VECTOR_INIT((&l3ctx.clientmgr_ctx)->clients);
	VECTOR_INIT((&l3ctx.clientmgr_ctx)->oldclients);
	post_task(&l3ctx.taskqueue_ctx, OLDCLIENTS_KEEP_SECONDS, 0, purge_oldclients_task, NULL, NULL);
}

int client_compare_by_mac(const struct client *a, const struct client *b) { return memcmp(&a->mac, &b->mac, ETH_ALEN); }
