#include "intercom.h"
#include "error.h"
#include "l3roamd.h"
#include "icmp6.h"

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define INTERCOM_PORT 5523
#define INTERCOM_GROUP "ff02::5523"
#define INTERCOM_MAX_RECENT 100

bool join_mcast(const int sock, const struct in6_addr addr, intercom_if *iface) {
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (mreq.ipv6mr_interface == 0)
		goto error;

	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;
	else if (errno == EADDRINUSE)
		return true;

error:
	fprintf(stderr, "Could not join multicast group on %s: ", iface->ifname);
	perror(NULL);
	return false;
}

void intercom_update_interfaces(intercom_ctx *ctx) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);

		iface->ifindex = if_nametoindex(iface->ifname);

		if (!iface->ifindex)
			continue;

		if (join_mcast(ctx->fd, ctx->groupaddr.sin6_addr, iface))
			iface->ok = true;
	}
}

bool intercom_has_ifname(intercom_ctx *ctx, char *ifname) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);

		if (strcmp(ifname, iface->ifname) == 0)
			return true;
	}

	return false;
}

void intercom_add_interface(intercom_ctx *ctx, char *ifname) {
	if (intercom_has_ifname(ctx, ifname))
		return;

	intercom_if iface = {
		.ok = false,
		.ifname = ifname
	};

	VECTOR_ADD(ctx->interfaces, iface);

	intercom_update_interfaces(ctx);
}

void intercom_init(intercom_ctx *ctx) {

	struct in6_addr mgroup_addr;
	inet_pton(AF_INET6, INTERCOM_GROUP, &mgroup_addr); // TODO Fehler abfangen

	ctx->groupaddr = (struct sockaddr_in6) {
		.sin6_family = AF_INET6,
		.sin6_addr = mgroup_addr,
		.sin6_port = htons(INTERCOM_PORT),
	};

	ctx->fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);

	if (ctx->fd < 0)
		exit_error("creating socket");

	struct sockaddr_in6 server_addr = {};

	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(INTERCOM_PORT);

	if (bind(ctx->fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
}

void intercom_seek(intercom_ctx *ctx, const struct in6_addr *address) {
	intercom_packet_seek packet;

	uint32_t nonce = rand();

	packet.hdr = (intercom_packet_hdr) {
		.type = INTERCOM_SEEK,
		.nonce = nonce,
		.ttl = 255,
	};

	memcpy(&packet.hdr.sender, ctx->ip.s6_addr, sizeof(uint8_t) * 16);

	memcpy(&packet.address, address, 16);

	intercom_recently_seen_add(ctx, &packet.hdr);

	intercom_send_packet(ctx, (uint8_t*)&packet, sizeof(packet));
}

bool intercom_send_packet_unicast(intercom_ctx *ctx, const struct in6_addr *recipient, uint8_t *packet, ssize_t packet_len) {
	struct sockaddr_in6 addr = (struct sockaddr_in6) {
		.sin6_family = AF_INET6,
		.sin6_port = htons(INTERCOM_PORT),
		.sin6_addr = *recipient
	};

	ssize_t rc = sendto(ctx->fd, packet, packet_len, 0, (struct sockaddr*)&addr, sizeof(addr));

	if (rc < 0)
		perror("sendto failed");

	return rc >= 0;
}

void intercom_send_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		intercom_if *iface = &VECTOR_INDEX(ctx->interfaces, i);

		if (!iface->ok)
			continue;

		struct sockaddr_in6 groupaddr = ctx->groupaddr;

		groupaddr.sin6_scope_id = iface->ifindex;

		ssize_t rc = sendto(ctx->fd, packet, packet_len, 0, (struct sockaddr*)&groupaddr, sizeof(groupaddr));
		printf("sent packet to %s on iface %s rc: %zi\n", INTERCOM_GROUP, iface->ifname,rc);

		if (rc < 0)
			iface->ok = false;
	}
}

bool intercom_recently_seen(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
	for (int i = 0; i < VECTOR_LEN(ctx->recent_packets); i++) {
		intercom_packet_hdr *ref_hdr = &VECTOR_INDEX(ctx->recent_packets, i);

		if (ref_hdr->nonce == hdr->nonce && ref_hdr->type == hdr->type)
			return true;
	}
	return false;
}

void intercom_recently_seen_add(intercom_ctx *ctx, intercom_packet_hdr *hdr) {
	if (VECTOR_LEN(ctx->recent_packets) > INTERCOM_MAX_RECENT)
		VECTOR_DELETE(ctx->recent_packets, 0);

	VECTOR_ADD(ctx->recent_packets, *hdr);
}

void intercom_handle_seek(intercom_ctx *ctx, intercom_packet_seek *packet) {
	if (clientmgr_is_ipv4(CTX(clientmgr), (struct in6_addr *)packet->address))
		arp_send_request(CTX(arp), (struct in6_addr *)packet->address);
	else
		icmp6_send_solicitation(CTX(icmp6), (struct in6_addr *)packet->address);
}

void intercom_handle_claim(intercom_ctx *ctx, intercom_packet_claim *packet) {
	struct in6_addr sender;

	memcpy(&sender.s6_addr, &packet->hdr.sender, sizeof(uint8_t) * 16);

	clientmgr_handle_claim(CTX(clientmgr), &sender, packet->mac);
}

void intercom_handle_info(intercom_ctx *ctx, intercom_packet_info *packet) {
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	struct client client = {};

	memcpy(client.mac, &packet->mac, sizeof(uint8_t) * 6);

	struct client_ip ip = {
		.state = IP_INACTIVE
	};

	intercom_packet_info_entry *entry = (intercom_packet_info_entry*)((uint8_t*)(packet) + sizeof(intercom_packet_info));

	for (int i = 0; i < packet->num_addresses; i++) {
		memcpy(&ip.addr.s6_addr, &entry->address, sizeof(uint8_t) * 16);
		VECTOR_ADD(client.addresses, ip);
		entry++;
	}

	clientmgr_handle_info(CTX(clientmgr), &client, packet->relinquished);
}

void intercom_handle_packet(intercom_ctx *ctx, uint8_t *packet, ssize_t packet_len) {
	intercom_packet_hdr *hdr = (intercom_packet_hdr*) packet;

	if (intercom_recently_seen(ctx, hdr))
		return;

	intercom_recently_seen_add(ctx, hdr);

	if (hdr->type == INTERCOM_SEEK)
		intercom_handle_seek(ctx, (intercom_packet_seek*)packet);

	if (hdr->type == INTERCOM_CLAIM)
		intercom_handle_claim(ctx, (intercom_packet_claim*)packet);

	if (hdr->type == INTERCOM_INFO)
		intercom_handle_info(ctx, (intercom_packet_info*)packet);

	hdr->ttl--;

	if (hdr->ttl > 0)
		intercom_send_packet(ctx, packet, packet_len);
}

void intercom_handle_in(intercom_ctx *ctx, int fd) {
	ssize_t count;
	uint8_t buf[1500];

	while (1) {
		count = read(fd, buf, sizeof buf);

		if (count == -1) {
			/* If errno == EAGAIN, that means we have read all
				 data. So go back to the main loop. */
			if (errno != EAGAIN) {
				perror("read - going back to main loop");
			}
			break;
		} else if (count == 0) {
			/* End of file. The remote has closed the
				 connection. */
			break;
		}

		intercom_handle_packet(ctx, buf, count);
	}
}

// Announce at most 32 addresses per client
#define INFO_MAX 32

/* recipient = NULL -> send to neighbours */
void intercom_info(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client, bool relinquished) {
	intercom_packet_info *packet = malloc(sizeof(intercom_packet_info) + INFO_MAX * sizeof(intercom_packet_info_entry));
	int i;

	uint32_t nonce = rand();

	packet->hdr = (intercom_packet_hdr) {
		.type = INTERCOM_INFO,
		.nonce = nonce,
		.ttl = 1,
	};

	memcpy(&packet->hdr.sender, ctx->ip.s6_addr, sizeof(uint8_t) * 16);

	memcpy(&packet->mac, client->mac, sizeof(uint8_t) * 6);
	packet->relinquished = relinquished;

	intercom_packet_info_entry *entry = (intercom_packet_info_entry*)((uint8_t*)(packet) + sizeof(intercom_packet_info));

	for (i = 0; i < VECTOR_LEN(client->addresses) && i < INFO_MAX; i++) {
		struct client_ip *ip = &VECTOR_INDEX(client->addresses, i);
		memcpy(&entry->address, ip->addr.s6_addr, sizeof(uint8_t) * 16);
		entry++;
	}

	packet->num_addresses = i;

	ssize_t packet_len = sizeof(intercom_packet_info) + i * sizeof(intercom_packet_info_entry);

	if (recipient != NULL)
		intercom_send_packet_unicast(ctx, recipient, (uint8_t*)packet, packet_len);
	else {
		intercom_recently_seen_add(ctx, &packet->hdr);

		intercom_send_packet(ctx, (uint8_t*)packet, packet_len);
	}
	free(packet);
}

bool intercom_claim(intercom_ctx *ctx, const struct in6_addr *recipient, struct client *client) {
	intercom_packet_claim packet;

	uint32_t nonce = rand();

	packet.hdr = (intercom_packet_hdr) {
		.type = INTERCOM_CLAIM,
		.nonce = nonce,
		.ttl = 255,
	};

	memcpy(&packet.hdr.sender, ctx->ip.s6_addr, sizeof(uint8_t) * 16);

	memcpy(&packet.mac, client->mac, 6);

	intercom_recently_seen_add(ctx, &packet.hdr);

	if (recipient != NULL)
		return intercom_send_packet_unicast(ctx, recipient, (uint8_t*)&packet, sizeof(packet));
	else {
		intercom_send_packet(ctx, (uint8_t*)&packet, sizeof(packet));
		return true;
	}
}
