/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "icmp6.h"
#include "ipmgr.h"
#include "l3roamd.h"
#include "packet.h"
#include "util.h"

#include <error.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in6.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

unsigned short csum(unsigned short *ptr, int nbytes);

int icmp6_init_packet() {
	int sock, err;
	struct sock_fprog fprog;
	static const struct sock_filter filter[] = {
	    BPF_STMT(BPF_LD | BPF_B | BPF_ABS, sizeof(struct ip6_hdr) + offsetof(struct icmp6_hdr, icmp6_type)),
	    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ND_NEIGHBOR_SOLICIT, 1, 0), BPF_STMT(BPF_RET | BPF_K, 0),
	    BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
	};

	fprog.filter = (struct sock_filter *)filter;
	fprog.len = sizeof filter / sizeof filter[0];

	sock = socket(PF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK, htons(ETH_P_IPV6));
	if (sock < 0) {
		perror("Can't create socket(PF_PACKET)");
	}

	// Tie the BSD-PF filter to the socket
	err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));
	if (err < 0) {
		perror("setsockopt(SO_ATTACH_FILTER)");
	}

	return sock;
}

static inline int setsockopt_int(int socket, int level, int option, int value) {
	return setsockopt(socket, level, option, &value, sizeof(value));
}

void icmp6_init(icmp6_ctx *ctx) {
	if (l3ctx.clientif_set) {
		int fd = socket(PF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMPV6);
		setsockopt_int(fd, IPPROTO_RAW, IPV6_CHECKSUM, 2);
		setsockopt_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, 255);
		setsockopt_int(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, 1);
		setsockopt_int(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, 1);
		setsockopt_int(fd, IPPROTO_IPV6, IPV6_AUTOFLOWLABEL, 0);

		// receive NA on fd
		struct icmp6_filter filter;
		ICMP6_FILTER_SETBLOCKALL(&filter);
		ICMP6_FILTER_SETPASS(ND_NEIGHBOR_ADVERT, &filter);
		setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
		ctx->fd = fd;
		ctx->nsfd = icmp6_init_packet();
	}

	// send icmp6 unreachable on unreachfd6
	int unreachfd6 = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMPV6);
	struct icmp6_filter filterv6 = {};

	ICMP6_FILTER_SETBLOCKALL(&filterv6);
	// shutdown(unreachfd6, SHUT_RD);
	ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filterv6);
	setsockopt(unreachfd6, IPPROTO_ICMPV6, ICMP6_FILTER, &filterv6, sizeof(filterv6));
	ctx->unreachfd6 = unreachfd6;

	struct icmp_filter filterv4 = {};
	filterv4.data |= 1 << ICMP_DEST_UNREACH;
	int unreachfd4 = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
	setsockopt(unreachfd4, IPPROTO_ICMP, ICMP_FILTER, &filterv4, sizeof(filterv4));
	ctx->unreachfd4 = unreachfd4;

	icmp6_setup_interface(ctx);
}

void icmp6_setup_interface(icmp6_ctx *ctx) {
	ctx->ok = false;

	if (!l3ctx.clientif_set)
		return;

	int rc = setsockopt(ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->clientif, strnlen(ctx->clientif, IFNAMSIZ - 1));
	log_verbose("Setting up icmp6 interface: %s %i %i %i\n", ctx->clientif, strnlen(ctx->clientif, 12), IFNAMSIZ, rc);

	if (rc < 0) {
		perror("icmp6 - setsockopt fd:");
		return;
	}

	obtain_mac_from_if(ctx->mac, ctx->clientif);
	ctx->ifindex = if_nametoindex(ctx->clientif);

	struct sockaddr_ll lladdr;
	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = PF_PACKET;
	lladdr.sll_protocol = htons(ETH_P_IPV6);
	lladdr.sll_ifindex = ctx->ifindex;
	lladdr.sll_hatype = 0;
	lladdr.sll_pkttype = 0;
	lladdr.sll_halen = ETH_ALEN;

	while (bind(ctx->nsfd, (struct sockaddr *)&lladdr, sizeof(lladdr)) < 0) {
		perror("bind on icmp6 ns fd failed, retrying");
	}

	ctx->ok = true;
}

void icmp6_interface_changed(icmp6_ctx *ctx, int type, const struct ifinfomsg *msg) {
	char ifname[IFNAMSIZ];

	if (if_indextoname(msg->ifi_index, ifname) == NULL)
		return;

	if (strncmp(ifname, ctx->clientif, IFNAMSIZ - 1) != 0)
		return;

	log_verbose("icmp6 interface change detected\n");

	ctx->ifindex = msg->ifi_index;

	switch (type) {
		case RTM_NEWLINK:
		case RTM_SETLINK:
			icmp6_setup_interface(ctx);
			break;

		case RTM_DELLINK:
			ctx->ok = false;
			break;
	}
}

struct __attribute__((__packed__)) dest_unreach_packet {
	struct icmphdr hdr;
	uint8_t data[1272];
};

struct __attribute__((__packed__)) dest_unreach_packet6 {
	struct icmp6_hdr hdr;
	uint8_t data[1272];
};
struct __attribute__((__packed__)) sol_packet {
	struct nd_neighbor_solicit hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[ETH_ALEN];
};

struct __attribute__((__packed__)) adv_packet {
	struct nd_neighbor_advert hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[ETH_ALEN];
};

void icmp6_handle_ns_in(icmp6_ctx *ctx) {
	char cbuf[CMSG_SPACE(sizeof(int))];

	struct __attribute__((__packed__)) {
		struct ip6_hdr hdr;
		struct sol_packet sol;
	} packet = {};

	struct iovec iov = {.iov_base = &packet, .iov_len = sizeof(packet)};

	struct sockaddr_ll lladdr;

	struct msghdr hdr = {.msg_name = &lladdr,
			     .msg_namelen = sizeof(lladdr),
			     .msg_iov = &iov,
			     .msg_iovlen = 1,
			     .msg_control = cbuf,
			     .msg_controllen = sizeof(cbuf)};

	while (true) {
		ssize_t rc = recvmsg(ctx->nsfd, &hdr, 0);

		if (ctx->ndp_disabled)
			return;

		if (rc <= 0)
			return;

		log_debug("handling icmp6-NDP packet\n");

		uint8_t *mac = lladdr.sll_addr;

		if (packet.sol.hdr.nd_ns_hdr.icmp6_type == ND_NEIGHBOR_SOLICIT) {
			struct  in6_addr ns_target = packet.sol.hdr.nd_ns_target;
			if (memcmp(&packet.hdr.ip6_src,
				   "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
				   "\x00\x00\x00\x00\x00\x00",
				   16) == 0) {
				// client is doing DAD. We could trigger sending
				// NS on this IP address for a couple of times
				// in a while to learn its address instead of
				// flooding the network. If we do this, what
				// effects will this have on privacy extensions?
				log_verbose("triggering local NS cycle after DAD for address %s\n",
					    print_ip(&ns_target));
				struct ns_task *ns_data = create_ns_task(&ns_target,
									 (struct timespec){
									     .tv_sec = 0, .tv_nsec = 300000000,
									 },
									 15, true);
				post_task(&l3ctx.taskqueue_ctx, 0, 0, ipmgr_ns_task, free, ns_data);
			} else {
				struct  in6_addr ip6_src = packet.hdr.ip6_src;
				log_debug(
				    "Received Neighbor Solicitation from %s [%s] for IP %s. Learning source-IP for "
				    "client.\n",
				    print_ip(&ip6_src), print_mac(mac), print_ip(&ns_target));

				clientmgr_notify_mac(&l3ctx.clientmgr_ctx, mac, ctx->ifindex);
				clientmgr_add_address(&l3ctx.clientmgr_ctx, &ip6_src, mac, ctx->ifindex);
			}
		}
	}
}

void icmp6_handle_in(icmp6_ctx *ctx) {
	if (ctx->ndp_disabled)
		return;

	log_debug("handling icmp6 event\n");

	struct msghdr msghdr;
	memset(&msghdr, 0, sizeof(msghdr));

	struct adv_packet packet = {};
	char cbuf[CMSG_SPACE(sizeof(int))];

	struct iovec iov = {.iov_base = &packet, .iov_len = sizeof(packet)};

	struct sockaddr_in6 peeraddr;

	struct msghdr hdr = {.msg_name = &peeraddr,
			     .msg_namelen = sizeof(peeraddr),
			     .msg_iov = &iov,
			     .msg_iovlen = 1,
			     .msg_control = cbuf,
			     .msg_controllen = sizeof(cbuf)};
	while (true) {
		ssize_t rc = recvmsg(ctx->fd, &hdr, 0);

		if (rc == -1)
			return;

		if (packet.hdr.nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT) {
			log_debug("not an advertisement - returning\n");
			continue;
		}
		//	if (packet.hdr.nd_na_hdr.icmp6_code != 0)
		//		return;

		if (memcmp(packet.hw_addr, "\x00\x00\x00\x00\x00\x00", 6) == 0)
			continue;

		struct in6_addr addr = packet.hdr.nd_na_target;
		log_debug("Learning from Neighbour Advertisement that Client [%s] is active on ip %s\n",
			  print_mac(packet.hw_addr), print_ip(&addr));

		// TODO: stop possibly previously started NS-cycles due to DAD,

		clientmgr_add_address(&l3ctx.clientmgr_ctx, &addr, packet.hw_addr, ctx->ifindex);
	}
}

int icmp_send_dest_unreachable(const struct in6_addr *addr, const struct packet *data) {
	int len = 0, retries = 3;
	struct dest_unreach_packet packet = {};

	memset(&packet, 0, sizeof(packet));
	memset(&packet.hdr, 0, sizeof(packet.hdr));
	packet.hdr.type = ICMP_DEST_UNREACH;
	packet.hdr.code = ICMP_HOST_UNREACH;
	packet.hdr.checksum = htons(0);

	int dlen = packet_ipv4_get_header_length((uint8_t *)data) + 8;
	if (dlen < packet_ipv4_get_length((uint8_t *)data))
		dlen = data->len;

	memcpy(packet.data, data->data, dlen);

	struct sockaddr_in dst = {};
	dst.sin_family = AF_INET;

	struct in_addr sin = extractv4_v6(addr);
	memcpy(&dst.sin_addr, &sin, sizeof(struct in_addr));

	packet.hdr.checksum =
	    csum((unsigned short *)&packet,
		 sizeof(struct icmphdr) + dlen);  // icmp dest unreachbyte is 8 Bytes according to RFC 792

	while (len <= 0 && retries > 0) {
		len = sendto(l3ctx.icmp6_ctx.unreachfd4, &packet, sizeof(struct icmphdr) + dlen, 0,
			     (struct sockaddr *)&dst, sizeof(dst));

		if (len > 0) {
			log_debug(
			    "sent %i bytes ICMP destination unreachable to "
			    "%s\n",
			    len, print_ip(addr));
			return 0;
		} else if (len < 0) {
			fprintf(stderr,
				"Error while sending ICMP destination "
				"unreachable, retrying %s\n",
				print_ip(addr));
			perror("sendto");
		}
		retries--;
	}
	return 1;
}

int icmp6_send_dest_unreachable(const struct in6_addr *addr, const struct packet *data) {
	struct dest_unreach_packet6 packet = {};
	memset(&packet, 0, sizeof(packet));
	memset(&packet.hdr, 0, sizeof(packet.hdr));
	packet.hdr.icmp6_type = ICMP6_DST_UNREACH;
	packet.hdr.icmp6_code = ICMP6_DST_UNREACH_NOROUTE;
	packet.hdr.icmp6_cksum = htons(0);

	int dlen = 1272;
	if (data->len < 1272)
		dlen = data->len;

	memcpy(packet.data, data->data, dlen);

	struct sockaddr_in6 dst = {};
	dst.sin6_family = AF_INET6;
	dst.sin6_flowinfo = 0;
	memcpy(&dst.sin6_addr, addr, 16);

	int len = 0;
	int retries = 3;

	while (len <= 0 && retries > 0) {
		len = sendto(l3ctx.icmp6_ctx.unreachfd6, &packet, sizeof(packet.hdr) + dlen, 0, (struct sockaddr *)&dst,
			     sizeof(dst));

		if (len > 0) {
			log_debug("sent %i bytes ICMP6 destination unreachable to %s\n", len, print_ip(addr));
			return 0;
		} else if (len < 0) {
			fprintf(stderr, "Error while sending ICMP destination unreachable, retrying %s\n",
				print_ip(addr));
			perror("sendto");
		}
		retries--;
	}
	return 1;
}

void icmp6_send_solicitation(icmp6_ctx *ctx, const struct in6_addr *addr) {
	if (!ctx->ok)
		return;

	struct sol_packet packet = {};

	memset(&packet, 0, sizeof(packet));
	memset(&packet.hdr, 0, sizeof(packet.hdr));

	packet.hdr.nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
	packet.hdr.nd_ns_hdr.icmp6_code = 0;
	packet.hdr.nd_ns_hdr.icmp6_cksum = htons(0);
	packet.hdr.nd_ns_reserved = htonl(0);

	memcpy(&packet.hdr.nd_ns_target, addr, 16);

	packet.opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	packet.opt.nd_opt_len = 1;

	memcpy(packet.hw_addr, ctx->mac, 6);

	struct sockaddr_in6 dst = {};
	dst.sin6_family = AF_INET6;
	dst.sin6_flowinfo = 0;

	// RFC2461 dst address are multicast when the node needs to resolve an
	// address and unicast when the node seeks to verify the existence of a
	// neighbor
	memcpy(&dst.sin6_addr, addr, 16);
	memcpy(&dst.sin6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff", 13);

	struct client *_client = NULL;
	if (clientmgr_is_known_address(&l3ctx.clientmgr_ctx, addr, &_client)) {
		// find ll-address of the client. if it exists, use that as
		// target for our NS
		struct in6_addr lladdr = {};
		struct prefix _prefix = {};
		parse_prefix(&_prefix, "fe80::/64");
		lladdr = mac2ipv6(_client->mac, &_prefix);

		if (clientmgr_is_known_address(&l3ctx.clientmgr_ctx, &lladdr, &_client)) {
			memcpy(&dst.sin6_addr, &lladdr, 16);
		}
	}

	char str[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &dst.sin6_addr, str, sizeof str);

	int len = 0;
	int retries = 3;
	while (len <= 0 && retries > 0) {
		len = sendto(ctx->fd, &packet, sizeof(packet), 0, (struct sockaddr *)&dst, sizeof(dst));
		log_debug("sent NS with length %i to %s %i\n", len, str);
		if (len < 0)
			perror("Error while sending NS, retrying");
		retries--;
	}
}

// TODO why doesn't the kernel calculate the ICMP checksum?
unsigned short csum(unsigned short *ptr, int nbytes) {
	u_int32_t sum;
	u_int16_t oddbyte;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *)&oddbyte) = *(u_char *)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	return (u_int16_t)~sum;
}
