#include "icmp6.h"
#include "l3roamd.h"
#include "util.h"

#include <linux/in6.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <string.h>
#include <error.h>
#include <stdio.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

int icmp6_init_packet() {
	int sock, err;
	struct sock_fprog fprog;
	static const struct sock_filter filter[] =
	{
			BPF_STMT(BPF_LD|BPF_B|BPF_ABS, sizeof(struct ip6_hdr) + offsetof(struct icmp6_hdr, icmp6_type)),
			BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, ND_NEIGHBOR_SOLICIT, 1, 0),
			BPF_STMT(BPF_RET|BPF_K, 0),
			BPF_STMT(BPF_RET|BPF_K, 0xffffffff),
	};

	fprog.filter = (struct sock_filter *)filter;
	fprog.len = sizeof filter / sizeof filter[0];

	sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IPV6));
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


	// send icmp6 unreachable on unreachfd
	int unreachfd = socket(AF_INET6, SOCK_RAW,IPPROTO_ICMPV6);
	struct icmp6_filter filterv6;

	ICMP6_FILTER_SETBLOCKALL(&filterv6);
	ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filterv6);
	setsockopt(unreachfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filterv6, sizeof (filterv6));

	ctx->fd = fd;

	ctx->unreachfd = unreachfd;

	ctx->nsfd = icmp6_init_packet();

	icmp6_setup_interface(ctx);
}

void icmp6_setup_interface(icmp6_ctx *ctx) {
	if (!strlen(ctx->clientif))
		return;

	ctx->ok = false;

	int rc = setsockopt(ctx->fd, SOL_SOCKET, SO_BINDTODEVICE, ctx->clientif, strnlen(ctx->clientif, IFNAMSIZ-1));
	printf("Setting up icmp6 interface: %i\n", rc);

	if (rc < 0) {
		perror("icmp6 - setsockopt fd:");
		return;
	}
	
	struct ifreq req = {};
	strncpy(req.ifr_name, ctx->clientif, IFNAMSIZ-1);
	ioctl(ctx->fd, SIOCGIFHWADDR, &req);
	memcpy(ctx->mac, req.ifr_hwaddr.sa_data, 6);

	struct ifreq req1 = {};
	strncpy(req1.ifr_name, ctx->clientif, IFNAMSIZ-1);
	ioctl(ctx->fd, SIOCGIFINDEX, &req1);

	struct sockaddr_ll lladdr;

	// Bind the socket to the interface we're interested in
	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = PF_PACKET;
	lladdr.sll_protocol = htons(ETH_P_IPV6);
	lladdr.sll_ifindex = req1.ifr_ifindex;
	lladdr.sll_hatype = 0;
	lladdr.sll_pkttype = 0;
	lladdr.sll_halen = ETH_ALEN;

	while (bind(ctx->nsfd, (struct sockaddr *)&lladdr, sizeof(lladdr)) < 0 ) {
		perror("bind on icmp6 ns fd failed, retrying");
	}

	ctx->ifindex = req1.ifr_ifindex;

	ctx->ok = true;
}

void icmp6_interface_changed(icmp6_ctx *ctx, int type, const struct ifinfomsg *msg) {
	char ifname[IFNAMSIZ];

	if (if_indextoname(msg->ifi_index, ifname) == NULL)
		return;

	if (strcmp(ifname, ctx->clientif) != 0)
		return;

	printf("icmp6 interface change detected\n");

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
	struct icmp6_hdr hdr;
	uint8_t data[1272];
};
struct __attribute__((__packed__)) sol_packet {
	struct nd_neighbor_solicit hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[6];
};

struct __attribute__((__packed__)) adv_packet {
	struct nd_neighbor_advert hdr;
	struct nd_opt_hdr opt;
	uint8_t hw_addr[6];
};

void icmp6_handle_ns_in(icmp6_ctx *ctx, int fd) {


	struct msghdr msghdr = {};
	memset (&msghdr, 0, sizeof (msghdr));

	char cbuf[CMSG_SPACE (sizeof (int))];

	struct __attribute__((__packed__)) {
		struct ip6_hdr hdr;
		struct sol_packet sol;
	} packet = {};

	struct iovec iov =	{
		.iov_base = &packet,
		.iov_len = sizeof(packet)
	};

	struct sockaddr_ll lladdr;

	struct msghdr hdr =	{
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

	ssize_t rc = recvmsg(ctx->nsfd, &hdr, 0);

	if (ctx->ndp_disabled)
		return;
	
	if (rc == -1)
		return;
	
	if (l3ctx.debug)
		printf("handling icmp6-NS event\n");
	
	uint8_t *mac = lladdr.sll_addr;

	if (packet.sol.hdr.nd_ns_hdr.icmp6_type == ND_NEIGHBOR_SOLICIT) {
		if (memcmp(&packet.hdr.ip6_src, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0)
			return;

		if (l3ctx.debug) {
			char str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &packet.hdr.ip6_src, str, INET6_ADDRSTRLEN);
			printf("Received Neighbor Solicitation from %s [%02x:%02x:%02x:%02x:%02x:%02x] for IP ", str, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			print_ip(&packet.sol.hdr.nd_ns_target, ". Learning source-IP for client.\n");
		}

		clientmgr_notify_mac(CTX(clientmgr), mac, ctx->ifindex);
		clientmgr_add_address(CTX(clientmgr), &packet.hdr.ip6_src, mac, ctx->ifindex);
	}
}

void icmp6_handle_in(icmp6_ctx *ctx, int fd) {
	if (ctx->ndp_disabled)
		return;
	
	if (l3ctx.debug)
		printf("handling icmp6 event\n");

	struct msghdr msghdr;
	memset (&msghdr, 0, sizeof (msghdr));

	struct adv_packet packet = {};
	char cbuf[CMSG_SPACE (sizeof (int))];

	struct iovec iov =	{
		.iov_base = &packet,
		.iov_len = sizeof(packet)
	};

	struct sockaddr_in6 peeraddr;

	struct msghdr hdr =	{
		.msg_name = &peeraddr,
		.msg_namelen = sizeof(peeraddr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof (cbuf)
	};

	ssize_t rc = recvmsg(ctx->fd, &hdr, 0);

	if (rc == -1)
		return;
	
	if (packet.hdr.nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT) {
		printf("not an advertisement - returning\n");
		return;
	}
//	if (packet.hdr.nd_na_hdr.icmp6_code != 0)
//		return;

	if (memcmp(packet.hw_addr, "\x00\x00\x00\x00\x00\x00", 6) == 0)
		return;

	if (l3ctx.debug) {
		printf("Learning from Neighbour Advertisement that Client [%02x:%02x:%02x:%02x:%02x:%02x] ",  packet.hw_addr[0], packet.hw_addr[1], packet.hw_addr[2], packet.hw_addr[3], packet.hw_addr[4], packet.hw_addr[5]);
		print_ip(&packet.hdr.nd_na_target, " is active.\n");
	}
	
	clientmgr_add_address(CTX(clientmgr), &packet.hdr.nd_na_target, packet.hw_addr, ctx->ifindex);
}

void icmp6_send_dest_unreachable(const struct in6_addr *addr, const struct packet *data, int fd) {
	struct dest_unreach_packet packet = {};
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

	int len=0;
	int retries = 3;
	while (len <= 0 && retries > 0){
		len = sendto((&l3ctx.icmp6_ctx)->unreachfd, &packet, sizeof(packet.hdr) + dlen, 0, (struct sockaddr*)&dst, sizeof(dst));

		if (l3ctx.debug && len > 0) {
			printf("sent %i bytes ICMP6 destination unreachable to ", len);
			print_ip(addr, "\n");
		}
		else if (len < 0) {
			printf("Error while sending ICMP destination unreachable, retrying ");
			print_ip(addr, "\n");
			perror("sendto");
		}
		retries--;
	}
}

void icmp6_send_solicitation(icmp6_ctx *ctx, const struct in6_addr *addr) {
	if (!strlen(ctx->clientif))
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

	// RFC2461 dst address are multicast when the node needs to resolve an address and unicast when the node seeks to verify the existence of a neighbor
	memcpy(&dst.sin6_addr, addr, 16);
	memcpy(&dst.sin6_addr, "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff", 13);

	struct client *_client = NULL;
	if (clientmgr_is_known_address(&l3ctx.clientmgr_ctx, addr, &_client)) {
		// find ll-address of the client. if it exists, use that as target for our NS
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

	int len=0;
	int retries = 3;
	while (len <= 0 && retries > 0){
		len = sendto(ctx->fd, &packet, sizeof(packet), 0, (struct sockaddr*)&dst, sizeof(dst));
		if (l3ctx.debug)
			printf("sent NS to %s %i\n", str, len);
		if (len < 0)
			perror("Error while sending NS, retrying");
		retries--;
	}
}

/*
void icmp6_send_echo_request() {
	struct icmp6_hdr icmp6;
	int sock;
	struct icmp6_filter filterv6;
	struct ifreq ifr;

	sock = socket(AF_INET6, SOCK_RAW,IPPROTO_ICMPV6);

	ICMP6_FILTER_SETBLOCKALL(&filterv6);
	ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filterv6);
	ICMP6_FILTER_SETPASS(ICMP6_PACKET_TOO_BIG, &filterv6);
	ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filterv6);
	ICMP6_FILTER_SETPASS(ICMP6_PARAM_PROB, &filterv6);  
	ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filterv6);
	ICMP6_FILTER_SETPASS(ND_REDIRECT, &filterv6);

	setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filterv6, sizeof (filterv6));
	setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof ifr);

	icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6.icmp6_code = 0;
	icmp6.icmp6_cksum = 0;
	icmp6.icmp6_id = id;
	icmp6.icmp6_seq = 100;

	if( (sendto(sock, &icmp6, sizeof(struct icmp6_hdr), 0, (struct sockaddr *)dest, socklen)) != sizeof(struct icmp6_hdr))
		perror("icmp6 echo request sendto");
}
*/
