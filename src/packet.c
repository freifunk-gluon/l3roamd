#include "packet.h"
#include "util.h"
#include <stdbool.h>
#include <netinet/in.h>
#include <string.h>

static struct in6_addr packet_get_ip4(const uint8_t packet[], int offset) {
    struct in_addr src;
    struct in6_addr src6;
    memcpy(&src, packet + offset, 4);
    mapv4_v6(&src, &src6);
    return src6;
}

static struct in6_addr packet_get_src4(const uint8_t packet[]) {
    return packet_get_ip4(packet, 12);
}

static struct in6_addr packet_get_dst4(const uint8_t packet[]) {
    return packet_get_ip4(packet, 16);
}

static struct in6_addr packet_get_ip6(const uint8_t packet[], int offset) {
    struct in6_addr src;
    memcpy(&src, packet + offset, 16);
    return src;
}

static struct in6_addr packet_get_src6(const uint8_t packet[]) {
    return packet_get_ip6(packet, 8);
}

static struct in6_addr packet_get_dst6(const uint8_t packet[]) {
    return packet_get_ip6(packet, 24);
}

static inline bool packet_isv4(const uint8_t packet[]) {
    return (packet[0] & 0xf0) == 0x40;
}


static inline bool packet_isv6(const uint8_t packet[]) {
    return (packet[0] & 0xf0) == 0x60;
}


struct in6_addr packet_get_src(const uint8_t packet[]) {
    if ( packet_isv4(packet) )
        return packet_get_src4(packet);
    else if ( packet_isv6(packet) )
        return packet_get_src6(packet);
    struct in6_addr ret = {};
    return ret;
}

struct in6_addr packet_get_dst(const uint8_t packet[]) {
    if ( packet_isv4(packet) )
        return packet_get_dst4(packet);
    else if ( packet_isv6(packet) )
        return packet_get_dst6(packet);
    struct in6_addr ret = {};
    return ret;
}
