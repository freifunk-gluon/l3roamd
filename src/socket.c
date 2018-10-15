/*
   Copyright (c) 2017, Christof Schulze <christof@christofschulze.com>
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

#include <stdio.h>
#include <unistd.h>
#include <json-c/json.h>

#include "socket.h"
#include "error.h"
#include "l3roamd.h"
#include "prefix.h"
#include "routemgr.h"
#include "util.h"
#include "clientmgr.h"

void socket_init(socket_ctx *ctx, char *path) {
    if (!path) {
        ctx->fd = -1;
        return;
    }

    printf("Initializing unix socket: %s\n", path);

    unlink(path);

    size_t status_socket_len = strlen(path);
    size_t len = offsetof(struct sockaddr_un, sun_path) + status_socket_len + 1;
    uint8_t buf[len] __attribute__((aligned(__alignof__(struct sockaddr_un))));
    memset(buf, 0, offsetof(struct sockaddr_un, sun_path));

    struct sockaddr_un *sa = (struct sockaddr_un *)buf;
    sa->sun_family = AF_UNIX;
    memcpy(sa->sun_path, path, status_socket_len+1);

    ctx->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);

    if (bind(ctx->fd, (struct sockaddr *)sa, len)) {
        switch (errno) {
        case EADDRINUSE:
            exit_error("unable to create status socket: the path `%s' already exists", path);
        default:
            exit_errno("unable to create status socket");
        }
    }

    if (listen(ctx->fd, 5)) {
        perror("unable to listen on unix-socket");
        exit(EXIT_FAILURE);
    }
}

bool parse_command(char *cmd, enum socket_command *scmd) {
    if (!strncmp(cmd, "get_clients", 11)) {
        *scmd = GET_CLIENTS;
        return true;
    }
    if (!strncmp(cmd, "del_meshif ", 11)) {
        *scmd = DEL_MESHIF;
        return true;
    }
    if (!strncmp(cmd, "add_meshif ", 11)) {
        *scmd = ADD_MESHIF;
        return true;
    }
    if (!strncmp(cmd, "del_prefix ", 11)) {
        *scmd = DEL_PREFIX;
        return true;
    }
    if (!strncmp(cmd, "add_address ", 12)) {
        *scmd = ADD_ADDRESS;
        return true;
    }
    if (!strncmp(cmd, "del_address ", 12)) {
        *scmd = DEL_ADDRESS;
        return true;
    }
    if (!strncmp(cmd, "add_prefix ", 11)) {
        *scmd = ADD_PREFIX;
        return true;
    }
    if (!strncmp(cmd, "probe ", 6)) {
        *scmd = PROBE;
        return true;
    }
    if (!strncmp(cmd, "get_prefixes", 12)) {
        *scmd = GET_PREFIX;
        return true;
    }
    return false;
}

void socket_get_prefixes(struct json_object *obj) {
    struct json_object *jprefixes = json_object_new_array();
    char str_prefix[INET6_ADDRSTRLEN] = {};

    inet_ntop(AF_INET6, &l3ctx.clientmgr_ctx.v4prefix.prefix, str_prefix, INET6_ADDRSTRLEN);
    json_object_array_add(jprefixes, json_object_new_string(str_prefix));

    for (int i = 0; i<VECTOR_LEN(l3ctx.clientmgr_ctx.prefixes); i++) {
        struct prefix *_prefix = &VECTOR_INDEX(l3ctx.clientmgr_ctx.prefixes, i);
        inet_ntop(AF_INET6, &_prefix->prefix, str_prefix, INET6_ADDRSTRLEN);
        json_object_array_add(jprefixes, json_object_new_string(str_prefix));
    }
    json_object_object_add(obj, "prefixes", jprefixes);
}

void get_clients(struct json_object *obj) {
    int i = 0, j = 0;
    struct json_object *jclients = json_object_new_object();

    json_object_object_add(obj, "clients", json_object_new_int(VECTOR_LEN(l3ctx.clientmgr_ctx.clients)));

    for (i = 0; i < VECTOR_LEN(l3ctx.clientmgr_ctx.clients); i++) {
        struct client *_client = &VECTOR_INDEX(l3ctx.clientmgr_ctx.clients, i);
        struct json_object *jclient = json_object_new_object();

        // char mac[18] = {};
        // mac_addr_n2a(mac, _client->mac);
        char ifname[IFNAMSIZ] = "";

        if_indextoname(_client->ifindex, ifname);
        json_object_object_add(jclient, "interface", json_object_new_string(ifname));

        struct json_object *addresses = json_object_new_object();
        for (j = 0; j<VECTOR_LEN(_client->addresses); j++) {
            struct json_object *address = json_object_new_object();
            struct client_ip *_client_ip = &VECTOR_INDEX(_client->addresses, j);
            char ip_str[INET6_ADDRSTRLEN] = "";
            inet_ntop(AF_INET6, &_client_ip->addr, ip_str, INET6_ADDRSTRLEN);

            json_object_object_add(address, "state", json_object_new_int(_client_ip->state));
            json_object_object_add(addresses , ip_str, address);
        }

        if (j) {
            json_object_object_add(jclient, "addresses", addresses);
        }
        else {
            json_object_put(addresses);
        }

        json_object_object_add(jclients, print_mac( _client->mac), jclient);
    }

    if (i) {
        json_object_object_add(obj,"clientlist", jclients);
    }
    else {
        json_object_put(jclients);
    }

}

void socket_handle_in(socket_ctx *ctx) {
    log_debug("handling socket event\n");

    int fd = accept(ctx->fd, NULL, NULL);
    char line[LINEBUFFER_SIZE];

    int len=0;
    int fill=0;
    // TODO: it would be nice to be able to set a timeout here after which the fd is closed
    while (fill<LINEBUFFER_SIZE) {
        len = read(fd, &(line[fill]), 1);
        if (line[fill] == '\n' || line[fill] == '\r') {
            line[fill]='\0';
            break;
        }
        fill+=len;
    }

    enum socket_command cmd;
    if (!parse_command(line, &cmd) ) {
        fprintf(stderr, "Could not parse command on socket (%s)\n",line);
        goto end;
    }

    struct prefix _prefix = {};
    struct json_object *retval = json_object_new_object();
    uint8_t mac[ETH_ALEN] = { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa };
    struct in6_addr address = {};
    char *str_address = NULL;
    char *str_mac = NULL;
    char *str_meshif = NULL;

    switch (cmd) {
    case PROBE:
        str_address = strtok(&line[ETH_ALEN], " ");
        str_mac = strtok(NULL, " ");
        sscanf(str_mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if (inet_pton(AF_INET6, str_address, &address) == 1) {
            routemgr_probe_neighbor(&l3ctx.routemgr_ctx, l3ctx.routemgr_ctx.clientif_index, &address,  mac);
        }
        break;
    case GET_CLIENTS:
        get_clients(retval);
        dprintf(fd, "%s", json_object_to_json_string(retval));
        break;
    case ADD_PREFIX:
        if (parse_prefix(&_prefix, &line[11])) {
            add_prefix(&CTX(clientmgr)->prefixes, _prefix);
            routemgr_insert_route(CTX(routemgr), 254, if_nametoindex(CTX(ipmgr)->ifname), (struct in6_addr*)(_prefix.prefix.s6_addr), _prefix.plen );
            dprintf(fd, "Added prefix: %s", &line[11]);
        }
        break;
    case ADD_ADDRESS:
        str_address = strtok(&line[12], " ");
        str_mac = strtok(NULL, " ");
        sscanf(str_mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        if (inet_pton(AF_INET6, str_address, &address) == 1) {
            clientmgr_add_address(&l3ctx.clientmgr_ctx, &address, mac, l3ctx.routemgr_ctx.clientif_index);
            dprintf(fd, "OK");
        }
        else {
            struct in_addr ip4;
            if (inet_pton(AF_INET, str_address, &ip4) == 1) {
		    mapv4_v6(&ip4, &address);
                clientmgr_add_address(&l3ctx.clientmgr_ctx, &address, mac, l3ctx.routemgr_ctx.clientif_index);
                dprintf(fd, "OK");
            }
            else
                dprintf(fd, "NOT OK");
            }
        break;
    case ADD_MESHIF:
	str_meshif = strndup(&line[11], IFNAMSIZ);
	if (! intercom_add_interface ( &l3ctx.intercom_ctx, str_meshif ) ) {
		free(str_meshif);
		break;
	}
	break;
    case DEL_MESHIF:
	str_meshif = strndup(&line[11], IFNAMSIZ);
	if (! intercom_del_interface ( &l3ctx.intercom_ctx, str_meshif ) )
		free(str_meshif);
	break;
    case DEL_ADDRESS:
        str_address = strtok(&line[12], " ");
        str_mac = strtok(NULL, " ");
        sscanf(str_mac, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
        struct client *client = get_client(mac);
        if (client) {
            if (inet_pton(AF_INET6, str_address, &address) == 1) {
                rtmgr_client_remove_address(&address);
                dprintf(fd, "OK");
            }
            else {
                dprintf(fd, "NOT OK");
            }
        }
        break;
    case DEL_PREFIX:
        if (parse_prefix(&_prefix, &line[11])) {
            del_prefix(&CTX(clientmgr)->prefixes, _prefix);
            routemgr_remove_route(CTX(routemgr), 254, (struct in6_addr*)(_prefix.prefix.s6_addr), _prefix.plen );
            dprintf(fd, "Deleted prefix: %s", &line[11]);
        }
        break;
    case GET_PREFIX:
        socket_get_prefixes(retval);
        dprintf(fd, "%s", json_object_to_json_string(retval));
        break;
    }

    json_object_put(retval);
end:
    close(fd);
}
