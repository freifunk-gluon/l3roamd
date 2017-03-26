#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <inttypes.h>


typedef struct {
	struct l3ctx *l3ctx;
	int fd;
} socket_ctx;

void socket_init(socket_ctx *ctx, char *path);
void socket_handle_in(socket_ctx *ctx, size_t count);
