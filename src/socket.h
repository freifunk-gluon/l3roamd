#pragma once

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

#define LINEBUFFER_SIZE 1024

enum socket_command {
	GET_CLIENTS =0,
	PROBE,
	ADD_MESHIF,
	DEL_MESHIF,
	ADD_PREFIX,
	DEL_PREFIX,
	GET_PREFIX,
	ADD_ADDRESS,
	DEL_ADDRESS
};

typedef struct {
	struct l3ctx *l3ctx;
	int fd;
} socket_ctx;

void socket_init(socket_ctx *ctx, char *path);
void socket_handle_in(socket_ctx *ctx);
