/*
   Copyright (c) 2017, Christof Schulze <christof.schulze@gmx.net>
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

#include "socket.h"
#include "error.h"

void socket_init(socket_ctx *ctx, char *path) {
	if (! path) {
		ctx->fd = -1;
		return;
	}

	printf("initialize socket\n");

	unlink(path);

	size_t status_socket_len = strlen(path);
	size_t len = offsetof(struct sockaddr_un, sun_path) + status_socket_len + 1;
	uint8_t buf[len] __attribute__((aligned(__alignof__(struct sockaddr_un))));
	memset(buf, 0, offsetof(struct sockaddr_un, sun_path));

	struct sockaddr_un *sa = (struct sockaddr_un *)buf;
	sa->sun_family = AF_UNIX;
	memcpy(sa->sun_path, path, status_socket_len+1);

	ctx->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);


	int ret = bind(ctx->fd, (struct sockaddr *)&ctx->socket, sizeof(ctx->socket));
	if (bind(ctx->fd, (struct sockaddr *)sa, len)) {
		switch (errno) {
			case EADDRINUSE:
				exit_error("unable to create status socket: the path `%s' already exists", path);
			default:
				exit_errno("unable to create status socket");
		}
	}

	ret = listen(ctx->fd, 5);
	if (ret == -1) {
		perror("listen");
		exit(EXIT_FAILURE);
	}
}

void socket_handle_in(socket_ctx *ctx, size_t count) {
	int fd = accept(ctx->fd, NULL, NULL);
	dprintf(fd, "{\"clients\":%zu}", count);
	close(fd);
}
