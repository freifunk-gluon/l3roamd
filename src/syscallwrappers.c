/*
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include "syscallwrappers.h"
#include "error.h"

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int obtainrandom(void *buf, size_t buflen, unsigned int flags) {
	int rc = 0;
	size_t fill = 0;

	do {
		rc = (int)syscall(SYS_getrandom, &buf + fill, buflen - fill, flags);
		if (rc < 0 ) {
			if (errno != ENOSYS) {
				exit_error("syscall SYS_getrandom.");
			}
			perror("syscall SYS_getrandom failed. retrying");
		} else {
			fill += rc;
		}
	} while (fill < buflen);

	return fill;
}
