/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - standalone main
 *
 * Copyright 2018, 2023 Phoenix Systems
 * Author: Jan Sikorski, Gerard Swiderski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/threads.h>

#include "posixsrv_private.h"

#include "posixsrv.h"


static char stacks[4][0x1000] __attribute__((aligned(8)));


static int fail(const char *str)
{
	printf("posixsrv fail: %s\n", str);
	exit(EXIT_FAILURE);
}


int main(int argc, char **argv)
{
	oid_t fs;
	unsigned srvPort;
	unsigned eventPort;

	while (lookup("/", NULL, &fs) < 0) {
		usleep(5000);
	}

	if (posixsrv_init(&srvPort, &eventPort) < 0) {
		fail("srv init");
	}

	openlog("posixsrv", LOG_CONS, LOG_DAEMON);

	beginthread(posixsrv_threadMain, 4, stacks[0], sizeof(stacks[0]), (void *)eventPort);

	for (int i = 1; i < sizeof(stacks) / sizeof(stacks[0]); ++i) {
		beginthread(posixsrv_threadMain, 4, stacks[i], sizeof(stacks[i]), (void *)srvPort);
	}

	posixsrv_threadRqTimeout(NULL);

	/* never reached */
	return 0;
}
