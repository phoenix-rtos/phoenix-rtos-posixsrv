/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * POSIX server - public api
 *
 * Copyright 2018, 2023 Phoenix Systems
 * Author: Jan Sikorski, Gerard Swiderski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#ifndef POSIXSRV_H
#define POSIXSRV_H


int posixsrv_init(unsigned *srvPort, unsigned *eventPort);


unsigned posixsrv_port(void);


void posixsrvthr(void *arg);


void rq_timeoutthr(void *arg);


#endif /* end of POSIXSRV_H */
