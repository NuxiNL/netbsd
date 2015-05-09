/*	$NetBSD$	*/

/*-
 * Copyright (c) 2015 Nuxi, https://nuxi.nl/
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _CLOUDABI_UTIL_H_
#define	_CLOUDABI_UTIL_H_

#include <sys/filedesc.h>
#include <sys/socket.h>

#include <compat/cloudabi/cloudabi_syscalldefs.h>

struct lwp;
struct mbuf;
struct nameidata;
struct vnode;

/* Mode for new files created by CloudABI processed. */
#define CLOUDABI_MODE(l)	(0777 & ~(l)->l_proc->p_cwdi->cwdi_cmask)
/* Calls NDINIT() with SANDBOXINDIR set. */
#define	CLOUDABI_NDINIT(ndp, op, flags, pathbuf) \
	NDINIT(ndp, op, (flags) | SANDBOXINDIR, pathbuf)

/* Performs a namei lookup with a base directory as a file descriptor. */
int cloudabi_namei(struct lwp *, cloudabi_fd_t, cap_rights_t,
    struct nameidata *);

/* Returns the vnode corresponding with a base directory and pathname. */
int cloudabi_namei_simple(struct lwp *, cloudabi_lookup_t, cap_rights_t,
    const char *, size_t, unsigned int, struct vnode **);

/* Fetches the time value of a clock. */
int cloudabi_clock_time_get(struct lwp *, cloudabi_clockid_t,
    cloudabi_timestamp_t *);

/* Converts a NetBSD errno to a CloudABI errno. */
cloudabi_errno_t cloudabi_convert_errno(int);

/* Converts a file descriptor to a CloudABI file descriptor type. */
cloudabi_filetype_t cloudabi_convert_filetype(const struct file *);

/* Converts CloudABI's Capsicum rights to NetBSD's set of rights. */
int cloudabi_convert_cloudabi_rights(cloudabi_rights_t, cap_rights_t *);

/* Generates a unique thread ID for a given thread. */
cloudabi_tid_t cloudabi_gettid(struct lwp *);

/* Converts NetBSD's struct sockaddr to CloudABI's cloudabi_sockaddr_t. */
void cloudabi_convert_sockaddr(const struct sockaddr *, socklen_t,
    cloudabi_sockaddr_t *);

/* Initialization of the futex pool. */
void cloudabi_futex_init(void);
void cloudabi_futex_destroy(void);

/*
 * Blocking futex functions.
 *
 * These functions are called by CloudABI's polling system calls to
 * sleep on a lock or condition variable.
 */
int cloudabi_futex_condvar_wait(struct lwp *, cloudabi_condvar_t *,
    cloudabi_lock_t *, cloudabi_clockid_t, cloudabi_timestamp_t,
    cloudabi_timestamp_t);
int cloudabi_futex_lock_rdlock(struct lwp *, cloudabi_lock_t *,
    cloudabi_clockid_t, cloudabi_timestamp_t, cloudabi_timestamp_t);
int cloudabi_futex_lock_wrlock(struct lwp *, cloudabi_lock_t *,
    cloudabi_clockid_t, cloudabi_timestamp_t, cloudabi_timestamp_t);

#endif
