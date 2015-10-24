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

#ifndef _SYS_CAPSICUM_H_
#define	_SYS_CAPSICUM_H_

#ifndef _KERNEL
#error "This header can only be used in kernel space"
#endif

#ifndef _CAP_RIGHTS_T_DECLARED
#define	_CAP_RIGHTS_T_DECLARED
typedef struct cap_rights cap_rights_t;
#endif

/*
 * Though this operating system does not yet provide support for
 * Capsicum, file descriptor operations in kernelspace can already be
 * annotated to describe which file descriptor rights they depend on.
 * This makes it easier for people to experiment with implementing
 * Capsicum or other capability-based security frameworks.
 */

struct cap_rights {
	char cr_bogus;
};

/*
 * Capsicum rights that are defined on FreeBSD.
 */

#define	CAP_ACCEPT		0
#define	CAP_BIND		0
#define	CAP_CONNECT		0
#define	CAP_CREATE		0
#define	CAP_EVENT		0
#define	CAP_EXTATTR_DELETE	0
#define	CAP_EXTATTR_GET		0
#define	CAP_EXTATTR_LIST	0
#define	CAP_EXTATTR_SET		0
#define	CAP_FCHDIR		0
#define	CAP_FCHFLAGS		0
#define	CAP_FCHMOD		0
#define	CAP_FCHMODAT		0
#define	CAP_FCHOWN		0
#define	CAP_FCHOWNAT		0
#define	CAP_FCNTL		0
#define	CAP_FDISCARD		0
#define	CAP_FLOCK		0
#define	CAP_FPATHCONF		0
#define	CAP_FSTAT		0
#define	CAP_FSTATAT		0
#define	CAP_FSTATFS		0
#define	CAP_FSYNC		0
#define	CAP_FTRUNCATE		0
#define	CAP_FUTIMES		0
#define	CAP_FUTIMESAT		0
#define	CAP_GETPEERNAME		0
#define	CAP_GETSOCKNAME		0
#define	CAP_GETSOCKOPT		0
#define	CAP_IOCTL		0
#define	CAP_KQUEUE_CHANGE	0
#define	CAP_KQUEUE_EVENT	0
#define	CAP_LINKAT_SOURCE	0
#define	CAP_LINKAT_TARGET	0
#define	CAP_LISTEN		0
#define	CAP_LOOKUP		0
#define	CAP_MKDIRAT		0
#define	CAP_MKFIFOAT		0
#define	CAP_MKNODAT		0
#define	CAP_MKSYMLINKAT		0
#define	CAP_MMAP		0
#define	CAP_MMAP_R		0
#define	CAP_MMAP_W		0
#define	CAP_MMAP_X		0
#define	CAP_PREAD		0
#define	CAP_PWRITE		0
#define	CAP_READ		0
#define	CAP_READDIR		0
#define	CAP_READLINKAT		0
#define	CAP_RECV		0
#define	CAP_RENAMEAT_SOURCE	0
#define	CAP_RENAMEAT_TARGET	0
#define	CAP_SEEK		0
#define	CAP_SEEK_TELL		0
#define	CAP_SEM_GETVALUE	0
#define	CAP_SEM_POST		0
#define	CAP_SEM_WAIT		0
#define	CAP_SEND		0
#define	CAP_SETSOCKOPT		0
#define	CAP_SHUTDOWN		0
#define	CAP_SOCK_SERVER		0
#define	CAP_SYMLINKAT		0
#define	CAP_UNLINKAT		0
#define	CAP_WRITE		0

/*
 * Capsicum rights that are not present on FreeBSD. These may need their
 * own separate right bits or be expressed using the rights above.
 */

#define	CAP_FACCESSAT		0
#define	CAP_FCHROOT		0
#define	CAP_FREVOKE		0
#define	CAP_MQ_GETATTR		0
#define	CAP_MQ_SETATTR		0
#define	CAP_POSIX_FADVISE	0
#define	CAP_POSIX_FALLOCATE	0
#define	CAP_READDIR		0

/*
 * Stub rights set operations. These currently return NULL pointers to
 * allow the compiler to optimize away these sets when the return value
 * is passed directly to fd_getfile().
 */

static __inline cap_rights_t *
cap_rights_init(cap_rights_t *cr, ...)
{

	return (0);
}

static __inline cap_rights_t *
cap_rights_set(cap_rights_t *cr, ...)
{

	return (0);
}

#endif /* !_SYS_CAPSICUM_H_ */
