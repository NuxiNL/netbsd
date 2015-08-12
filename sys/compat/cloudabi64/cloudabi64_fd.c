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

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/syscallargs.h>

#include <compat/cloudabi64/cloudabi64_syscalldefs.h>
#include <compat/cloudabi64/cloudabi64_syscallargs.h>

static_assert(sizeof(cloudabi64_ciovec_t) == sizeof(struct iovec),
    "Size mismatch");
static_assert(offsetof(cloudabi64_ciovec_t, iov_base) ==
    offsetof(struct iovec, iov_base), "Offset mismatch");
static_assert(offsetof(cloudabi64_ciovec_t, iov_len) ==
    offsetof(struct iovec, iov_len), "Offset mismatch");

static_assert(sizeof(cloudabi64_iovec_t) == sizeof(struct iovec),
    "Size mismatch");
static_assert(offsetof(cloudabi64_iovec_t, iov_base) ==
    offsetof(struct iovec, iov_base), "Offset mismatch");
static_assert(offsetof(cloudabi64_iovec_t, iov_len) ==
    offsetof(struct iovec, iov_len), "Offset mismatch");

int
cloudabi64_sys_fd_pread(struct lwp *l,
    const struct cloudabi64_sys_fd_pread_args *uap, register_t *retval)
{
	struct sys_preadv_args sys_preadv_args;

	SCARG(&sys_preadv_args, fd) = SCARG(uap, fd);
	SCARG(&sys_preadv_args, iovp) = (const struct iovec *)SCARG(uap, iov);
	SCARG(&sys_preadv_args, iovcnt) = SCARG(uap, iovcnt);
	SCARG(&sys_preadv_args, offset) = SCARG(uap, offset);
	return (sys_preadv(l, &sys_preadv_args, retval));
}

int
cloudabi64_sys_fd_pwrite(struct lwp *l,
    const struct cloudabi64_sys_fd_pwrite_args *uap, register_t *retval)
{
	struct sys_pwritev_args sys_pwritev_args;

	SCARG(&sys_pwritev_args, fd) = SCARG(uap, fd);
	SCARG(&sys_pwritev_args, iovp) = (const struct iovec *)SCARG(uap, iov);
	SCARG(&sys_pwritev_args, iovcnt) = SCARG(uap, iovcnt);
	SCARG(&sys_pwritev_args, offset) = SCARG(uap, offset);
	return (sys_pwritev(l, &sys_pwritev_args, retval));
}

int
cloudabi64_sys_fd_read(struct lwp *l,
    const struct cloudabi64_sys_fd_read_args *uap, register_t *retval)
{
	struct sys_readv_args sys_readv_args;

	SCARG(&sys_readv_args, fd) = SCARG(uap, fd);
	SCARG(&sys_readv_args, iovp) = (const struct iovec *)SCARG(uap, iov);
	SCARG(&sys_readv_args, iovcnt) = SCARG(uap, iovcnt);
	return (sys_readv(l, &sys_readv_args, retval));
}

int
cloudabi64_sys_fd_write(struct lwp *l,
    const struct cloudabi64_sys_fd_write_args *uap, register_t *retval)
{
	struct sys_writev_args sys_writev_args;

	SCARG(&sys_writev_args, fd) = SCARG(uap, fd);
	SCARG(&sys_writev_args, iovp) = (const struct iovec *)SCARG(uap, iov);
	SCARG(&sys_writev_args, iovcnt) = SCARG(uap, iovcnt);
	return (sys_writev(l, &sys_writev_args, retval));
}
