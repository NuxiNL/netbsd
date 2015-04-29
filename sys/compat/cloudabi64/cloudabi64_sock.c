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
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <compat/cloudabi/cloudabi_util.h>

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
cloudabi64_sys_sock_recv(struct lwp *l,
    const struct cloudabi64_sys_sock_recv_args *uap, register_t *retval)
{
	cloudabi64_recv_in_t ri;
	cloudabi64_recv_out_t ro;
	struct msghdr msghdr;
	struct mbuf *from;
	register_t retval2[2];
	int error;

	error = copyin(SCARG(uap, in), &ri, sizeof(ri));
	if (error != 0)
		return (error);

	/* Convert results in cloudabi_recv_in_t to struct msghdr. */
	memset(&msghdr, '\0', sizeof(msghdr));
	msghdr.msg_iov = (struct iovec *)ri.ri_data;
	msghdr.msg_iovlen = ri.ri_datalen;
	if (ri.ri_flags & CLOUDABI_MSG_PEEK)
		msghdr.msg_flags |= MSG_PEEK;
	if (ri.ri_flags & CLOUDABI_MSG_WAITALL)
		msghdr.msg_flags |= MSG_WAITALL;

	error = do_sys_recvmsg(l, SCARG(uap, s), &msghdr, &from, NULL, retval2);
	if (error != 0)
		return (error);

	/* Convert results in msghdr to cloudabi_recv_out_t. */
	memset(&ro, '\0', sizeof(ro));
	ro.ro_datalen = retval2[0];
	cloudabi_convert_sockaddr(from, &ro.ro_peername);
	return (copyout(&ro, SCARG(uap, out), sizeof(ro)));
}

int
cloudabi64_sys_sock_send(struct lwp *l,
    const struct cloudabi64_sys_sock_send_args *uap, register_t *retval)
{
	cloudabi64_send_in_t si;
	cloudabi64_send_out_t so;
	struct msghdr msghdr;
	register_t retval2[2];
	int error, flags;

	error = copyin(SCARG(uap, in), &si, sizeof(si));
	if (error != 0)
		return (error);

	/* Convert results in cloudabi_send_in_t to struct msghdr. */
	memset(&msghdr, '\0', sizeof(msghdr));
	msghdr.msg_iov = (struct iovec *)si.si_data;
	msghdr.msg_iovlen = si.si_datalen;
	flags = MSG_IOVUSRSPACE | MSG_NOSIGNAL;
	if (si.si_flags & CLOUDABI_MSG_EOR)
		flags |= MSG_EOR;

	error = do_sys_sendmsg(l, SCARG(uap, s), &msghdr, flags, retval2);
	if (error != 0)
		return (error);

	/* Convert results in msghdr to cloudabi_send_out_t. */
	memset(&so, '\0', sizeof(so));
	so.so_datalen = retval2[0];
	return (copyout(&so, SCARG(uap, out), sizeof(so)));
}
