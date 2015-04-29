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
#include <sys/syscallargs.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>

int
cloudabi_sys_sock_accept(struct lwp *l,
    const struct cloudabi_sys_sock_accept_args *uap, register_t *retval)
{
	struct mbuf *name;
	int error;

	error = do_sys_accept(l, SCARG(uap, s), &name, retval, NULL, 0, 0);
	if (error != 0)
		return (error);

	/* TODO(ed): Copy out socket address. */

	if (name != NULL)
		m_free(name);
	return (0);
}

int
cloudabi_sys_sock_bind(struct lwp *l,
    const struct cloudabi_sys_sock_bind_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_sock_connect(struct lwp *l,
    const struct cloudabi_sys_sock_connect_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_sock_stat_get(struct lwp *l,
    const struct cloudabi_sys_sock_stat_get_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_sock_listen(struct lwp *l,
    const struct cloudabi_sys_sock_listen_args *uap, register_t *retval)
{
	struct sys_listen_args sys_listen_args;

	SCARG(&sys_listen_args, s) = SCARG(uap, s);
	SCARG(&sys_listen_args, backlog) = SCARG(uap, backlog);
	return (sys_listen(l, &sys_listen_args, retval));
}

int
cloudabi_sys_sock_shutdown(struct lwp *l,
    const struct cloudabi_sys_sock_shutdown_args *uap, register_t *retval)
{
	struct sys_shutdown_args sys_shutdown_args;

	SCARG(&sys_shutdown_args, s) = SCARG(uap, fd);
	switch (SCARG(uap, how)) {
	case CLOUDABI_SHUT_RD:
		SCARG(&sys_shutdown_args, how) = SHUT_RD;
		break;
	case CLOUDABI_SHUT_WR:
		SCARG(&sys_shutdown_args, how) = SHUT_WR;
		break;
	case CLOUDABI_SHUT_RD | CLOUDABI_SHUT_WR:
		SCARG(&sys_shutdown_args, how) = SHUT_RDWR;
		break;
	default:
		return (EINVAL);
	}
	return (sys_shutdown(l, &sys_shutdown_args, retval));
}
