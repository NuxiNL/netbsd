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
#include <sys/fcntl.h>
#include <sys/syscallargs.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>

int
cloudabi_sys_fd_close(struct lwp *l,
    const struct cloudabi_sys_fd_close_args *uap, register_t *retval)
{
	struct sys_close_args sys_close_args;

	SCARG(&sys_close_args, fd) = SCARG(uap, fd);
	return (sys_close(l, &sys_close_args, retval));
}

int
cloudabi_sys_fd_create1(struct lwp *l,
    const struct cloudabi_sys_fd_create1_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_fd_create2(struct lwp *l,
    const struct cloudabi_sys_fd_create2_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_fd_datasync(struct lwp *l,
    const struct cloudabi_sys_fd_datasync_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_fd_dup(struct lwp *l, const struct cloudabi_sys_fd_dup_args *uap,
    register_t *retval)
{
	struct sys_dup_args sys_dup_args;

	SCARG(&sys_dup_args, fd) = SCARG(uap, from);
	return (sys_dup(l, &sys_dup_args, retval));
}

int
cloudabi_sys_fd_replace(struct lwp *l,
    const struct cloudabi_sys_fd_replace_args *uap, register_t *retval)
{
	struct sys_dup2_args sys_dup2_args;
	register_t discard[2];

	/* This system call is supposed to return zero upon success. */
	/* TODO(ed): This should disallow dupping to unused descriptors. */
	SCARG(&sys_dup2_args, from) = SCARG(uap, from);
	SCARG(&sys_dup2_args, to) = SCARG(uap, to);
	return (sys_dup2(l, &sys_dup2_args, discard));
}

int
cloudabi_sys_fd_seek(struct lwp *l, const struct cloudabi_sys_fd_seek_args *uap,
    register_t *retval)
{
	struct sys_lseek_args sys_lseek_args;

	SCARG(&sys_lseek_args, fd) = SCARG(uap, fd);
	SCARG(&sys_lseek_args, offset) = SCARG(uap, offset);

	switch (SCARG(uap, whence)) {
	case CLOUDABI_WHENCE_CUR:
		SCARG(&sys_lseek_args, whence) = SEEK_CUR;
		break;
	case CLOUDABI_WHENCE_END:
		SCARG(&sys_lseek_args, whence) = SEEK_END;
		break;
	case CLOUDABI_WHENCE_SET:
		SCARG(&sys_lseek_args, whence) = SEEK_SET;
		break;
	default:
		return (EINVAL);
	}

	return (sys_lseek(l, &sys_lseek_args, retval));
}

int
cloudabi_sys_fd_stat_get(struct lwp *l,
    const struct cloudabi_sys_fd_stat_get_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_fd_stat_put(struct lwp *l,
    const struct cloudabi_sys_fd_stat_put_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_fd_sync(struct lwp *l, const struct cloudabi_sys_fd_sync_args *uap,
    register_t *retval)
{

	return (ENOSYS);
}
