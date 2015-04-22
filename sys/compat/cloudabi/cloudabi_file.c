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

#include <compat/cloudabi/cloudabi_syscallargs.h>

int
cloudabi_sys_file_advise(struct lwp *l,
    const struct cloudabi_sys_file_advise_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_allocate(struct lwp *l,
     const struct cloudabi_sys_file_allocate_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_create(struct lwp *l,
    const struct cloudabi_sys_file_create_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_link(struct lwp *l,
    const struct cloudabi_sys_file_link_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_open(struct lwp *l,
    const struct cloudabi_sys_file_open_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_readdir(struct lwp *l,
    const struct cloudabi_sys_file_readdir_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_readlink(struct lwp *l,
    const struct cloudabi_sys_file_readlink_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_rename(struct lwp *l,
    const struct cloudabi_sys_file_rename_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_stat_fget(struct lwp *l,
    const struct cloudabi_sys_file_stat_fget_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_stat_fput(struct lwp *l,
    const struct cloudabi_sys_file_stat_fput_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_stat_get(struct lwp *l,
    const struct cloudabi_sys_file_stat_get_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_stat_put(struct lwp *l,
    const struct cloudabi_sys_file_stat_put_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_symlink(struct lwp *l,
    const struct cloudabi_sys_file_symlink_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_unlink(struct lwp *l,
    const struct cloudabi_sys_file_unlink_args *uap, register_t *retval)
{

	return (ENOSYS);
}
