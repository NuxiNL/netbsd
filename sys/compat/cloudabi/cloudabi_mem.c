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
cloudabi_sys_mem_advise(struct lwp *l,
    const struct cloudabi_sys_mem_advise_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_mem_lock(struct lwp *l,
    const struct cloudabi_sys_mem_lock_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_mem_map(struct lwp *l, const struct cloudabi_sys_mem_map_args *uap,
    register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_mem_protect(struct lwp *l,
    const struct cloudabi_sys_mem_protect_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_mem_sync(struct lwp *l,
    const struct cloudabi_sys_mem_sync_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_mem_unlock(struct lwp *l,
    const struct cloudabi_sys_mem_unlock_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_mem_unmap(struct lwp *l,
    const struct cloudabi_sys_mem_unmap_args *uap, register_t *retval)
{

	return (ENOSYS);
}
