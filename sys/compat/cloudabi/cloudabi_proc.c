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
#include <sys/proc.h>
#include <sys/syscallargs.h>
#include <sys/wait.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>

int
cloudabi_sys_proc_exit(struct lwp *l,
    const struct cloudabi_sys_proc_exit_args *uap, register_t *retval)
{
	struct sys_exit_args sys_exit_args;

	SCARG(&sys_exit_args, rval) = SCARG(uap, rval);
	return sys_exit(l, &sys_exit_args, retval);
}

int
cloudabi_sys_proc_fork(struct lwp *l, const void *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_proc_raise(struct lwp *l,
    const struct cloudabi_sys_proc_raise_args *uap, register_t *retval)
{

	return (ENOSYS);
}
