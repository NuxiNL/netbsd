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
#include <sys/lwp.h>
#include <sys/proc.h>
#include <sys/syscallargs.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>
#include <compat/cloudabi/cloudabi_util.h>

cloudabi_tid_t
cloudabi_gettid(struct lwp *l)
{

	/* Unique thread ID. */
	return (l->l_lid * PID_MAX + l->l_proc->p_pid);
}

int
cloudabi_sys_thread_exit(struct lwp *l,
    const struct cloudabi_sys_thread_exit_args *uap, register_t *retval)
{
	struct cloudabi_sys_lock_unlock_args cloudabi_sys_lock_unlock_args;

        /* Wake up joining thread. */
	SCARG(&cloudabi_sys_lock_unlock_args, lock) = SCARG(uap, lock);
	SCARG(&cloudabi_sys_lock_unlock_args, scope) = SCARG(uap, scope);
	cloudabi_sys_lock_unlock(l, &cloudabi_sys_lock_unlock_args, retval);

        /* Terminate thread. */
	lwp_exit(l);
	return (0);
}

int
cloudabi_sys_thread_yield(struct lwp *l, const void *uap, register_t *retval)
{

	return (sys_sched_yield(l, NULL, retval));
}
