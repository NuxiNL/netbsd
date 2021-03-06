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
#include <sys/kmem.h>
#include <sys/lwp.h>
#include <sys/proc.h>

#include <compat/cloudabi64/cloudabi64_syscalldefs.h>
#include <compat/cloudabi64/cloudabi64_syscallargs.h>

int
cloudabi64_sys_thread_create(struct lwp *l,
    const struct cloudabi64_sys_thread_create_args *uap, register_t *retval)
{
	cloudabi64_threadattr_t *threadattr;
	lwpid_t lid;
	int error;

	/* Copy in the thread creation attributes. */
	threadattr = kmem_alloc(sizeof(*threadattr), KM_SLEEP);
	error = copyin(SCARG(uap, attr), threadattr, sizeof(*threadattr));
	if (error != 0) {
		kmem_free(threadattr, sizeof(*threadattr));
		return (error);
	}

	/*
	 * Create a new thread. Provide the attributes to
	 * cloudabi64_startlwp().
	 */
	error = do_lwp_create(l, threadattr, LWP_DETACHED, &lid);
	if (error != 0) {
		kmem_free(threadattr, sizeof(*threadattr));
		return (error);
	}

	/*
	 * Generate unique thread ID using the same scheme as cloudabi_gettid().
	 */
	retval[0] = lid * PID_MAX + l->l_proc->p_pid;
	return (0);
}
