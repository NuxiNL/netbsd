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
#include <sys/cprng.h>
#include <sys/proc.h>
#include <sys/uio.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>

int
cloudabi_sys_random_get(struct lwp *l,
    const struct cloudabi_sys_random_get_args *uap, register_t *retval)
{
	struct iovec iov = {
		.iov_base = SCARG(uap, buf),
		.iov_len = SCARG(uap, nbyte),
	};
	struct uio uio = {
		.uio_iov = &iov,
		.uio_iovcnt = 1,
		.uio_resid = iov.iov_len,
		.uio_rw = UIO_READ,
		.uio_vmspace = l->l_proc->p_vmspace,
	};

	/* Move random data to userspace. */
	while (uio.uio_resid > 0) {
		char buf[1024];
		size_t len;
		int error;

		len = MIN(sizeof(buf), uio.uio_resid);
		cprng_strong(kern_cprng, buf, len, 0);
		error = uiomove(buf, len, &uio);
		if (error != 0)
			return (error);
	}
	return (0);
}
