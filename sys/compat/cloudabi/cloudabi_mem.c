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
#include <sys/mman.h>
#include <sys/syscallargs.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>
#include <compat/cloudabi/cloudabi_syscalldefs.h>

/* Converts CloudABI's memory protection flags to NetBSD's. */
static int
convert_mprot(cloudabi_mprot_t in)
{
	int out;

	out = 0;
	if (in & CLOUDABI_PROT_EXEC)
		out |= PROT_EXEC;
	if (in & CLOUDABI_PROT_WRITE)
		out |= PROT_WRITE;
	if (in & CLOUDABI_PROT_READ)
		out |= PROT_READ;
	return (out);
}

int
cloudabi_sys_mem_advise(struct lwp *l,
    const struct cloudabi_sys_mem_advise_args *uap, register_t *retval)
{
	struct sys_madvise_args sys_madvise_args;

	SCARG(&sys_madvise_args, addr) = SCARG(uap, addr);
	SCARG(&sys_madvise_args, len) = SCARG(uap, len);

	switch (SCARG(uap, advice)) {
	case CLOUDABI_ADVICE_DONTNEED:
		SCARG(&sys_madvise_args, behav) = MADV_DONTNEED;
		break;
	case CLOUDABI_ADVICE_NORMAL:
		SCARG(&sys_madvise_args, behav) = MADV_NORMAL;
		break;
	case CLOUDABI_ADVICE_RANDOM:
		SCARG(&sys_madvise_args, behav) = MADV_RANDOM;
		break;
	case CLOUDABI_ADVICE_SEQUENTIAL:
		SCARG(&sys_madvise_args, behav) = MADV_SEQUENTIAL;
		break;
	case CLOUDABI_ADVICE_WILLNEED:
		SCARG(&sys_madvise_args, behav) = MADV_WILLNEED;
		break;
	default:
		return (EINVAL);
	}

	return (sys_madvise(l, &sys_madvise_args, retval));
}

int
cloudabi_sys_mem_lock(struct lwp *l,
    const struct cloudabi_sys_mem_lock_args *uap, register_t *retval)
{
	struct sys_mlock_args sys_mlock_args;

	SCARG(&sys_mlock_args, addr) = SCARG(uap, addr);
	SCARG(&sys_mlock_args, len) = SCARG(uap, len);

	return (sys_mlock(l, &sys_mlock_args, retval));
}

int
cloudabi_sys_mem_map(struct lwp *l, const struct cloudabi_sys_mem_map_args *uap,
    register_t *retval)
{
	struct sys_mmap_args sys_mmap_args;

	SCARG(&sys_mmap_args, addr) = SCARG(uap, addr);
	SCARG(&sys_mmap_args, len) = SCARG(uap, len);
	SCARG(&sys_mmap_args, prot) = convert_mprot(SCARG(uap, prot));
	SCARG(&sys_mmap_args, fd) = SCARG(uap, fd);
	SCARG(&sys_mmap_args, pos) = SCARG(uap, off);

	/* Translate flags. */
	SCARG(&sys_mmap_args, flags) = 0;
	if (SCARG(uap, flags) & CLOUDABI_MAP_ANON)
		SCARG(&sys_mmap_args, flags) |= MAP_ANON;
	if (SCARG(uap, flags) & CLOUDABI_MAP_FIXED)
		SCARG(&sys_mmap_args, flags) |= MAP_FIXED;
	if (SCARG(uap, flags) & CLOUDABI_MAP_PRIVATE)
		SCARG(&sys_mmap_args, flags) |= MAP_PRIVATE;
	if (SCARG(uap, flags) & CLOUDABI_MAP_SHARED)
		SCARG(&sys_mmap_args, flags) |= MAP_SHARED;

	return (sys_mmap(l, &sys_mmap_args, retval));
}

int
cloudabi_sys_mem_protect(struct lwp *l,
    const struct cloudabi_sys_mem_protect_args *uap, register_t *retval)
{
	struct sys_mprotect_args sys_mprotect_args;

	SCARG(&sys_mprotect_args, addr) = SCARG(uap, addr);
	SCARG(&sys_mprotect_args, len) = SCARG(uap, len);
	SCARG(&sys_mprotect_args, prot) = convert_mprot(SCARG(uap, prot));

	return (sys_mprotect(l, &sys_mprotect_args, retval));
}

int
cloudabi_sys_mem_sync(struct lwp *l,
    const struct cloudabi_sys_mem_sync_args *uap, register_t *retval)
{
	struct sys___msync13_args sys___msync13_args;

	SCARG(&sys___msync13_args, addr) = SCARG(uap, addr);
	SCARG(&sys___msync13_args, len) = SCARG(uap, len);

	/* Convert flags. */
	SCARG(&sys___msync13_args, flags) = 0;
	switch (SCARG(uap, flags) & (CLOUDABI_MS_ASYNC | CLOUDABI_MS_SYNC)) {
	case CLOUDABI_MS_ASYNC:
		SCARG(&sys___msync13_args, flags) |= MS_ASYNC;
		break;
	case CLOUDABI_MS_SYNC:
		SCARG(&sys___msync13_args, flags) |= MS_SYNC;
		break;
	default:
		return (EINVAL);
	}
	if ((SCARG(uap, flags) & CLOUDABI_MS_INVALIDATE) != 0)
		SCARG(&sys___msync13_args, flags) |= MS_INVALIDATE;

	return (sys___msync13(l, &sys___msync13_args, retval));
}

int
cloudabi_sys_mem_unlock(struct lwp *l,
    const struct cloudabi_sys_mem_unlock_args *uap, register_t *retval)
{
	struct sys_munlock_args sys_munlock_args;

	SCARG(&sys_munlock_args, addr) = SCARG(uap, addr);
	SCARG(&sys_munlock_args, len) = SCARG(uap, len);

	return (sys_munlock(l, &sys_munlock_args, retval));
}

int
cloudabi_sys_mem_unmap(struct lwp *l,
    const struct cloudabi_sys_mem_unmap_args *uap, register_t *retval)
{
	struct sys_munmap_args sys_munmap_args;

	SCARG(&sys_munmap_args, addr) = SCARG(uap, addr);
	SCARG(&sys_munmap_args, len) = SCARG(uap, len);

	return (sys_munmap(l, &sys_munmap_args, retval));
}
