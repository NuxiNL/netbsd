/*-
 * Copyright (c) 2009 Robert N. M. Watson
 * Copyright (c) 2015 Nuxi, https://nuxi.nl/
 * All rights reserved.
 *
 * This software was developed at the University of Cambridge Computer
 * Laboratory with support from a grant from Google, Inc.
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
#include <sys/atomic.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/kauth.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/procdesc.h>
#include <sys/ptrace.h>
#include <sys/queue.h>
#include <sys/stat.h>

/*-
 * struct procdesc describes a process descriptor, and essentially consists
 * of two pointers -- one to the file descriptor, and one to the process.
 * When both become NULL, the process descriptor will be freed.  An important
 * invariant is that there is only ever one process descriptor for a process,
 * so a single file pointer will suffice.
 *
 * Locking key:
 * (p) - Protected by the process descriptor mutex.
 * (r) - Atomic reference count.
 * (t) - Protected by the proc_lock.
 */
struct procdesc {
	/*
	 * Basic process descriptor state: the process, and process descriptor
	 * refcount.
	 */
	struct proc	*pd_proc;		/* (t) Process. */
	u_int		 pd_refcount;		/* (r) Reference count. */

	/*
	 * In-flight data and notification of events.
	 */
	int		 pd_flags;		/* (p) PD_ flags. */
	u_short		 pd_xstat;		/* (p) Exit status. */
	struct klist	 pd_klist;		/* (p) Event notification. */
	kmutex_t	 pd_lock;		/* Protect data + events. */
};

/*
 * Flags for the pd_flags field.
 */
#define	PDF_CLOSED	0x00000001	/* Descriptor has closed. */
#define	PDF_EXITED	0x00000002	/* Process exited. */

static int	procdesc_stat(file_t *, struct stat *);
static int	procdesc_close(file_t *);
static int	procdesc_kqfilter(file_t *, struct knote *);
static void	procdesc_restart(file_t *);

static struct fileops procdesc_ops = {
	.fo_read = fbadop_read,
	.fo_write = fbadop_write,
	.fo_ioctl = fbadop_ioctl,
	.fo_fcntl = fnullop_fcntl,
	.fo_poll = fnullop_poll,
	.fo_stat = procdesc_stat,
	.fo_close = procdesc_close,
	.fo_kqfilter = procdesc_kqfilter,
	.fo_restart = procdesc_restart,
};

void
procdesc_new(struct proc *p)
{
	struct procdesc *pd;

	pd = malloc(sizeof(*pd), M_PROCDESC, M_WAITOK);
	pd->pd_proc = p;
	p->p_procdesc = pd;
	pd->pd_flags = 0;
	mutex_init(&pd->pd_lock, MUTEX_DEFAULT, IPL_NONE);
	SLIST_INIT(&pd->pd_klist);

	/*
	 * Process descriptors start out with two references: one from their
	 * struct file, and the other from their struct proc.
	 */
	pd->pd_refcount = 2;
}

void
procdesc_finit(struct procdesc *pdp, struct file *fp)
{

	fp->f_flag = FREAD | FWRITE;
	fp->f_type = DTYPE_PROCDESC;
	fp->f_ops = &procdesc_ops;
	fp->f_procdesc = pdp;
}

static void
procdesc_free(struct procdesc *pd)
{

	if (atomic_dec_uint_nv(&pd->pd_refcount) == 0) {
		KASSERT(pd->pd_proc == NULL);
		KASSERT((pd->pd_flags & PDF_CLOSED) != 0);
		KASSERT(SLIST_EMPTY(&pd->pd_klist));

		mutex_destroy(&pd->pd_lock);
		free(pd, M_PROCDESC);
	}
}

int
procdesc_exit(struct proc *p)
{
	struct procdesc *pd;

	KASSERT(mutex_owned(proc_lock));
	KASSERT(p->p_procdesc != NULL);

	pd = p->p_procdesc;

	mutex_enter(&pd->pd_lock);
	KASSERT((pd->pd_flags & PDF_CLOSED) == 0 || p->p_pptr == initproc);

	pd->pd_flags |= PDF_EXITED;
	pd->pd_xstat = p->p_xstat;

	/*
	 * If the process descriptor has been closed, then we have nothing
	 * to do; return 1 so that init will get SIGCHLD and do the reaping.
	 * Clean up the procdesc now rather than letting it happen during
	 * that reap.
	 */
	if (pd->pd_flags & PDF_CLOSED) {
		mutex_exit(&pd->pd_lock);
		pd->pd_proc = NULL;
		p->p_procdesc = NULL;
		procdesc_free(pd);
		return (1);
	}
	KNOTE(&pd->pd_klist, NOTE_EXIT);
	mutex_exit(&pd->pd_lock);
	return (0);
}

/*
 * When a process descriptor is reaped, perhaps as a result of close() or
 * pdwait(), release the process's reference on the process descriptor.
 */
void
procdesc_reap(struct proc *p)
{
	struct procdesc *pd;

	KASSERT(mutex_owned(proc_lock));
	KASSERT(p->p_procdesc != NULL);

	pd = p->p_procdesc;
	pd->pd_proc = NULL;
	p->p_procdesc = NULL;
	procdesc_free(pd);
}

static int
procdesc_stat(file_t *fp, struct stat *sb)
{
	struct procdesc *pd;
	struct timeval pstart;

	/*
	 * XXXRW: Perhaps we should cache some more information from the
	 * process so that we can return it reliably here even after it has
	 * died.  For example, caching its credential data.
	 */
	bzero(sb, sizeof(*sb));
	pd = fp->f_procdesc;
	mutex_enter(proc_lock);
	if (pd->pd_proc != NULL) {
		mutex_enter(pd->pd_proc->p_lock);

		/* Set birth and [acm] times to process start time. */
		pstart = pd->pd_proc->p_stats->p_start;
		TIMEVAL_TO_TIMESPEC(&pstart, &sb->st_birthtim);
		sb->st_atim = sb->st_birthtim;
		sb->st_ctim = sb->st_birthtim;
		sb->st_mtim = sb->st_birthtim;
		if (pd->pd_proc->p_stat != SZOMB)
			sb->st_mode = S_IFREG | S_IRWXU;
		else
			sb->st_mode = S_IFREG;
		sb->st_uid = kauth_cred_getuid(pd->pd_proc->p_cred);
		sb->st_gid = kauth_cred_getgid(pd->pd_proc->p_cred);
		mutex_exit(pd->pd_proc->p_lock);
	} else
		sb->st_mode = S_IFREG;
	mutex_exit(proc_lock);
	return (0);
}

/*
 * procdesc_close() - last close on a process descriptor.  If the process is
 * still running, terminate with SIGKILL and let init(8) clean up the mess; if
 * not, we have to clean up the zombie ourselves.
 */
static int
procdesc_close(file_t *fp)
{
	struct procdesc *pd;
	struct proc *p;

	KASSERT(fp->f_type == DTYPE_PROCDESC);

	pd = fp->f_procdesc;

	mutex_enter(proc_lock);
	mutex_enter(&pd->pd_lock);
	pd->pd_flags |= PDF_CLOSED;
	mutex_exit(&pd->pd_lock);
	p = pd->pd_proc;
	if (p == NULL) {
		/*
		 * This is the case where process' exit status was already
		 * collected and procdesc_reap() was already called.
		 */
		mutex_exit(proc_lock);
	} else {
		mutex_enter(p->p_lock);
		if (p->p_stat == SZOMB) {
			/*
			 * If the process is already dead and just awaiting
			 * reaping, do that now.  This will release the
			 * process's reference to the process descriptor when it
			 * calls back into procdesc_reap().
			 */
			mutex_exit(p->p_lock);
			proc_free(p, NULL);
		} else {
			/*
			 * If the process is not yet dead, we need to kill it,
			 * but we can't wait around synchronously for it to go
			 * away, as that path leads to madness (and deadlocks).
			 * First, detach the process from its descriptor so that
			 * its exit status will be reported normally.
			 */
			pd->pd_proc = NULL;
			p->p_procdesc = NULL;
			procdesc_free(pd);

			/*
			 * Next, reparent it to init(8) so that there's someone
			 * to pick up the pieces; finally, terminate with
			 * prejudice.
			 */
			p->p_exitsig = SIGCHLD;
			proc_reparent(p, initproc);
			mutex_exit(p->p_lock);
			psignal(p, SIGKILL);
			mutex_exit(proc_lock);
		}
	}

	/*
	 * Release the file descriptor's reference on the process descriptor.
	 */
	procdesc_free(pd);
	return (0);
}

static void
procdesc_kqops_detach(struct knote *kn)
{
	struct procdesc *pd;

	pd = ((file_t *)kn->kn_obj)->f_procdesc;
	mutex_enter(&pd->pd_lock);
	SLIST_REMOVE(&pd->pd_klist, kn, knote, kn_selnext);
	mutex_exit(&pd->pd_lock);
}

static int
procdesc_kqops_event(struct knote *kn, long hint)
{
	struct procdesc *pd;
	u_int event;

	pd = ((file_t *)kn->kn_obj)->f_procdesc;
	if (hint == 0) {
		/*
		 * Initial test after registration. Generate a NOTE_EXIT in
		 * case the process already terminated before registration.
		 */
		event = pd->pd_flags & PDF_EXITED ? NOTE_EXIT : 0;
	} else {
		/* Mask off extra data. */
		event = (u_int)hint & NOTE_PCTRLMASK;
	}

	/* If the user is interested in this event, record it. */
	if (kn->kn_sfflags & event)
		kn->kn_fflags |= event;

	/* Process is gone, so flag the event as finished. */
	if (event == NOTE_EXIT) {
		kn->kn_flags |= EV_EOF | EV_ONESHOT;
		if (kn->kn_fflags & NOTE_EXIT)
			kn->kn_data = pd->pd_xstat;
		return (1);
	}

	return (kn->kn_fflags != 0);
}

static struct filterops procdesc_kqops = {
	.f_isfd = 1,
	.f_detach = procdesc_kqops_detach,
	.f_event = procdesc_kqops_event,
};

static int
procdesc_kqfilter(file_t *fp, struct knote *kn)
{
	struct klist *klist;
	struct procdesc *pd;

	pd = fp->f_procdesc;
	switch (kn->kn_filter) {
	case EVFILT_PROCDESC:
		kn->kn_fop = &procdesc_kqops;
		kn->kn_flags |= EV_CLEAR;
		klist = &pd->pd_klist;
		break;
	default:
		return (EINVAL);
	}

	mutex_enter(&pd->pd_lock);
	SLIST_INSERT_HEAD(klist, kn, kn_selnext);
	mutex_exit(&pd->pd_lock);
	return (0);
}

static void
procdesc_restart(file_t *fp)
{

	/* TODO(ed): Does this need an explicit implementation? */
}
