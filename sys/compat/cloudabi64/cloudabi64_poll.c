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
#include <sys/event.h>

#include <compat/cloudabi/cloudabi_util.h>

#include <compat/cloudabi64/cloudabi64_syscalldefs.h>
#include <compat/cloudabi64/cloudabi64_syscallargs.h>

/* Converts CloudABI's event objects to NetBSD's struct kevent. */
static int
cloudabi64_kevent_fetch_changes(void *arg, const struct kevent *inp,
    struct kevent *kevp, size_t index, int count)
{
	const cloudabi64_event_t *in = (const cloudabi64_event_t *)inp + index;

	while (count-- > 0) {
		cloudabi64_event_t ev;
		int error;

		error = copyin(in++, &ev, sizeof(ev));
		if (error != 0)
			return (error);

		switch (ev.type) {
		case CLOUDABI_EVENT_TYPE_CLOCK: {
			cloudabi_timestamp_t ts;

			/* Convert timestamp to a relative value. */
			if (ev.clock.timeout > 0) {
				/* Non-zero timestamp. */
				error = cloudabi_clock_time_get(curlwp,
				    ev.clock.clock_id, &ts);
				if (error != 0)
					return (error);
				ts = ts > ev.clock.timeout ? 0 :
				    ev.clock.timeout - ts;
				if (ts > INTPTR_MAX)
					ts = INTPTR_MAX;
			} else {
				/* Shortcut: no need to ask for the time. */
				ts = 0;
			}
			kevp->filter = EVFILT_TIMER;
			kevp->ident = ev.clock.identifier;
			kevp->fflags = 0;
			kevp->data = ts / 1000000;
			break;
		}
		case CLOUDABI_EVENT_TYPE_FD_READ:
			kevp->filter = EVFILT_READ;
			kevp->ident = ev.fd_readwrite.fd;
			/* TODO(ed): Fix the poll() case. */
			kevp->fflags = 0;
			kevp->data = 0;
			break;
		case CLOUDABI_EVENT_TYPE_FD_WRITE:
			kevp->filter = EVFILT_WRITE;
			kevp->ident = ev.fd_readwrite.fd;
			kevp->fflags = 0;
			kevp->data = 0;
			break;
#if 0 /* TODO(ed): Implement. */
		case CLOUDABI_EVENT_TYPE_PROC_TERMINATE:
			kevp->filter = EVFILT_PROCDESC;
			kevp->ident = ev.proc_terminate.fd;
			kevp->fflags = NOTE_EXIT;
			kevp->data = 0;
			break;
#endif
		default:
			kevp->filter = 0;
			kevp->ident = 0;
			kevp->fflags = 0;
			kevp->data = 0;
			break;
		}
		/* TODO(ed): Use proper flags if not anonymous. */
		kevp->flags = EV_ADD | EV_ONESHOT;
		kevp->udata = ev.userdata;
		++kevp;
	}
	return (0);
}

/* Converts NetBSD's struct kevent to CloudABI's event objects. */
static int
cloudabi64_kevent_put_events(void *arg, struct kevent *kevp,
    struct kevent *outp, size_t index, int count)
{
	cloudabi64_event_t *out = (cloudabi64_event_t *)outp + index;

	while (count-- > 0) {
		cloudabi64_event_t ev;
		int error;

		memset(&ev, '\0', sizeof(ev));
		switch (kevp->filter) {
		case EVFILT_TIMER:
			ev.type = CLOUDABI_EVENT_TYPE_CLOCK;
			ev.clock.identifier = kevp->ident;
			break;
		case EVFILT_READ:
		case EVFILT_WRITE:
			ev.type = kevp->filter == EVFILT_READ ?
			    CLOUDABI_EVENT_TYPE_FD_READ :
			    CLOUDABI_EVENT_TYPE_FD_WRITE;
			ev.fd_readwrite.fd = kevp->ident;
			ev.fd_readwrite.nbytes = kevp->data;
			if ((kevp->flags & EV_EOF) != 0) {
				ev.fd_readwrite.flags |=
				    CLOUDABI_EVENT_FD_READWRITE_HANGUP;
			}
			break;
#if 0 /* TODO(ed): Implement. */
		case EVFILT_PROCDESC:
			ev.type = CLOUDABI_EVENT_TYPE_PROC_TERMINATE;
			ev.proc_terminate.fd = kevp->ident;
			if (WIFSIGNALED(kevp->data)) {
				/* Process terminated due to a signal. */
				ev.proc_terminate.signal =
				    convert_signal(WTERMSIG(kevp->data));
				ev.proc_terminate.exitcode = 0;
			} else {
				/* Process exited. */
				ev.proc_terminate.signal = 0;
				ev.proc_terminate.exitcode =
				    WEXITSTATUS(kevp->data);
			}
			break;
#endif
		}
		ev.userdata = kevp->udata;
		if (kevp->flags & EV_ERROR)
			ev.error = cloudabi_convert_errno(kevp->data);
		++kevp;

		error = copyout(&ev, out++, sizeof(ev));
		if (error != 0)
			return (error);
	}
	return (0);
}

static struct kevent_ops cloudabi64_kevent_ops = {
	.keo_fetch_changes	= cloudabi64_kevent_fetch_changes,
	.keo_put_events		= cloudabi64_kevent_put_events
};

int
cloudabi64_sys_poll(struct lwp *l, const struct cloudabi64_sys_poll_args *uap,
    register_t *retval)
{
	int error;

	/*
	 * Bandaid to support CloudABI futex constructs that are not
	 * implemented through NetBSD's kqueue().
	 */
	if (SCARG(uap, fd) == CLOUDABI_POLL_ONCE && SCARG(uap, nin) == 1 &&
	    SCARG(uap, nout) >= 1) {
		cloudabi64_event_t ev;
		error = copyin(SCARG(uap, in), &ev, sizeof(ev));
		if (error != 0)
			return (error);
		if (ev.type == CLOUDABI_EVENT_TYPE_CONDVAR) {
			/* Wait on a condition variable. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_condvar_wait(
			        l, (cloudabi_condvar_t *)ev.condvar.condvar,
			        (cloudabi_lock_t *)ev.condvar.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return (copyout(&ev, SCARG(uap, out), sizeof(ev)));
		} else if (ev.type == CLOUDABI_EVENT_TYPE_LOCK_RDLOCK) {
			/* Acquire a read lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_rdlock(
			        l, (cloudabi_lock_t *)ev.lock.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return (copyout(&ev, SCARG(uap, out), sizeof(ev)));
		} else if (ev.type == CLOUDABI_EVENT_TYPE_LOCK_WRLOCK) {
			/* Acquire a write lock. */
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_wrlock(
			        l, (cloudabi_lock_t *)ev.lock.lock,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return (copyout(&ev, SCARG(uap, out), sizeof(ev)));
		}
	} else if (SCARG(uap, fd) == CLOUDABI_POLL_ONCE &&
	    SCARG(uap, nin) == 2 && SCARG(uap, nout) >= 2) {
		cloudabi64_event_t ev[2];
		error = copyin(SCARG(uap, in), &ev, sizeof(ev));
		if (error != 0)
			return (error);
		if (ev[0].type == CLOUDABI_EVENT_TYPE_CONDVAR &&
		    ev[1].type == CLOUDABI_EVENT_TYPE_CLOCK) {
			/* Wait for a condition variable with timeout. */
			error = cloudabi_futex_condvar_wait(
			    l, (cloudabi_condvar_t *)ev[0].condvar.condvar,
			    (cloudabi_lock_t *)ev[0].condvar.lock,
			    ev[1].clock.clock_id, ev[1].clock.timeout,
			    ev[1].clock.precision);
			if (error == ETIMEDOUT) {
				ev[1].error = 0;
				retval[0] = 1;
				return (copyout(&ev[1], SCARG(uap, out),
				    sizeof(ev[1])));
			}

			ev[0].error = cloudabi_convert_errno(error);
			retval[0] = 1;
			return (copyout(&ev[0], SCARG(uap, out),
			    sizeof(ev[0])));
		} else if (ev[0].type == CLOUDABI_EVENT_TYPE_LOCK_RDLOCK &&
		    ev[1].type == CLOUDABI_EVENT_TYPE_CLOCK) {
			/* Acquire a read lock with a timeout. */
			error = cloudabi_futex_lock_rdlock(
			    l, (cloudabi_lock_t *)ev[0].lock.lock,
			    ev[1].clock.clock_id, ev[1].clock.timeout,
			    ev[1].clock.precision);
			if (error == ETIMEDOUT) {
				ev[1].error = 0;
				retval[0] = 1;
				return (copyout(&ev[1], SCARG(uap, out),
				    sizeof(ev[1])));
			}

			ev[0].error = cloudabi_convert_errno(error);
			retval[0] = 1;
			return (copyout(&ev[0], SCARG(uap, out),
			    sizeof(ev[0])));
		} else if (ev[0].type == CLOUDABI_EVENT_TYPE_LOCK_WRLOCK &&
		    ev[1].type == CLOUDABI_EVENT_TYPE_CLOCK) {
			/* Acquire a write lock with a timeout. */
			error = cloudabi_futex_lock_wrlock(
			    l, (cloudabi_lock_t *)ev[0].lock.lock,
			    ev[1].clock.clock_id, ev[1].clock.timeout,
			    ev[1].clock.precision);
			if (error == ETIMEDOUT) {
				ev[1].error = 0;
				retval[0] = 1;
				return (copyout(&ev[1], SCARG(uap, out),
				    sizeof(ev[1])));
			}

			ev[0].error = cloudabi_convert_errno(error);
			retval[0] = 1;
			return (copyout(&ev[0], SCARG(uap, out),
			    sizeof(ev[0])));
		}
	}

	if (SCARG(uap, fd) == CLOUDABI_POLL_ONCE) {
		/* Anonymous poll call. */
		error = kevent1_anonymous(retval,
		    (const struct kevent *)SCARG(uap, in),
		    SCARG(uap, nin), (struct kevent *)SCARG(uap, out),
		    SCARG(uap, nout), NULL, &cloudabi64_kevent_ops);
	} else {
		/* Stateful poll call with a file descriptor. */
		error = kevent1(retval, SCARG(uap, fd),
		    (const struct kevent *)SCARG(uap, in),
		    SCARG(uap, nin), (struct kevent *)SCARG(uap, out),
		    SCARG(uap, nout), NULL, &cloudabi64_kevent_ops);
	}
	return (error);
}
