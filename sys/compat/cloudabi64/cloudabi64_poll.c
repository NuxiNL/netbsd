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
#include <sys/wait.h>

#include <compat/cloudabi/cloudabi_util.h>

#include <compat/cloudabi64/cloudabi64_syscalldefs.h>
#include <compat/cloudabi64/cloudabi64_syscallargs.h>

/* Converts a NetBSD signal number to a CloudABI signal number. */
static cloudabi_signal_t
convert_signal(int sig)
{
	static const cloudabi_signal_t signals[] = {
		[SIGABRT]	= CLOUDABI_SIGABRT,
		[SIGALRM]	= CLOUDABI_SIGALRM,
		[SIGBUS]	= CLOUDABI_SIGBUS,
		[SIGCHLD]	= CLOUDABI_SIGCHLD,
		[SIGCONT]	= CLOUDABI_SIGCONT,
		[SIGFPE]	= CLOUDABI_SIGFPE,
		[SIGHUP]	= CLOUDABI_SIGHUP,
		[SIGILL]	= CLOUDABI_SIGILL,
		[SIGINT]	= CLOUDABI_SIGINT,
		[SIGKILL]	= CLOUDABI_SIGKILL,
		[SIGPIPE]	= CLOUDABI_SIGPIPE,
		[SIGQUIT]	= CLOUDABI_SIGQUIT,
		[SIGSEGV]	= CLOUDABI_SIGSEGV,
		[SIGSTOP]	= CLOUDABI_SIGSTOP,
		[SIGSYS]	= CLOUDABI_SIGSYS,
		[SIGTERM]	= CLOUDABI_SIGTERM,
		[SIGTRAP]	= CLOUDABI_SIGTRAP,
		[SIGTSTP]	= CLOUDABI_SIGTSTP,
		[SIGTTIN]	= CLOUDABI_SIGTTIN,
		[SIGTTOU]	= CLOUDABI_SIGTTOU,
		[SIGURG]	= CLOUDABI_SIGURG,
		[SIGUSR1]	= CLOUDABI_SIGUSR1,
		[SIGUSR2]	= CLOUDABI_SIGUSR2,
		[SIGVTALRM]	= CLOUDABI_SIGVTALRM,
		[SIGXCPU]	= CLOUDABI_SIGXCPU,
		[SIGXFSZ]	= CLOUDABI_SIGXFSZ,
	};

	/* Convert unknown signals to SIGABRT. */
	if (sig < 0 || sig >= __arraycount(signals) || signals[sig] == 0)
		return (SIGABRT);
	return (signals[sig]);
}

/* Converts CloudABI's event objects to NetBSD's struct kevent. */
static int
cloudabi64_kevent_fetch_changes(void *arg, const struct kevent *inp,
    struct kevent *kevp, size_t index, int count)
{
	cloudabi64_subscription_t sub;
	const cloudabi64_subscription_t *in;
	cloudabi_timestamp_t ts;
	int error;

	in = (const cloudabi64_subscription_t *)inp + index;
	while (count-- > 0) {
		error = copyin(in++, &sub, sizeof(sub));
		if (error != 0)
			return (error);

		memset(kevp, '\0', sizeof(*kevp));
		kevp->udata = sub.userdata;
		switch (sub.type) {
		case CLOUDABI_EVENTTYPE_CLOCK:
			kevp->filter = EVFILT_TIMER;
			kevp->ident = sub.clock.identifier;
			if ((sub.clock.flags &
			    CLOUDABI_SUBSCRIPTION_CLOCK_ABSTIME) != 0 &&
			    sub.clock.timeout > 0) {
				/* Convert absolute timestamp to a relative. */
				error = cloudabi_clock_time_get(curlwp,
				    sub.clock.clock_id, &ts);
				if (error != 0)
					return (error);
				ts = ts > sub.clock.timeout ? 0 :
				    sub.clock.timeout - ts;
			} else {
				/* Relative timestamp. */
				ts = sub.clock.timeout;
			}
			ts /= 1000000;
			kevp->data = ts > INT64_MAX ? INT64_MAX : ts;
			/* Prevent returning EINVAL. */
			if (kevp->data == 0)
				kevp->data = 1;
			break;
		case CLOUDABI_EVENTTYPE_FD_READ:
			kevp->filter = EVFILT_READ;
			kevp->ident = sub.fd_readwrite.fd;
			/* TODO(ed): Fix the poll() case. */
			break;
		case CLOUDABI_EVENTTYPE_FD_WRITE:
			kevp->filter = EVFILT_WRITE;
			kevp->ident = sub.fd_readwrite.fd;
			break;
		case CLOUDABI_EVENTTYPE_PROC_TERMINATE:
			kevp->filter = EVFILT_PROCDESC;
			kevp->ident = sub.proc_terminate.fd;
			kevp->fflags = NOTE_EXIT;
			break;
		default:
			kevp->filter = UINT32_MAX;
			break;
		}
		if (arg) {
			/* Ignore flags. Simply use oneshot mode. */
			kevp->flags = EV_ADD | EV_ONESHOT;
		} else {
			/* Translate flags. */
			if ((sub.flags & CLOUDABI_SUBSCRIPTION_ADD) != 0)
				kevp->flags |= EV_ADD;
			if ((sub.flags & CLOUDABI_SUBSCRIPTION_CLEAR) != 0)
				kevp->flags |= EV_CLEAR;
			if ((sub.flags & CLOUDABI_SUBSCRIPTION_DELETE) != 0)
				kevp->flags |= EV_DELETE;
			if ((sub.flags & CLOUDABI_SUBSCRIPTION_DISABLE) != 0)
				kevp->flags |= EV_DISABLE;
			if ((sub.flags & CLOUDABI_SUBSCRIPTION_ENABLE) != 0)
				kevp->flags |= EV_ENABLE;
			if ((sub.flags & CLOUDABI_SUBSCRIPTION_ONESHOT) != 0)
				kevp->flags |= EV_ONESHOT;
		}
		++kevp;
	}
	return (0);
}

/* Converts NetBSD's struct kevent to CloudABI's event objects. */
static int
cloudabi64_kevent_put_events(void *arg, struct kevent *kevp,
    struct kevent *outp, size_t index, int count)
{
	cloudabi64_event_t ev;
	cloudabi64_event_t *out;
	int error;

	out = (cloudabi64_event_t *)outp + index;
	while (count-- > 0) {
		/* Convert fields that should always be present. */
		memset(&ev, '\0', sizeof(ev));
		ev.userdata = (uintptr_t)kevp->udata;
		switch (kevp->filter) {
		case EVFILT_TIMER:
			ev.type = CLOUDABI_EVENTTYPE_CLOCK;
			ev.clock.identifier = kevp->ident;
			break;
		case EVFILT_READ:
			ev.type = CLOUDABI_EVENTTYPE_FD_READ;
			ev.fd_readwrite.fd = kevp->ident;
			break;
		case EVFILT_WRITE:
			ev.type = CLOUDABI_EVENTTYPE_FD_WRITE;
			ev.fd_readwrite.fd = kevp->ident;
			break;
		case EVFILT_PROCDESC:
			ev.type = CLOUDABI_EVENTTYPE_PROC_TERMINATE;
			ev.proc_terminate.fd = kevp->ident;
			break;
		}

		if ((kevp->flags & EV_ERROR) == 0) {
			/* Success. */
			switch (kevp->filter) {
			case EVFILT_READ:
			case EVFILT_WRITE:
				ev.fd_readwrite.nbytes = kevp->data;
				if ((kevp->flags & EV_EOF) != 0) {
					ev.fd_readwrite.flags |=
					    CLOUDABI_EVENT_FD_READWRITE_HANGUP;
				}
				break;
			case EVFILT_PROCDESC:
				if (WIFSIGNALED(kevp->data)) {
					/* Process got signalled. */
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
			}
		} else {
			/* Error. */
			ev.error = cloudabi_convert_errno(kevp->data);
		}
		++kevp;

		error = copyout(&ev, out++, sizeof(ev));
		if (error != 0)
			return (error);
	}
	return (0);
}

int
cloudabi64_sys_poll(struct lwp *l, const struct cloudabi64_sys_poll_args *uap,
    register_t *retval)
{
	static struct kevent_ops copyops = {
		.keo_fetch_changes	= cloudabi64_kevent_fetch_changes,
		.keo_put_events		= cloudabi64_kevent_put_events,
		.keo_private		= (void *)1,
	};
	int error;

	/*
	 * Bandaid to support CloudABI futex constructs that are not
	 * implemented through NetBSD's kqueue().
	 */
	if (SCARG(uap, nevents) == 1) {
		cloudabi64_subscription_t sub;
		cloudabi64_event_t ev;

		error = copyin(SCARG(uap, in), &sub, sizeof(sub));
		if (error != 0)
			return (error);
		memset(&ev, '\0', sizeof(ev));
		ev.userdata = sub.userdata;
		ev.type = sub.type;
		if (sub.type == CLOUDABI_EVENTTYPE_CONDVAR) {
			/* Wait on a condition variable. */
			ev.condvar.condvar = sub.condvar.condvar;
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_condvar_wait(
			        l, (cloudabi_condvar_t *)sub.condvar.condvar,
			        sub.condvar.condvar_scope,
			        (cloudabi_lock_t *)sub.condvar.lock,
			        sub.condvar.lock_scope,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return (copyout(&ev, SCARG(uap, out), sizeof(ev)));
		} else if (sub.type == CLOUDABI_EVENTTYPE_LOCK_RDLOCK) {
			/* Acquire a read lock. */
			ev.lock.lock = sub.lock.lock;
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_rdlock(
			        l, (cloudabi_lock_t *)sub.lock.lock,
			        sub.lock.lock_scope,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return (copyout(&ev, SCARG(uap, out), sizeof(ev)));
		} else if (sub.type == CLOUDABI_EVENTTYPE_LOCK_WRLOCK) {
			/* Acquire a write lock. */
			ev.lock.lock = sub.lock.lock;
			ev.error = cloudabi_convert_errno(
			    cloudabi_futex_lock_wrlock(
			        l, (cloudabi_lock_t *)sub.lock.lock,
			        sub.lock.lock_scope,
			        CLOUDABI_CLOCK_MONOTONIC, UINT64_MAX, 0));
			retval[0] = 1;
			return (copyout(&ev, SCARG(uap, out), sizeof(ev)));
		}
	} else if (SCARG(uap, nevents) == 2) {
		cloudabi64_subscription_t sub[2];
		cloudabi64_event_t ev[2] = {};

		error = copyin(SCARG(uap, in), &sub, sizeof(sub));
		if (error != 0)
			return (error);
		ev[0].userdata = sub[0].userdata;
		ev[0].type = sub[0].type;
		ev[1].userdata = sub[1].userdata;
		ev[1].type = sub[1].type;
		if (sub[0].type == CLOUDABI_EVENTTYPE_CONDVAR &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK &&
		    sub[1].clock.flags == CLOUDABI_SUBSCRIPTION_CLOCK_ABSTIME) {
			/* Wait for a condition variable with timeout. */
			ev[0].condvar.condvar = sub[0].condvar.condvar;
			ev[1].clock.identifier = sub[1].clock.identifier;
			error = cloudabi_futex_condvar_wait(
			    l, (cloudabi_condvar_t *)sub[0].condvar.condvar,
			    sub[0].condvar.condvar_scope,
			    (cloudabi_lock_t *)sub[0].condvar.lock,
			    sub[0].condvar.lock_scope, sub[1].clock.clock_id,
			    sub[1].clock.timeout, sub[1].clock.precision);
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
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_LOCK_RDLOCK &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK &&
		    sub[1].clock.flags == CLOUDABI_SUBSCRIPTION_CLOCK_ABSTIME) {
			/* Acquire a read lock with a timeout. */
			ev[0].lock.lock = sub[0].lock.lock;
			ev[1].clock.identifier = sub[1].clock.identifier;
			error = cloudabi_futex_lock_rdlock(
			    l, (cloudabi_lock_t *)sub[0].lock.lock,
			    sub[0].lock.lock_scope, sub[1].clock.clock_id,
			    sub[1].clock.timeout, sub[1].clock.precision);
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
		} else if (sub[0].type == CLOUDABI_EVENTTYPE_LOCK_WRLOCK &&
		    sub[1].type == CLOUDABI_EVENTTYPE_CLOCK &&
		    sub[1].clock.flags == CLOUDABI_SUBSCRIPTION_CLOCK_ABSTIME) {
			/* Acquire a write lock with a timeout. */
			ev[0].lock.lock = sub[0].lock.lock;
			ev[1].clock.identifier = sub[1].clock.identifier;
			error = cloudabi_futex_lock_wrlock(
			    l, (cloudabi_lock_t *)sub[0].lock.lock,
			    sub[0].lock.lock_scope, sub[1].clock.clock_id,
			    sub[1].clock.timeout, sub[1].clock.precision);
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

	/* Anonymous poll call. */
	return (kevent1_anonymous(retval,
	    (const struct kevent *)SCARG(uap, in),
	    (struct kevent *)SCARG(uap, out),
	    SCARG(uap, nevents), &copyops));
}

int
cloudabi64_sys_poll_fd(struct lwp *l,
    const struct cloudabi64_sys_poll_fd_args *uap, register_t *retval)
{
	static struct kevent_ops copyops = {
		.keo_fetch_changes	= cloudabi64_kevent_fetch_changes,
		.keo_put_events		= cloudabi64_kevent_put_events,
	};
	cloudabi64_subscription_t subtimo;
	struct timespec timeout;
	int error;

	if (SCARG(uap, timeout) != NULL) {
		/* Poll with a timeout. */
		error = copyin(SCARG(uap, timeout), &subtimo, sizeof(subtimo));
		if (error != 0)
			return (error);
		if (subtimo.type != CLOUDABI_EVENTTYPE_CLOCK ||
		    subtimo.clock.flags != 0)
			return (EINVAL);
		timeout.tv_sec = subtimo.clock.timeout / 1000000000;
		timeout.tv_nsec = subtimo.clock.timeout % 1000000000;
		return (kevent1(retval, SCARG(uap, fd),
		    (const struct kevent *)SCARG(uap, in),
		    SCARG(uap, nin), (struct kevent *)SCARG(uap, out),
		    SCARG(uap, nout), &timeout, &copyops));
	} else {
		/* Poll without a timeout. */
		return (kevent1(retval, SCARG(uap, fd),
		    (const struct kevent *)SCARG(uap, in),
		    SCARG(uap, nin), (struct kevent *)SCARG(uap, out),
		    SCARG(uap, nout), NULL, &copyops));
	}
}
