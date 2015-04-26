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

/* Converts a CloudABI clock ID to a NetBSD clock ID. */
static int
convert_clockid(cloudabi_clockid_t in, clockid_t *out)
{
	switch (in) {
	case CLOUDABI_CLOCK_MONOTONIC:
		*out = CLOCK_MONOTONIC;
		return 0;
	case CLOUDABI_CLOCK_REALTIME:
		*out = CLOCK_REALTIME;
		return 0;
	default:
		return EINVAL;
	}
}

#define NSEC_PER_SEC 1000000000

/* Converts a struct timespec to a CloudABI timestamp. */
static int
convert_timespec_to_timestamp(const struct timespec *in,
    cloudabi_timestamp_t *out)
{
	cloudabi_timestamp_t s, ns;

	/* Timestamps from before the Epoch cannot be expressed. */
	if (in->tv_sec < 0)
		return (EOVERFLOW);

	s = in->tv_sec;
	ns = in->tv_nsec;
	if (s > UINT64_MAX / NSEC_PER_SEC || (s == UINT64_MAX / NSEC_PER_SEC &&
	    ns > UINT64_MAX % NSEC_PER_SEC)) {
		/* Addition of seconds would cause an overflow. */
		return (EOVERFLOW);
	}

	*out = s * NSEC_PER_SEC + ns;
	return (0);
}

int
cloudabi_sys_clock_res_get(struct lwp *l,
    const struct cloudabi_sys_clock_res_get_args *uap, register_t *retval)
{
	struct timespec ts;
	cloudabi_timestamp_t cts;
	int error;
	clockid_t clockid;

	error = convert_clockid(SCARG(uap, clock_id), &clockid);
	if (error != 0)
		return error;

	error = clock_getres1(clockid, &ts);
	if (error != 0)
		return error;

	error = convert_timespec_to_timestamp(&ts, &cts);
	if (error != 0)
		return error;
	retval[0] = cts;
	return (0);
}

int
cloudabi_sys_clock_time_get(struct lwp *l,
    const struct cloudabi_sys_clock_time_get_args *uap, register_t *retval)
{
	struct timespec ts;
	cloudabi_timestamp_t cts;
	int error;
	clockid_t clockid;

	error = convert_clockid(SCARG(uap, clock_id), &clockid);
	if (error != 0)
		return (error);

	error = clock_gettime1(clockid, &ts);
	if (error != 0)
		return (error);

	error = convert_timespec_to_timestamp(&ts, &cts);
	if (error != 0)
		return error;
	retval[0] = cts;
	return (0);
}
