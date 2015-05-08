/*	$NetBSD: filedesc.h,v 1.63 2012/02/11 23:16:18 martin Exp $	*/

/*-
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)filedesc.h	8.1 (Berkeley) 6/2/93
 */

#ifndef _SYS_FILEDESC_H_
#define	_SYS_FILEDESC_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/condvar.h>

#define	_CAP_BIT(n)		((uint64_t)1 << (n))
#define	CAP_ACCEPT		_CAP_BIT(0)
#define	CAP_BIND		_CAP_BIT(1)
#define	CAP_BINDAT		_CAP_BIT(2)
#define	CAP_CONNECT		_CAP_BIT(3)
#define	CAP_CONNECTAT		_CAP_BIT(4)
#define	CAP_EVENT		_CAP_BIT(5)
#define	CAP_FDATASYNC		_CAP_BIT(6)
#define	CAP_FSTAT		_CAP_BIT(7)
#define	CAP_FSTATAT		_CAP_BIT(8)
#define	CAP_FSYNC		_CAP_BIT(9)
#define	CAP_FTRUNCATE		_CAP_BIT(10)
#define	CAP_FUTIMES		_CAP_BIT(11)
#define	CAP_FUTIMESAT		_CAP_BIT(12)
#define	CAP_GETDENTS		_CAP_BIT(13)
#define	CAP_GETPEERNAME		_CAP_BIT(14)
#define	CAP_GETSOCKNAME		_CAP_BIT(15)
#define	CAP_GETSOCKOPT		_CAP_BIT(16)
#define	CAP_JUST_MMAP_X		_CAP_BIT(17)
#define	CAP_JUST_SEEK		_CAP_BIT(18)
#define	CAP_KQUEUE_CHANGE	_CAP_BIT(19)
#define	CAP_KQUEUE_EVENT	_CAP_BIT(20)
#define	CAP_LINKAT_DEST		_CAP_BIT(21)
#define	CAP_LINKAT_SRC		_CAP_BIT(22)
#define	CAP_LISTEN		_CAP_BIT(23)
#define	CAP_MKDIRAT		_CAP_BIT(24)
#define	CAP_MKFIFOAT		_CAP_BIT(25)
#define	CAP_MMAP		_CAP_BIT(26)
#define	CAP_POSIX_FADVISE	_CAP_BIT(27)
#define	CAP_POSIX_FALLOCATE	_CAP_BIT(28)
#define	CAP_READ		_CAP_BIT(29)
#define	CAP_READLINKAT		_CAP_BIT(30)
#define	CAP_RENAMEAT_DEST	_CAP_BIT(31)
#define	CAP_RENAMEAT_SRC	_CAP_BIT(32)
#define	CAP_SEEK_TELL		_CAP_BIT(33)
#define	CAP_SHUTDOWN		_CAP_BIT(34)
#define	CAP_SYMLINKAT		_CAP_BIT(35)
#define	CAP_UNLINKAT		_CAP_BIT(36)
#define	CAP_WRITE		_CAP_BIT(37)
#define	CAP_OTHER		_CAP_BIT(63)

#define	CAP_MMAP_R		(CAP_MMAP | CAP_JUST_SEEK | CAP_READ)
#define	CAP_MMAP_W		(CAP_MMAP | CAP_JUST_SEEK | CAP_WRITE)
#define	CAP_MMAP_X		(CAP_MMAP | CAP_JUST_SEEK | CAP_JUST_MMAP_X)
#define	CAP_PREAD		(CAP_READ | CAP_JUST_SEEK)
#define	CAP_PWRITE		(CAP_WRITE | CAP_JUST_SEEK)
#define	CAP_SEEK		(CAP_JUST_SEEK | CAP_SEEK_TELL)

typedef uint64_t cap_rights_t;

/*
 * This structure is used for the management of descriptors.  It may be
 * shared by multiple processes.
 *
 * A process is initially started out with NDFILE descriptors stored within
 * this structure, selected to be enough for typical applications based on
 * the historical limit of 20 open files (and the usage of descriptors by
 * shells).  If these descriptors are exhausted, a larger descriptor table
 * may be allocated, up to a process' resource limit; the internal arrays
 * are then unused.  The initial expansion is set to NDEXTENT; each time
 * it runs out, it is doubled until the resource limit is reached. NDEXTENT
 * should be selected to be the biggest multiple of OFILESIZE (see below)
 * that will fit in a power-of-two sized piece of memory.
 */
#define	NDFILE		20
#define	NDEXTENT	50		/* 250 bytes in 256-byte alloc */
#define	NDENTRIES	32		/* 32 fds per entry */
#define	NDENTRYMASK	(NDENTRIES - 1)
#define	NDENTRYSHIFT	5		/* bits per entry */
#define	NDLOSLOTS(x)	(((x) + NDENTRIES - 1) >> NDENTRYSHIFT)
#define	NDHISLOTS(x)	((NDLOSLOTS(x) + NDENTRIES - 1) >> NDENTRYSHIFT)
#define	NDFDFILE	6		/* first 6 descriptors are free */

/*
 * Process-private descriptor reference, one for each descriptor slot
 * in use.  Locks:
 *
 * :	unlocked
 * a	atomic operations + filedesc_t::fd_lock in some cases
 * d	filedesc_t::fd_lock
 *
 * Note that ff_exclose and ff_allocated are likely to be byte sized
 * (bool).  In general adjacent sub-word sized fields must be locked
 * the same way, but in this case it's ok: ff_exclose can only be
 * modified while the descriptor slot is live, and ff_allocated when
 * it's invalid.
 */
typedef struct fdfile {
	bool		ff_exclose;	/* :: close on exec flag */
	bool		ff_allocated;	/* d: descriptor slot is allocated */
	u_int		ff_refcnt;	/* a: reference count on structure */
	struct file	*ff_file;	/* d: pointer to file if open */
	SLIST_HEAD(,knote) ff_knlist;	/* d: knotes attached to this fd */
	kcondvar_t	ff_closing;	/* d: notifier for close */
} fdfile_t;

/* Reference count */
#define	FR_CLOSING	(0x80000000)	/* closing: must interlock */
#define	FR_MASK		(~FR_CLOSING)	/* reference count */

/*
 * Open file table, potentially many 'active' tables per filedesc_t
 * in a multi-threaded process, or with a shared filedesc_t (clone()).
 * nfiles is first to avoid pointer arithmetic.
 */
typedef struct fdtab {
	u_int		dt_nfiles;	/* number of open files allocated */
	struct fdtab	*dt_link;	/* for lists of dtab */
	fdfile_t	*dt_ff[NDFILE];	/* file structures for open fds */
} fdtab_t;

typedef struct filedesc {
	/*
	 * Built-in fdfile_t records first, since they have strict
	 * alignment requirements.
	 */
	uint8_t		fd_dfdfile[NDFDFILE][CACHE_LINE_SIZE];
	/*
	 * All of the remaining fields are locked by fd_lock.
	 */
	kmutex_t	fd_lock;	/* lock on structure */
	fdtab_t * volatile fd_dt;	/* active descriptor table */
	uint32_t	*fd_himap;	/* each bit points to 32 fds */
	uint32_t	*fd_lomap;	/* bitmap of free fds */
	struct klist	*fd_knhash;	/* hash of attached non-fd knotes */
	int		fd_lastkqfile;	/* max descriptor for kqueue */
	int		fd_lastfile;	/* high-water mark of fd_ofiles */
	int		fd_refcnt;	/* reference count */
	u_long		fd_knhashmask;	/* size of fd_knhash */
	int		fd_freefile;	/* approx. next free file */
	int		fd_unused;	/* unused */
	bool		fd_exclose;	/* non-zero if >0 fd with EXCLOSE */
	/*
	 * This structure is used when the number of open files is
	 * <= NDFILE, and are then pointed to by the pointers above.
	 */
	fdtab_t		fd_dtbuiltin;
	/*
	 * These arrays are used when the number of open files is
	 * <= 1024, and are then pointed to by the pointers above.
	 */
#define fd_startzero	fd_dhimap	/* area to zero on return to cache */
	uint32_t	fd_dhimap[NDENTRIES >> NDENTRYSHIFT];
	uint32_t	fd_dlomap[NDENTRIES];
} filedesc_t;

typedef struct cwdinfo {
	struct vnode	*cwdi_cdir;	/* current directory */
	struct vnode	*cwdi_rdir;	/* root directory */
	struct vnode	*cwdi_edir;	/* emulation root (if known) */
	krwlock_t	cwdi_lock;	/* lock on entire struct */
	u_short		cwdi_cmask;	/* mask for file creation */
	u_int		cwdi_refcnt;	/* reference count */
} cwdinfo_t;

#ifdef _KERNEL

struct fileops;
struct socket;
struct proc;

/*
 * Kernel global variables and routines.
 */
void	fd_sys_init(void);
int	fd_open(const char*, int, int, int*);
int	fd_dupopen(int, int *, int, int);
int	fd_alloc(struct proc *, int, int *);
void	fd_tryexpand(struct proc *);
int	fd_allocfile(file_t **, int *);
void	fd_affix(struct proc *, file_t *, unsigned);
void	fd_abort(struct proc *, file_t *, unsigned);
filedesc_t *fd_copy(void);
filedesc_t *fd_init(filedesc_t *);
void	fd_share(proc_t *);
void	fd_hold(lwp_t *);
void	fd_free(void);
void	fd_closeexec(void);
void	fd_ktrexecfd(void);
int	fd_checkstd(void);
int	fd_getfile(unsigned, cap_rights_t, file_t **);
file_t	*fd_getfile2(proc_t *, unsigned);
void	fd_putfile(unsigned);
int	fd_getvnode(unsigned, cap_rights_t, file_t **);
int	fd_getsock(unsigned, cap_rights_t, struct socket **);
int	fd_getsock1(unsigned, cap_rights_t, struct socket **, file_t **);
void	fd_putvnode(unsigned);
void	fd_putsock(unsigned);
int	fd_close(unsigned);
int	fd_dup(file_t *, int, int *, bool);
int	fd_dup2(file_t *, unsigned, int);
int	fd_clone(file_t *, unsigned, int, const struct fileops *, void *);
void	fd_set_exclose(struct lwp *, int, bool);
int	pipe1(struct lwp *, register_t *, int);
int	dodup(struct lwp *, int, int, int, register_t *);

void	cwd_sys_init(void);
struct cwdinfo *cwdinit(void);
void	cwdshare(proc_t *);
void	cwdunshare(proc_t *);
void	cwdfree(struct cwdinfo *);
void	cwdexec(struct proc *);

#define GETCWD_CHECK_ACCESS 0x0001
int	getcwd_common(struct vnode *, struct vnode *, char **, char *, int,
    int, struct lwp *);
int	vnode_to_path(char *, size_t, struct vnode *, struct lwp *,
    struct proc *);

int	closef(file_t *);
file_t *fgetdummy(void);
void	fputdummy(file_t *);

struct stat;
int	do_sys_fstat(int, struct stat *);
struct flock;
int	do_fcntl_lock(int, int, struct flock *);
int	do_posix_fadvise(int, off_t, off_t, int);

extern kmutex_t filelist_lock;
extern filedesc_t filedesc0;

#endif /* _KERNEL */

#endif /* !_SYS_FILEDESC_H_ */
