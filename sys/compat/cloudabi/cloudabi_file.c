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

#ifdef _KERNEL_OPT
#include "opt_fileassoc.h"
#include "veriexec.h"
#endif

#include <sys/param.h>
#include <sys/file.h>
#ifdef FILEASSOC
#include <sys/fileassoc.h>
#endif
#include <sys/filedesc.h>
#include <sys/namei.h>
#include <sys/syscallargs.h>
#if NVERIEXEC > 0
#include <sys/verified_exec.h>
#endif
#include <sys/vnode.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>
#include <compat/cloudabi/cloudabi_util.h>

#define CLOUDABI_MODE(l)	(0777 & ~(l)->l_proc->p_cwdi->cwdi_cmask)
/* TODO(ed): Limit lookup to local directory. */
#define	CLOUDABI_NDINIT(ndp, op, flags, pathbuf) \
	NDINIT(ndp, op, (flags) | SANDBOXINDIR, pathbuf)

static int
cloudabi_namei(struct lwp *l, int fdat, struct nameidata *ndp)
{
	file_t *dfp;
	int error;

	error = fd_getvnode(fdat, &dfp);
	if (error == 0) {
		NDAT(ndp, dfp->f_vnode);
		error = namei(ndp);
		fd_putfile(fdat);
	}
	return (error);
}

int
cloudabi_sys_file_advise(struct lwp *l,
    const struct cloudabi_sys_file_advise_args *uap, register_t *retval)
{
	int advice;

	switch (SCARG(uap, advice)) {
	case CLOUDABI_ADVICE_DONTNEED:
		advice = POSIX_FADV_DONTNEED;
		break;
	case CLOUDABI_ADVICE_NOREUSE:
		advice = POSIX_FADV_NOREUSE;
		break;
	case CLOUDABI_ADVICE_NORMAL:
		advice = POSIX_FADV_NORMAL;
		break;
	case CLOUDABI_ADVICE_RANDOM:
		advice = POSIX_FADV_RANDOM;
		break;
	case CLOUDABI_ADVICE_SEQUENTIAL:
		advice = POSIX_FADV_SEQUENTIAL;
		break;
	case CLOUDABI_ADVICE_WILLNEED:
		advice = POSIX_FADV_WILLNEED;
		break;
	default:
		return (EINVAL);
	}

	return (do_posix_fadvise(SCARG(uap, fd), SCARG(uap, offset),
	    SCARG(uap, len), advice));
}

int
cloudabi_sys_file_allocate(struct lwp *l,
     const struct cloudabi_sys_file_allocate_args *uap, register_t *retval)
{
	struct sys_posix_fallocate_args sys_posix_fallocate_args;

	SCARG(&sys_posix_fallocate_args, fd) = SCARG(uap, fd);
	SCARG(&sys_posix_fallocate_args, pos) = SCARG(uap, offset);
	SCARG(&sys_posix_fallocate_args, len) = SCARG(uap, len);
	sys_posix_fallocate(l, &sys_posix_fallocate_args, retval);
	return (retval[0]);
}

int
cloudabi_sys_file_create(struct lwp *l,
    const struct cloudabi_sys_file_create_args *uap, register_t *retval)
{
	struct nameidata nd;
	struct vattr vattr;
	struct pathbuf *pb;
	struct vnode *vp;
	enum vtype type;
	int error;

	switch (SCARG(uap, type)) {
	case CLOUDABI_FILETYPE_DIRECTORY:
		type = VDIR;
		break;
	case CLOUDABI_FILETYPE_FIFO:
		type = VFIFO;
		break;
	default:
		return (EINVAL);
	}

	error = pathbuf_copyin_length(SCARG(uap, path), SCARG(uap, pathlen),
	    &pb);
	if (error != 0)
		return (error);

	CLOUDABI_NDINIT(&nd, CREATE,
	    LOCKPARENT | (type == VDIR ? CREATEDIR : 0), pb);
	error = cloudabi_namei(l, SCARG(uap, fd), &nd);
	if (error != 0) {
		pathbuf_destroy(pb);
		return (error);
	}
	vp = nd.ni_vp;
	if (vp != NULL) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		pathbuf_destroy(pb);
		return (EEXIST);
	}
	vattr_null(&vattr);
	vattr.va_type = type;
	vattr.va_mode = CLOUDABI_MODE(l);
	if (type == VDIR)
		error = VOP_MKDIR(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
	else
		error = VOP_MKNOD(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
	if (error == 0)
		vrele(nd.ni_vp);
	vput(nd.ni_dvp);
	pathbuf_destroy(pb);
	return (error);
}

int
cloudabi_sys_file_link(struct lwp *l,
    const struct cloudabi_sys_file_link_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_open(struct lwp *l,
    const struct cloudabi_sys_file_open_args *uap, register_t *retval)
{
	cloudabi_fdstat_t fds;
	struct nameidata nd;
	file_t *dfp, *fp;
	struct pathbuf *pb;
	struct proc *p = l->l_proc;
	int error, fd, fflags;

	/* Copy in initial file descriptor properties. */
	error = copyin(SCARG(uap, fds), &fds, sizeof(fds));
	if (error != 0)
		return (error);

	/* Translate flags. */
	fflags = O_NOCTTY;
#define	COPY_FLAG(flag) do {						\
	if (SCARG(uap, oflags) & CLOUDABI_O_##flag)			\
		fflags |= O_##flag;					\
} while (0)
	COPY_FLAG(CREAT);
	COPY_FLAG(DIRECTORY);
	COPY_FLAG(EXCL);
	COPY_FLAG(TRUNC);
#undef COPY_FLAG
#define	COPY_FLAG(flag) do {						\
	if (fds.fs_flags & CLOUDABI_FDFLAG_##flag)			\
		fflags |= O_##flag;					\
} while (0)
	COPY_FLAG(APPEND);
	COPY_FLAG(DSYNC);
	COPY_FLAG(NONBLOCK);
	COPY_FLAG(RSYNC);
	COPY_FLAG(SYNC);
#undef COPY_FLAG
	if ((SCARG(uap, fd) & CLOUDABI_LOOKUP_SYMLINK_FOLLOW) == 0)
		fflags |= O_NOFOLLOW;

	/* Roughly convert rights to open() access mode. */
	if ((fds.fs_rights_base &
	    (CLOUDABI_RIGHT_FD_READ | CLOUDABI_RIGHT_FILE_READDIR)) != 0 &&
	    (fds.fs_rights_base & CLOUDABI_RIGHT_FD_WRITE) != 0)
		fflags |= FREAD | FWRITE;
	else if ((fds.fs_rights_base &
	    (CLOUDABI_RIGHT_FD_READ | CLOUDABI_RIGHT_FILE_READDIR)) != 0)
		fflags |= FREAD;
	else if ((fds.fs_rights_base & CLOUDABI_RIGHT_FD_WRITE) != 0)
		fflags |= FWRITE;
	else if ((fds.fs_rights_base &
	    (CLOUDABI_RIGHT_PROC_EXEC | CLOUDABI_RIGHT_FILE_OPEN)) != 0)
		fflags |= FREAD;
	else
		return (EINVAL);

	/* Copy in the pathname. */
	error = pathbuf_copyin_length(SCARG(uap, path), SCARG(uap, pathlen),
	    &pb);
	if (error != 0)
		return (error);

	/* Obtain the directory from where to do the lookup. */
	error = fd_getvnode(SCARG(uap, fd), &dfp);
	if (error != 0) {
		if (error == EINVAL)
			error = ENOTDIR;
		goto out1;
	}

	/* Allocate a new file descriptor. */
	error = fd_allocfile(&fp, &fd);
	if (error != 0)
		goto out2;

	/* Attempt to open the file. */
	CLOUDABI_NDINIT(&nd, LOOKUP, FOLLOW, pb);
	NDAT(&nd, dfp->f_vnode);
	error = vn_open(&nd, fflags, CLOUDABI_MODE(l));
	if (error != 0) {
		fd_abort(p, fp, fd);
		goto out2;
	}

	/* Initialize the new file descriptor. */
	fp->f_flag = fflags & FMASK;
	fp->f_type = DTYPE_VNODE;
	fp->f_ops = &vnops;
	fp->f_vnode = nd.ni_vp;

	VOP_UNLOCK(nd.ni_vp);
	retval[0] = fd;
	fd_affix(p, fp, fd);
out2:
	fd_putfile(SCARG(uap, fd));
out1:
	pathbuf_destroy(pb);
	return (error);
}

int
cloudabi_sys_file_readdir(struct lwp *l,
    const struct cloudabi_sys_file_readdir_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_readlink(struct lwp *l,
    const struct cloudabi_sys_file_readlink_args *uap, register_t *retval)
{
	struct iovec iov;
	struct nameidata nd;
	struct uio uio;
	struct vnode *vp;
	struct pathbuf *pb;
	int error;

	/* Copy in pathname. */
	error = pathbuf_copyin_length(SCARG(uap, path), SCARG(uap, pathlen),
	    &pb);
	if (error)
		return (error);

	/* Look up symbolic link. */
	CLOUDABI_NDINIT(&nd, LOOKUP, NOFOLLOW | LOCKLEAF, pb);
	error = cloudabi_namei(l, SCARG(uap, fd), &nd);
	if (error != 0) {
		pathbuf_destroy(pb);
		return (error);
	}
	vp = nd.ni_vp;
	pathbuf_destroy(pb);

	/* Validate file type. */
	if (vp->v_type != VLNK) {
		error = EINVAL;
		goto out;
	}

	/* Respect filesystem permissions if mount option "symperm" is set. */
	if ((vp->v_mount->mnt_flag & MNT_SYMPERM) != 0) {
		error = VOP_ACCESS(vp, VREAD, l->l_cred);
		if (error != 0)
			goto out;
	}

	/* Read symbolic link contents. */
	iov.iov_base = SCARG(uap, buf);
	iov.iov_len = SCARG(uap, bufsize);
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_rw = UIO_READ;
	KASSERT(l == curlwp);
	uio.uio_vmspace = l->l_proc->p_vmspace;
	uio.uio_resid = SCARG(uap, bufsize);
	error = VOP_READLINK(vp, &uio, l->l_cred);
	retval[0] = SCARG(uap, bufsize) - uio.uio_resid;
out:
	vput(vp);
	return (error);
}

int
cloudabi_sys_file_rename(struct lwp *l,
    const struct cloudabi_sys_file_rename_args *uap, register_t *retval)
{

	return (ENOSYS);
}

#define NSEC_PER_SEC 1000000000

/* Converts a struct timespec to a timestamp in nanoseconds since the Epoch. */
static cloudabi_timestamp_t
convert_timestamp(const struct timespec *ts)
{
	cloudabi_timestamp_t s, ns;

	/* Timestamps from before the Epoch cannot be expressed. */
	if (ts->tv_sec < 0)
		return (0);

	s = ts->tv_sec;
	ns = ts->tv_nsec;
	if (s > UINT64_MAX / NSEC_PER_SEC || (s == UINT64_MAX / NSEC_PER_SEC &&
	    ns > UINT64_MAX % NSEC_PER_SEC)) {
		/* Addition of seconds would cause an overflow. */
		ns = UINT64_MAX;
	} else {
		ns += s * NSEC_PER_SEC;
	}
	return (ns);
}

/* Converts a NetBSD stat structure to a CloudABI stat structure. */
static void
convert_stat(struct file *fp, const struct stat *sb, cloudabi_filestat_t *csb)
{
	cloudabi_filestat_t res = {
		.st_dev		= sb->st_dev,
		.st_ino		= sb->st_ino,
		.st_nlink	= sb->st_nlink,
		.st_size	= sb->st_size,
		.st_atim	= convert_timestamp(&sb->st_atim),
		.st_mtim	= convert_timestamp(&sb->st_mtim),
		.st_ctim	= convert_timestamp(&sb->st_ctim),
		.st_filetype	= cloudabi_convert_filetype(fp, sb->st_mode),
	};

	*csb = res;
}

int
cloudabi_sys_file_stat_fget(struct lwp *l,
    const struct cloudabi_sys_file_stat_fget_args *uap, register_t *retval)
{
	struct stat sb;
	cloudabi_filestat_t csb;
	struct file *fp;
	int error;

	fp = fd_getfile(SCARG(uap, fd));
	if (fp == NULL)
		return (EBADF);

	error = fp->f_ops->fo_stat(fp, &sb);
	if (error != 0) {
		fd_putfile(SCARG(uap, fd));
		return (error);
	}

	/* Convert results and return them. */
	convert_stat(fp, &sb, &csb);
	fd_putfile(SCARG(uap, fd));
	return (copyout(&csb, SCARG(uap, buf), sizeof(csb)));
}

int
cloudabi_sys_file_stat_fput(struct lwp *l,
    const struct cloudabi_sys_file_stat_fput_args *uap, register_t *retval)
{
	cloudabi_filestat_t fs;
	int error;

	error = copyin(SCARG(uap, buf), &fs, sizeof(fs));
	if (error != 0)
		return (error);

	if ((SCARG(uap, flags) & CLOUDABI_FILESTAT_SIZE) != 0) {
		struct sys_ftruncate_args sys_ftruncate_args;

		if ((SCARG(uap, flags) & ~CLOUDABI_FILESTAT_SIZE) != 0)
			return (EINVAL);

		SCARG(&sys_ftruncate_args, fd) = SCARG(uap, fd);
		SCARG(&sys_ftruncate_args, length) = fs.st_size;
		return (sys_ftruncate(l, &sys_ftruncate_args, retval));
	} else if ((SCARG(uap, flags) & (CLOUDABI_FILESTAT_ATIM |
	    CLOUDABI_FILESTAT_ATIM_NOW | CLOUDABI_FILESTAT_MTIM |
	    CLOUDABI_FILESTAT_MTIM_NOW)) != 0) {
		/* TODO(ed): Implement. */
		return (ENOSYS);
	}
	return (EINVAL);
}

int
cloudabi_sys_file_stat_get(struct lwp *l,
    const struct cloudabi_sys_file_stat_get_args *uap, register_t *retval)
{
	struct nameidata nd;
	struct stat sb;
	cloudabi_filestat_t csb;
	struct pathbuf *pb;
	int error;

	error = pathbuf_copyin_length(SCARG(uap, path), SCARG(uap, pathlen),
	    &pb);
	if (error != 0)
		return (error);

	CLOUDABI_NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, pb);
	error = cloudabi_namei(l, SCARG(uap, fd), &nd);
	pathbuf_destroy(pb);
	if (error != 0)
		return (error);

	error = vn_stat(nd.ni_vp, &sb);
	vput(nd.ni_vp);
	if (error != 0)
		return (error);

	convert_stat(NULL, &sb, &csb);
	return (copyout(&csb, SCARG(uap, buf), sizeof(csb)));
}

int
cloudabi_sys_file_stat_put(struct lwp *l,
    const struct cloudabi_sys_file_stat_put_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_symlink(struct lwp *l,
    const struct cloudabi_sys_file_symlink_args *uap, register_t *retval)
{
	struct nameidata nd;
	struct vattr vattr;
	struct pathbuf *linkpb;
	char *path;
	int error;

	if (SCARG(uap, path1len) >= MAXPATHLEN)
		return (ENAMETOOLONG);

	/* Copy in pathnames. */
	error = pathbuf_copyin_length(SCARG(uap, path2), SCARG(uap, path2len),
	    &linkpb);
	if (error != 0)
		return (error);
	path = PNBUF_GET();
	error = copyin(SCARG(uap, path1), path, SCARG(uap, path1len));
	if (error != 0)
		goto out;
	if (memchr(path, '\0', SCARG(uap, path1len)) != NULL) {
		error = EINVAL;
		goto out;
	}
	path[SCARG(uap, path1len)] = '\0';

	CLOUDABI_NDINIT(&nd, CREATE, LOCKPARENT, linkpb);
	error = cloudabi_namei(l, SCARG(uap, fd), &nd);
	if (error != 0)
		goto out;
	if (nd.ni_vp) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		error = EEXIST;
		goto out;
	}
	vattr_null(&vattr);
	vattr.va_type = VLNK;
	vattr.va_mode = CLOUDABI_MODE(l);
	error = VOP_SYMLINK(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr, path);
	if (error == 0)
		vrele(nd.ni_vp);
	vput(nd.ni_dvp);
out:
	PNBUF_PUT(path);
	pathbuf_destroy(linkpb);
	return (error);
}

int
cloudabi_sys_file_unlink(struct lwp *l,
    const struct cloudabi_sys_file_unlink_args *uap, register_t *retval)
{
	struct nameidata nd;
	struct pathbuf *pb;
	struct vnode *vp;
	const char *pathstring;
	int error;

	error = pathbuf_copyin_length(SCARG(uap, path), SCARG(uap, pathlen),
	    &pb);
	if (error != 0)
		return (error);
	pathstring = pathbuf_stringcopy_get(pb);
	if (pathstring == NULL) {
		pathbuf_destroy(pb);
		return (ENOMEM);
	}

	CLOUDABI_NDINIT(&nd, DELETE, LOCKPARENT | LOCKLEAF, pb);
	error = cloudabi_namei(l, SCARG(uap, fd), &nd);
	if (error != 0)
		goto out;
	vp = nd.ni_vp;

	/* The root of a mounted filesystem cannot be deleted. */
	if ((vp->v_vflag & VV_ROOT) != 0 ||
	    (vp->v_type == VDIR && vp->v_mountedhere != NULL)) {
		error = EBUSY;
		goto abort;
	}
	/* No rmdir "." please. */
	if (nd.ni_dvp == vp) {
		error = EINVAL;
		goto abort;
	}

	/* AT_REMOVEDIR is required to remove a directory. */
	if (vp->v_type == VDIR) {
		if ((SCARG(uap, flag) & CLOUDABI_UNLINK_REMOVEDIR) == 0) {
			error = EPERM;
			goto abort;
		} else {
			error = VOP_RMDIR(nd.ni_dvp, nd.ni_vp, &nd.ni_cnd);
			goto out;
		}
	}

	/* Starting here we only deal with non directories. */
	if ((SCARG(uap, flag) & CLOUDABI_UNLINK_REMOVEDIR) != 0) {
		error = ENOTDIR;
		goto abort;
	}

#if NVERIEXEC > 0
	/* Handle remove requests for veriexec entries. */
	error = veriexec_removechk(curlwp, nd.ni_vp, pathstring);
	if (error != 0)
		goto abort;
#endif
#ifdef FILEASSOC
	fileassoc_file_delete(vp);
#endif
	error = VOP_REMOVE(nd.ni_dvp, nd.ni_vp, &nd.ni_cnd);
	goto out;

abort:
	VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
	if (nd.ni_dvp == vp)
		vrele(nd.ni_dvp);
	else
		vput(nd.ni_dvp);
	vput(vp);

out:
	pathbuf_stringcopy_put(pb, pathstring);
	pathbuf_destroy(pb);
	return (error);
}
