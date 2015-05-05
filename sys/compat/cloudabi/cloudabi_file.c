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
/*-
 * Copyright (c) 2008, 2009 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran.
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
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)vfs_syscalls.c	8.42 (Berkeley) 7/31/95
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#ifdef _KERNEL_OPT
#include "opt_fileassoc.h"
#include "veriexec.h"
#endif

#include <sys/param.h>
#include <sys/dirent.h>
#include <sys/file.h>
#ifdef FILEASSOC
#include <sys/fileassoc.h>
#endif
#include <sys/filedesc.h>
#include <sys/malloc.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/syscallargs.h>
#if NVERIEXEC > 0
#include <sys/verified_exec.h>
#endif
#include <sys/vnode.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>
#include <compat/cloudabi/cloudabi_util.h>

/* Performs a namei lookup with a base directory as a file descriptor. */
int
cloudabi_namei(struct lwp *l, cloudabi_fd_t fd, struct nameidata *ndp)
{
	file_t *dfp;
	int error;

	error = fd_getvnode(fd, &dfp);
	if (error == 0) {
		NDAT(ndp, dfp->f_vnode);
		error = namei(ndp);
		fd_putfile(fd);
	}
	return (error);
}

/* Returns the vnode corresponding with a base directory and pathname. */
int
cloudabi_namei_simple(struct lwp *l, cloudabi_lookup_t fd, const char *path,
    size_t pathlen, unsigned int flags, struct vnode **vp)
{
	struct nameidata nd;
	struct pathbuf *pb;
	int error;

	error = pathbuf_copyin_length(path, pathlen, &pb);
	if (error != 0)
		return (error);
	CLOUDABI_NDINIT(&nd, LOOKUP,
	    ((fd & CLOUDABI_LOOKUP_SYMLINK_FOLLOW) != 0 ?  FOLLOW : NOFOLLOW) |
	    flags, pb);
	error = cloudabi_namei(l, fd, &nd);
	pathbuf_destroy(pb);
	*vp = nd.ni_vp;
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
	struct nameidata nd;
	struct pathbuf *pb;
	struct vnode *vp;
	int error;

	/* Look up source path. */
	error = cloudabi_namei_simple(l, SCARG(uap, fd1), SCARG(uap, path1),
	    SCARG(uap, path1len), 0, &vp);
	if (error != 0)
		return (error);

	/* Look up destination path. */
	error = pathbuf_copyin_length(SCARG(uap, path2), SCARG(uap, path2len),
	    &pb);
	if (error != 0)
		goto out1;
	CLOUDABI_NDINIT(&nd, CREATE, LOCKPARENT, pb);
	error = cloudabi_namei(l, SCARG(uap, fd2), &nd);
	if (error != 0)
		goto out2;

	if (nd.ni_vp != NULL) {
		/* Target file already exists. */
		error = EEXIST;
	} else if (vp->v_type == VDIR) {
		/* Source file is a directory. */
		error = EPERM;
	} else if (nd.ni_dvp->v_mount != vp->v_mount) {
		/* Hardlink would cross mountpoints. */
		error = EXDEV;
	}

	if (error == 0) {
		/* Create hardlink. */
		error = VOP_LINK(nd.ni_dvp, vp, &nd.ni_cnd);
	} else {
		/* Abort. */
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		if (nd.ni_vp != NULL)
			vrele(nd.ni_vp);
	}
out2:
	pathbuf_destroy(pb);
out1:
	vrele(vp);
	return (error);
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

/* Performs an uiomove(), discarding excessive data. */
static int
safe_uiomove(void *buf, size_t howmuch, struct uio *uiop)
{

	if (howmuch > uiop->uio_resid)
		howmuch = uiop->uio_resid;
	return (uiomove(buf, howmuch, uiop));
}

/* Converts the file type from a directory entry. */
static cloudabi_filetype_t
convert_type(uint8_t type)
{

	switch (type) {
	case DT_BLK:
		return (CLOUDABI_FILETYPE_BLOCK_DEVICE);
	case DT_CHR:
		return (CLOUDABI_FILETYPE_CHARACTER_DEVICE);
	case DT_DIR:
		return (CLOUDABI_FILETYPE_DIRECTORY);
	case DT_FIFO:
		return (CLOUDABI_FILETYPE_FIFO);
	case DT_LNK:
		return (CLOUDABI_FILETYPE_SYMBOLIC_LINK);
	case DT_REG:
		return (CLOUDABI_FILETYPE_REGULAR_FILE);
	case DT_SOCK: {
		/* The exact type cannot be derived. */
		return (CLOUDABI_FILETYPE_SOCKET_STREAM);
	}
	default:
		return (CLOUDABI_FILETYPE_UNKNOWN);
	}
}

int
cloudabi_sys_file_readdir(struct lwp *l,
    const struct cloudabi_sys_file_readdir_args *uap, register_t *retval)
{
	struct iovec iov = {
		.iov_base = (void *)SCARG(uap, buf),
		.iov_len = SCARG(uap, nbyte)
	};
	struct uio uio = {
		.uio_iov = &iov,
		.uio_iovcnt = 1,
		.uio_resid = iov.iov_len,
		.uio_rw = UIO_READ,
		.uio_vmspace = l->l_proc->p_vmspace
	};
	file_t *fp;
	struct vnode *vp;
	void *readbuf;
	cloudabi_dircookie_t offset;
	int error;

	error = fd_getvnode(SCARG(uap, fd), &fp);
	if (error != 0)
		return (error == EINVAL ? ENOTDIR : error);

	if ((fp->f_flag & FREAD) == 0) {
		fd_putfile(SCARG(uap, fd));
		return (EBADF);
	}

	vp = fp->f_vnode;
	if (vp->v_type != VDIR) {
		fd_putfile(SCARG(uap, fd));
		return (ENOTDIR);
	}

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);

	/*
	 * TODO(ed): Allocate something smaller than MAXBSIZE in case we
	 * only need to return a small amount of data.
	 */
	readbuf = malloc(MAXBSIZE, M_TEMP, M_WAITOK);
	offset = SCARG(uap, cookie);
	while (uio.uio_resid > 0) {
		struct iovec readiov = {
			.iov_base = readbuf,
			.iov_len = MAXBSIZE
		};
		struct uio readuio = {
			.uio_iov = &readiov,
			.uio_iovcnt = 1,
			.uio_rw = UIO_READ,
			.uio_resid = MAXBSIZE,
			.uio_offset = offset
		};
		off_t *cookies = NULL, *cookie;
		int eof, ncookies = 0;

		/* Read new directory entries. */
		UIO_SETUP_SYSSPACE(&readuio);
		error = VOP_READDIR(vp, &readuio, fp->f_cred, &eof,
		    &cookies, &ncookies);
		if (error != 0)
			goto done;

		/* Convert entries to CloudABI's format. */
		/* TODO(ed): Add support for filesystems without cookies. */
		ssize_t readbuflen = MAXBSIZE - readuio.uio_resid;
		struct dirent *bde = readbuf;
		cookie = cookies;
		while (readbuflen >= offsetof(struct dirent, d_name) &&
		    uio.uio_resid > 0 && ncookies > 0) {
			/* Ensure that the returned offset always increases. */
			if (readbuflen >= bde->d_reclen && bde->d_fileno != 0 &&
			    *cookie > offset) {
				cloudabi_dirent_t cde = {
					.d_next = *cookie,
					.d_ino = bde->d_fileno,
					.d_namlen = bde->d_namlen,
					.d_type = convert_type(bde->d_type),
				};

				error = safe_uiomove(&cde, sizeof(cde), &uio);
				if (error != 0) {
					free(cookies, M_TEMP);
					goto done;
				}
				error = safe_uiomove(bde->d_name, bde->d_namlen,
				    &uio);
				if (error != 0) {
					free(cookies, M_TEMP);
					goto done;
				}
			}

			if (offset < *cookie)
				offset = *cookie;
			++cookie;
			--ncookies;
			readbuflen -= bde->d_reclen;
			bde = (struct dirent *)((char *)bde + bde->d_reclen);
		}
		free(cookies, M_TEMP);

		if (eof)
			break;
	}

done:
	VOP_UNLOCK(vp);
	fd_putfile(SCARG(uap, fd));
	free(readbuf, M_TEMP);
	retval[0] = SCARG(uap, nbyte) - uio.uio_resid;
	return (error);
}

int
cloudabi_sys_file_readlink(struct lwp *l,
    const struct cloudabi_sys_file_readlink_args *uap, register_t *retval)
{
	struct iovec iov;
	struct uio uio;
	struct vnode *vp;
	int error;

	/* Look up pathname. */
	error = cloudabi_namei_simple(l, SCARG(uap, fd), SCARG(uap, path),
	    SCARG(uap, pathlen), LOCKLEAF, &vp);
	if (error != 0)
		return (error);

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
	struct pathbuf *fpb, *tpb;
	struct nameidata fnd, tnd;
	struct vnode *fdvp, *fvp;
	struct vnode *tdvp, *tvp;
	struct mount *mp, *tmp;
	int error;

	error = pathbuf_copyin_length(SCARG(uap, old), SCARG(uap, oldlen),
	    &fpb);
	if (error)
		goto out0;
	KASSERT(fpb != NULL);

	error = pathbuf_copyin_length(SCARG(uap, new), SCARG(uap, newlen),
	    &tpb);
	if (error)
		goto out1;
	KASSERT(tpb != NULL);

	/*
	 * Lookup from.
	 *
	 * XXX LOCKPARENT is wrong because we don't actually want it
	 * locked yet, but (a) namei is insane, and (b) VOP_RENAME is
	 * insane, so for the time being we need to leave it like this.
	 */
	CLOUDABI_NDINIT(&fnd, DELETE, LOCKPARENT | INRENAME, fpb);
	error = cloudabi_namei(l, SCARG(uap, oldfd), &fnd);
	if (error != 0)
		goto out2;

	/*
	 * Pull out the important results of the lookup, fdvp and fvp.
	 * Of course, fvp is bogus because we're about to unlock fdvp.
	 */
	fdvp = fnd.ni_dvp;
	fvp = fnd.ni_vp;
	KASSERT(fdvp != NULL);
	KASSERT(fvp != NULL);
	KASSERT((fdvp == fvp) || (VOP_ISLOCKED(fdvp) == LK_EXCLUSIVE));

	/*
	 * Make sure neither fdvp nor fvp is locked.
	 */
	if (fdvp != fvp)
		VOP_UNLOCK(fdvp);
	/* XXX KASSERT(VOP_ISLOCKED(fdvp) != LK_EXCLUSIVE); */
	/* XXX KASSERT(VOP_ISLOCKED(fvp) != LK_EXCLUSIVE); */

	/*
	 * Reject renaming `.' and `..'.  Can't do this until after
	 * namei because we need namei's parsing to find the final
	 * component name.  (namei should just leave us with the final
	 * component name and not look it up itself, but anyway...)
	 *
	 * This was here before because we used to relookup from
	 * instead of to and relookup requires the caller to check
	 * this, but now file systems may depend on this check, so we
	 * must retain it until the file systems are all rototilled.
	 */
	if (((fnd.ni_cnd.cn_namelen == 1) &&
		(fnd.ni_cnd.cn_nameptr[0] == '.')) ||
	    ((fnd.ni_cnd.cn_namelen == 2) &&
		(fnd.ni_cnd.cn_nameptr[0] == '.') &&
		(fnd.ni_cnd.cn_nameptr[1] == '.'))) {
		error = EINVAL;	/* XXX EISDIR?  */
		goto abort0;
	}

	/*
	 * Lookup to.
	 *
	 * XXX LOCKPARENT is wrong, but...insanity, &c.  Also, using
	 * fvp here to decide whether to add CREATEDIR is a load of
	 * bollocks because fvp might be the wrong node by now, since
	 * fdvp is unlocked.
	 *
	 * XXX Why not pass CREATEDIR always?
	 */
	CLOUDABI_NDINIT(&tnd, RENAME, LOCKPARENT | NOCACHE | INRENAME |
	    ((fvp->v_type == VDIR)? CREATEDIR : 0), tpb);
	error = cloudabi_namei(l, SCARG(uap, newfd), &tnd);
	if (error != 0)
		goto abort0;

	/*
	 * Pull out the important results of the lookup, tdvp and tvp.
	 * Of course, tvp is bogus because we're about to unlock tdvp.
	 */
	tdvp = tnd.ni_dvp;
	tvp = tnd.ni_vp;
	KASSERT(tdvp != NULL);
	KASSERT((tdvp == tvp) || (VOP_ISLOCKED(tdvp) == LK_EXCLUSIVE));

	/*
	 * Make sure neither tdvp nor tvp is locked.
	 */
	if (tdvp != tvp)
		VOP_UNLOCK(tdvp);
	/* XXX KASSERT(VOP_ISLOCKED(tdvp) != LK_EXCLUSIVE); */
	/* XXX KASSERT((tvp == NULL) || (VOP_ISLOCKED(tvp) != LK_EXCLUSIVE)); */

	/*
	 * Reject renaming onto `.' or `..'.  relookup is unhappy with
	 * these, which is why we must do this here.  Once upon a time
	 * we relooked up from instead of to, and consequently didn't
	 * need this check, but now that we relookup to instead of
	 * from, we need this; and we shall need it forever forward
	 * until the VOP_RENAME protocol changes, because file systems
	 * will no doubt begin to depend on this check.
	 */
	if ((tnd.ni_cnd.cn_namelen == 1) && (tnd.ni_cnd.cn_nameptr[0] == '.')) {
		error = EISDIR;
		goto abort1;
	}
	if ((tnd.ni_cnd.cn_namelen == 2) &&
	    (tnd.ni_cnd.cn_nameptr[0] == '.') &&
	    (tnd.ni_cnd.cn_nameptr[1] == '.')) {
		error = EINVAL;
		goto abort1;
	}

	/*
	 * Get the mount point.  If the file system has been unmounted,
	 * which it may be because we're not holding any vnode locks,
	 * then v_mount will be NULL.  We're not really supposed to
	 * read v_mount without holding the vnode lock, but since we
	 * have fdvp referenced, if fdvp->v_mount changes then at worst
	 * it will be set to NULL, not changed to another mount point.
	 * And, of course, since it is up to the file system to
	 * determine the real lock order, we can't lock both fdvp and
	 * tdvp at the same time.
	 */
	mp = fdvp->v_mount;
	if (mp == NULL) {
		error = ENOENT;
		goto abort1;
	}

	/*
	 * Make sure the mount points match.  Again, although we don't
	 * hold any vnode locks, the v_mount fields may change -- but
	 * at worst they will change to NULL, so this will never become
	 * a cross-device rename, because we hold vnode references.
	 *
	 * XXX Because nothing is locked and the compiler may reorder
	 * things here, unmounting the file system at an inopportune
	 * moment may cause rename to fail with ENXDEV when it really
	 * should fail with ENOENT.
	 */
	tmp = tdvp->v_mount;
	if (tmp == NULL) {
		error = ENOENT;
		goto abort1;
	}

	if (mp != tmp) {
		error = EXDEV;
		goto abort1;
	}

	/*
	 * Take the vfs rename lock to avoid cross-directory screw cases.
	 * Nothing is locked currently, so taking this lock is safe.
	 */
	error = VFS_RENAMELOCK_ENTER(mp);
	if (error)
		goto abort1;

	/*
	 * Now fdvp, fvp, tdvp, and (if nonnull) tvp are referenced,
	 * and nothing is locked except for the vfs rename lock.
	 *
	 * The next step is a little rain dance to conform to the
	 * insane lock protocol, even though it does nothing to ward
	 * off race conditions.
	 *
	 * We need tdvp and tvp to be locked.  However, because we have
	 * unlocked tdvp in order to hold no locks while we take the
	 * vfs rename lock, tvp may be wrong here, and we can't safely
	 * lock it even if the sensible file systems will just unlock
	 * it straight away.  Consequently, we must lock tdvp and then
	 * relookup tvp to get it locked.
	 *
	 * Finally, because the VOP_RENAME protocol is brain-damaged
	 * and various file systems insanely depend on the semantics of
	 * this brain damage, the lookup of to must be the last lookup
	 * before VOP_RENAME.
	 */
	vn_lock(tdvp, LK_EXCLUSIVE | LK_RETRY);
	error = relookup(tdvp, &tnd.ni_vp, &tnd.ni_cnd, 0);
	if (error)
		goto abort2;

	/*
	 * Drop the old tvp and pick up the new one -- which might be
	 * the same, but that doesn't matter to us.  After this, tdvp
	 * and tvp should both be locked.
	 */
	if (tvp != NULL)
		vrele(tvp);
	tvp = tnd.ni_vp;
	KASSERT(VOP_ISLOCKED(tdvp) == LK_EXCLUSIVE);
	KASSERT((tvp == NULL) || (VOP_ISLOCKED(tvp) == LK_EXCLUSIVE));

	/*
	 * The old do_sys_rename had various consistency checks here
	 * involving fvp and tvp.  fvp is bogus already here, and tvp
	 * will become bogus soon in any sensible file system, so the
	 * only purpose in putting these checks here is to give lip
	 * service to these screw cases and to acknowledge that they
	 * exist, not actually to handle them, but here you go
	 * anyway...
	 */

	/*
	 * Acknowledge that directories and non-directories aren't
	 * suposed to mix.
	 */
	if (tvp != NULL) {
		if ((fvp->v_type == VDIR) && (tvp->v_type != VDIR)) {
			error = ENOTDIR;
			goto abort3;
		} else if ((fvp->v_type != VDIR) && (tvp->v_type == VDIR)) {
			error = EISDIR;
			goto abort3;
		}
	}

	/*
	 * Acknowledge some random screw case, among the dozens that
	 * might arise.
	 */
	if (fvp == tdvp) {
		error = EINVAL;
		goto abort3;
	}

	/*
	 * Acknowledge that POSIX has a wacky screw case.
	 *
	 * XXX Eventually the retain flag needs to be passed on to
	 * VOP_RENAME.
	 */
	if (fvp == tvp) {
		error = 0;
		goto abort3;
	}

	/*
	 * Make sure veriexec can screw us up.  (But a race can screw
	 * up veriexec, of course -- remember, fvp and (soon) tvp are
	 * bogus.)
	 */
#if NVERIEXEC > 0
	{
		char *f1, *f2;
		size_t f1_len;
		size_t f2_len;

		f1_len = fnd.ni_cnd.cn_namelen + 1;
		f1 = kmem_alloc(f1_len, KM_SLEEP);
		strlcpy(f1, fnd.ni_cnd.cn_nameptr, f1_len);

		f2_len = tnd.ni_cnd.cn_namelen + 1;
		f2 = kmem_alloc(f2_len, KM_SLEEP);
		strlcpy(f2, tnd.ni_cnd.cn_nameptr, f2_len);

		error = veriexec_renamechk(curlwp, fvp, f1, tvp, f2);

		kmem_free(f1, f1_len);
		kmem_free(f2, f2_len);

		if (error)
			goto abort3;
	}
#endif /* NVERIEXEC > 0 */

	/*
	 * All ready.  Incant the rename vop.
	 */
	/* XXX KASSERT(VOP_ISLOCKED(fdvp) != LK_EXCLUSIVE); */
	/* XXX KASSERT(VOP_ISLOCKED(fvp) != LK_EXCLUSIVE); */
	KASSERT(VOP_ISLOCKED(tdvp) == LK_EXCLUSIVE);
	KASSERT((tvp == NULL) || (VOP_ISLOCKED(tvp) == LK_EXCLUSIVE));
	error = VOP_RENAME(fdvp, fvp, &fnd.ni_cnd, tdvp, tvp, &tnd.ni_cnd);

	/*
	 * VOP_RENAME releases fdvp, fvp, tdvp, and tvp, and unlocks
	 * tdvp and tvp.  But we can't assert any of that.
	 */
	/* XXX KASSERT(VOP_ISLOCKED(fdvp) != LK_EXCLUSIVE); */
	/* XXX KASSERT(VOP_ISLOCKED(fvp) != LK_EXCLUSIVE); */
	/* XXX KASSERT(VOP_ISLOCKED(tdvp) != LK_EXCLUSIVE); */
	/* XXX KASSERT((tvp == NULL) || (VOP_ISLOCKED(tvp) != LK_EXCLUSIVE)); */

	/*
	 * So all we have left to do is to drop the rename lock and
	 * destroy the pathbufs.
	 */
	VFS_RENAMELOCK_EXIT(mp);
	goto out2;

abort3:	if ((tvp != NULL) && (tvp != tdvp))
		VOP_UNLOCK(tvp);
abort2:	VOP_UNLOCK(tdvp);
	VFS_RENAMELOCK_EXIT(mp);
abort1:	VOP_ABORTOP(tdvp, &tnd.ni_cnd);
	vrele(tdvp);
	if (tvp != NULL)
		vrele(tvp);
abort0:	VOP_ABORTOP(fdvp, &fnd.ni_cnd);
	vrele(fdvp);
	vrele(fvp);
out2:	pathbuf_destroy(tpb);
out1:	pathbuf_destroy(fpb);
out0:	return error;
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
	};

	if (S_ISBLK(sb->st_mode))
		res.st_filetype = CLOUDABI_FILETYPE_BLOCK_DEVICE;
	else if (S_ISCHR(sb->st_mode))
		res.st_filetype = CLOUDABI_FILETYPE_CHARACTER_DEVICE;
	else if (S_ISDIR(sb->st_mode))
		res.st_filetype = CLOUDABI_FILETYPE_DIRECTORY;
	else if (S_ISFIFO(sb->st_mode))
		res.st_filetype = CLOUDABI_FILETYPE_FIFO;
	else if (S_ISREG(sb->st_mode))
		res.st_filetype = CLOUDABI_FILETYPE_REGULAR_FILE;
	else if (S_ISSOCK(sb->st_mode)) {
		/* Inaccurate, but the best that we can do. */
		res.st_filetype = CLOUDABI_FILETYPE_SOCKET_STREAM;
	} else if (S_ISLNK(sb->st_mode))
		res.st_filetype = CLOUDABI_FILETYPE_SYMBOLIC_LINK;
	else
		res.st_filetype = CLOUDABI_FILETYPE_UNKNOWN;
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

static void
convert_utimens_arguments(const cloudabi_filestat_t *fs,
    cloudabi_fsflags_t flags, struct timespec *ts)
{

	if ((flags & CLOUDABI_FILESTAT_ATIM_NOW) != 0) {
		ts[0].tv_nsec = UTIME_NOW;
	} else if ((flags & CLOUDABI_FILESTAT_ATIM) != 0) {
		ts[0].tv_sec = fs->st_atim / NSEC_PER_SEC;
		ts[0].tv_nsec = fs->st_atim % NSEC_PER_SEC;
	} else {
		ts[0].tv_nsec = UTIME_OMIT;
	}

	if ((flags & CLOUDABI_FILESTAT_MTIM_NOW) != 0) {
		ts[1].tv_nsec = UTIME_NOW;
	} else if ((flags & CLOUDABI_FILESTAT_MTIM) != 0) {
		ts[1].tv_sec = fs->st_mtim / NSEC_PER_SEC;
		ts[1].tv_nsec = fs->st_mtim % NSEC_PER_SEC;
	} else {
		ts[1].tv_nsec = UTIME_OMIT;
	}
}

static int
do_stat_put(struct lwp *l, struct vnode *vp, const cloudabi_filestat_t *fsp,
    cloudabi_fsflags_t flags)
{
	cloudabi_filestat_t fs;
	struct vattr vattr;
	struct timespec ts[2];
	int error;
	bool vanull, setbirthtime;

	/* Only support timestamp modification for now. */
	if ((flags & ~(CLOUDABI_FILESTAT_ATIM | CLOUDABI_FILESTAT_ATIM_NOW |
	    CLOUDABI_FILESTAT_MTIM | CLOUDABI_FILESTAT_MTIM_NOW)) != 0 ||
	    flags == 0)
		return (EINVAL);

	/* Copy in timestamps and convert them to struct timespecs. */
	error = copyin(fsp, &fs, sizeof(fs));
	if (error != 0)
		return (error);
	convert_utimens_arguments(&fs, flags, ts);

	/* Process UTIME_NOW. */
	if (ts[0].tv_nsec == UTIME_NOW) {
		nanotime(&ts[0]);
		if (ts[1].tv_nsec == UTIME_NOW) {
			vanull = true;
			ts[1] = ts[0];
		}
	} else if (ts[1].tv_nsec == UTIME_NOW)
		nanotime(&ts[1]);

	/* Modify vnode attributes. */
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	setbirthtime = (VOP_GETATTR(vp, &vattr, l->l_cred) == 0 &&
	    timespeccmp(&ts[1], &vattr.va_birthtime, <));
	vattr_null(&vattr);
	if (ts[0].tv_nsec != UTIME_OMIT)
		vattr.va_atime = ts[0];
	if (ts[1].tv_nsec != UTIME_OMIT) {
		vattr.va_mtime = ts[1];
		if (setbirthtime)
			vattr.va_birthtime = ts[1];
	}
	if (vanull)
		vattr.va_vaflags |= VA_UTIMES_NULL;
	error = VOP_SETATTR(vp, &vattr, l->l_cred);
	VOP_UNLOCK(vp);
	return (error);
}

int
cloudabi_sys_file_stat_fput(struct lwp *l,
    const struct cloudabi_sys_file_stat_fput_args *uap, register_t *retval)
{
	file_t *fp;
	int error;

	if ((SCARG(uap, flags) & CLOUDABI_FILESTAT_SIZE) != 0) {
		cloudabi_filestat_t fs;
		struct sys_ftruncate_args sys_ftruncate_args;

		/* Treat file truncation separately for now. */
		if ((SCARG(uap, flags) & ~CLOUDABI_FILESTAT_SIZE) != 0)
			return (EINVAL);
		error = copyin(SCARG(uap, buf), &fs, sizeof(fs));
		if (error != 0)
			return (error);

		SCARG(&sys_ftruncate_args, fd) = SCARG(uap, fd);
		SCARG(&sys_ftruncate_args, length) = fs.st_size;
		return (sys_ftruncate(l, &sys_ftruncate_args, retval));
	}

	error = fd_getvnode(SCARG(uap, fd), &fp);
	if (error != 0)
		return (error);
	error = do_stat_put(l, fp->f_vnode, SCARG(uap, buf), SCARG(uap, flags));
	fd_putfile(SCARG(uap, fd));
	return (error);
}

int
cloudabi_sys_file_stat_get(struct lwp *l,
    const struct cloudabi_sys_file_stat_get_args *uap, register_t *retval)
{
	struct stat sb;
	cloudabi_filestat_t csb;
	struct vnode *vp;
	int error;

	/* Look up path. */
	error = cloudabi_namei_simple(l, SCARG(uap, fd), SCARG(uap, path),
	    SCARG(uap, pathlen), LOCKLEAF, &vp);
	if (error != 0)
		return (error);

	/* Obtain stat structure. */
	error = vn_stat(vp, &sb);
	vput(vp);
	if (error != 0)
		return (error);

	/* Convert to CloudABI's format. */
	convert_stat(NULL, &sb, &csb);
	return (copyout(&csb, SCARG(uap, buf), sizeof(csb)));
}

int
cloudabi_sys_file_stat_put(struct lwp *l,
    const struct cloudabi_sys_file_stat_put_args *uap, register_t *retval)
{
	struct vnode *vp;
	int error;

	/* Look up path. */
	error = cloudabi_namei_simple(l, SCARG(uap, fd), SCARG(uap, path),
	    SCARG(uap, pathlen), 0, &vp);
	if (error != 0)
		return (error);

	/* Change attributes. */
	error = do_stat_put(l, vp, SCARG(uap, buf), SCARG(uap, flags));
	vrele(vp);
	return (error);
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
