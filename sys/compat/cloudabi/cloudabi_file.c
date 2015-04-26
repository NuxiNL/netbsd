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
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/namei.h>
#include <sys/vnode.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>

#define CLOUDABI_MODE(l)	(0777 & ~(l)->l_proc->p_cwdi->cwdi_cmask)
/* TODO(ed): Limit lookup to local directory. */
#define	CLOUDABI_NDINIT(ndp, op, flags, pathbuf) \
	NDINIT(ndp, op, (flags) | 0, pathbuf)

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

	return (ENOSYS);
}

int
cloudabi_sys_file_allocate(struct lwp *l,
     const struct cloudabi_sys_file_allocate_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_create(struct lwp *l,
    const struct cloudabi_sys_file_create_args *uap, register_t *retval)
{
	struct nameidata nd;
	struct vattr vattr;
	struct pathbuf *pb;
	struct vnode *vp;
	int error;

	/* TODO(ed): Also support the creation of fifos. */
	if (SCARG(uap, type) != CLOUDABI_FILETYPE_DIRECTORY)
		return (EINVAL);

	error = pathbuf_copyin_length(SCARG(uap, path), SCARG(uap, pathlen),
	    &pb);
	if (error != 0)
		return (error);

	CLOUDABI_NDINIT(&nd, CREATE, LOCKPARENT | CREATEDIR, pb);
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
	vattr.va_type = VDIR;
	vattr.va_mode = CLOUDABI_MODE(l);
	error = VOP_MKDIR(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
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
	struct nameidata nd;
	file_t *dfp, *fp;
	struct pathbuf *pb;
	struct proc *p = l->l_proc;
	int error, fd;

	/* TODO(ed): Properly compute the access mode. */
	int flags = FREAD;

	/* Copy in the pathname. */
	error = pathbuf_copyin_length(SCARG(uap, path), SCARG(uap, pathlen),
	    &pb);
	if (error != 0)
		return (error);

	/* Obtain the directory from where to do the lookup. */
	error = fd_getvnode(SCARG(uap, fd), &dfp);
	if (error != 0)
		goto out1;

	/* Allocate a new file descriptor. */
	error = fd_allocfile(&fp, &fd);
	if (error != 0)
		goto out2;

	/* Attempt to open the file. */
	CLOUDABI_NDINIT(&nd, LOOKUP, FOLLOW, pb);
	NDAT(&nd, dfp->f_vnode);
	error = vn_open(&nd, flags, CLOUDABI_MODE(l));
	if (error != 0) {
		fd_abort(p, fp, fd);
		goto out2;
	}

	/* Initialize the new file descriptor. */
	fp->f_flag = flags & FMASK;
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

	return (ENOSYS);
}

int
cloudabi_sys_file_rename(struct lwp *l,
    const struct cloudabi_sys_file_rename_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_stat_fget(struct lwp *l,
    const struct cloudabi_sys_file_stat_fget_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_stat_fput(struct lwp *l,
    const struct cloudabi_sys_file_stat_fput_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_file_stat_get(struct lwp *l,
    const struct cloudabi_sys_file_stat_get_args *uap, register_t *retval)
{

	return (ENOSYS);
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

	return (ENOSYS);
}
