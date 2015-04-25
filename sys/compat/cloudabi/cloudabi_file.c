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

	/* TODO(ed): Limit lookup to local directory. */
	NDINIT(&nd, CREATE, LOCKPARENT | CREATEDIR, pb);
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
	vattr.va_mode = 0777 & ~l->l_proc->p_cwdi->cwdi_cmask;
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

	return (ENOSYS);
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
	struct vattr vattr;
	char *path;
	int error;
	struct pathbuf *linkpb;
	struct nameidata nd;

	if (SCARG(uap, path2len) >= MAXPATHLEN)
		return (ENAMETOOLONG);

	/* Copy in pathnames. */
	path = PNBUF_GET();
	error = copyin(SCARG(uap, path2), path, SCARG(uap, path2len));
	if (error != 0)
		goto out1;
	path[SCARG(uap, path2len)] = '\0';
	error = pathbuf_copyin_length(SCARG(uap, path1), SCARG(uap, path1len),
	    &linkpb);
	if (error != 0)
		goto out1;

	/* TODO(ed): Limit lookup to local directory. */
	NDINIT(&nd, CREATE, LOCKPARENT, linkpb);
	error = cloudabi_namei(l, SCARG(uap, fd), &nd);
	if (error != 0)
		goto out2;
	if (nd.ni_vp) {
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == nd.ni_vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(nd.ni_vp);
		error = EEXIST;
		goto out2;
	}
	vattr_null(&vattr);
	vattr.va_type = VLNK;
	vattr.va_mode = 0777 & ~l->l_proc->p_cwdi->cwdi_cmask;
	error = VOP_SYMLINK(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr, path);
	if (error == 0)
		vrele(nd.ni_vp);
	vput(nd.ni_dvp);
out2:
	pathbuf_destroy(linkpb);
out1:
	PNBUF_PUT(path);
	return (error);
}

int
cloudabi_sys_file_unlink(struct lwp *l,
    const struct cloudabi_sys_file_unlink_args *uap, register_t *retval)
{

	return (ENOSYS);
}
