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
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/syscallargs.h>
#include <sys/vnode.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>
#include <compat/cloudabi/cloudabi_util.h>

#define RIGHT_MAPPINGS \
	MAPPING(CLOUDABI_RIGHT_FD_DATASYNC, CAP_FDATASYNC)		\
	MAPPING(CLOUDABI_RIGHT_FD_READ, CAP_READ)			\
	MAPPING(CLOUDABI_RIGHT_FD_SEEK, CAP_JUST_SEEK)			\
	MAPPING(CLOUDABI_RIGHT_FD_STAT_PUT_FLAGS, CAP_FCNTL_SETFL)	\
	MAPPING(CLOUDABI_RIGHT_FD_SYNC, CAP_FSYNC)			\
	MAPPING(CLOUDABI_RIGHT_FD_TELL, CAP_SEEK_TELL)			\
	MAPPING(CLOUDABI_RIGHT_FD_WRITE, CAP_WRITE)			\
	MAPPING(CLOUDABI_RIGHT_FILE_ADVISE, CAP_POSIX_FADVISE)		\
	MAPPING(CLOUDABI_RIGHT_FILE_ALLOCATE, CAP_POSIX_FALLOCATE)	\
	MAPPING(CLOUDABI_RIGHT_FILE_CREATE_DIRECTORY, CAP_MKDIRAT)	\
	MAPPING(CLOUDABI_RIGHT_FILE_CREATE_FILE, CAP_CREATE)		\
	MAPPING(CLOUDABI_RIGHT_FILE_CREATE_FIFO, CAP_MKFIFOAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_LINK_SOURCE, CAP_LINKAT_SOURCE)	\
	MAPPING(CLOUDABI_RIGHT_FILE_LINK_TARGET, CAP_LINKAT_TARGET)	\
	MAPPING(CLOUDABI_RIGHT_FILE_OPEN, CAP_LOOKUP)			\
	MAPPING(CLOUDABI_RIGHT_FILE_READDIR, CAP_GETDENTS)		\
	MAPPING(CLOUDABI_RIGHT_FILE_READLINK, CAP_READLINKAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_RENAME_SOURCE, CAP_RENAMEAT_SOURCE)	\
	MAPPING(CLOUDABI_RIGHT_FILE_RENAME_TARGET, CAP_RENAMEAT_TARGET)	\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_FGET, CAP_FSTAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_FPUT_SIZE, CAP_FTRUNCATE)	\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_FPUT_TIMES, CAP_FUTIMES)	\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_GET, CAP_FSTATAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_STAT_PUT_TIMES, CAP_FUTIMESAT)	\
	MAPPING(CLOUDABI_RIGHT_FILE_SYMLINK, CAP_SYMLINKAT)		\
	MAPPING(CLOUDABI_RIGHT_FILE_UNLINK, CAP_UNLINKAT)		\
	MAPPING(CLOUDABI_RIGHT_MEM_MAP, CAP_MMAP)			\
	MAPPING(CLOUDABI_RIGHT_MEM_MAP_EXEC, CAP_JUST_MMAP_X)		\
	MAPPING(CLOUDABI_RIGHT_POLL_FD_READWRITE, CAP_EVENT)		\
	MAPPING(CLOUDABI_RIGHT_POLL_MODIFY, CAP_KQUEUE_CHANGE)		\
	MAPPING(CLOUDABI_RIGHT_POLL_PROC_TERMINATE, CAP_PDWAIT)		\
	MAPPING(CLOUDABI_RIGHT_POLL_WAIT, CAP_KQUEUE_EVENT)		\
	MAPPING(CLOUDABI_RIGHT_PROC_EXEC, CAP_FEXECVE)			\
	MAPPING(CLOUDABI_RIGHT_SOCK_ACCEPT, CAP_ACCEPT)			\
	MAPPING(CLOUDABI_RIGHT_SOCK_BIND_DIRECTORY, CAP_BINDAT)		\
	MAPPING(CLOUDABI_RIGHT_SOCK_BIND_SOCKET, CAP_BIND)		\
	MAPPING(CLOUDABI_RIGHT_SOCK_CONNECT_DIRECTORY, CAP_CONNECTAT)	\
	MAPPING(CLOUDABI_RIGHT_SOCK_CONNECT_SOCKET, CAP_CONNECT)	\
	MAPPING(CLOUDABI_RIGHT_SOCK_LISTEN, CAP_LISTEN)			\
	MAPPING(CLOUDABI_RIGHT_SOCK_SHUTDOWN, CAP_SHUTDOWN)		\
	MAPPING(CLOUDABI_RIGHT_SOCK_STAT_GET,				\
	    CAP_GETPEERNAME | CAP_GETSOCKNAME | CAP_GETSOCKOPT)

extern const struct fileops socketops;

int
cloudabi_sys_fd_close(struct lwp *l,
    const struct cloudabi_sys_fd_close_args *uap, register_t *retval)
{
	struct sys_close_args sys_close_args;

	SCARG(&sys_close_args, fd) = SCARG(uap, fd);
	return (sys_close(l, &sys_close_args, retval));
}

static int
create_socket(struct lwp *l, int type, register_t *retval)
{
	struct compat_30_sys_socket_args compat_30_sys_socket_args;

	SCARG(&compat_30_sys_socket_args, domain) = AF_UNIX;
	SCARG(&compat_30_sys_socket_args, type) = type;
	SCARG(&compat_30_sys_socket_args, protocol) = 0;
	return (compat_30_sys_socket(l, &compat_30_sys_socket_args, retval));
}

int
cloudabi_sys_fd_create1(struct lwp *l,
    const struct cloudabi_sys_fd_create1_args *uap, register_t *retval)
{

	/* TODO(ed): Add support for shared memory. */
	switch (SCARG(uap, type)) {
	case CLOUDABI_FILETYPE_POLL:
		return (kqueue1(l, retval, 0, CAP_FSTAT | CAP_KQUEUE));
	case CLOUDABI_FILETYPE_SOCKET_DGRAM:
		return (create_socket(l, SOCK_DGRAM, retval));
	case CLOUDABI_FILETYPE_SOCKET_SEQPACKET:
		return (create_socket(l, SOCK_SEQPACKET, retval));
	case CLOUDABI_FILETYPE_SOCKET_STREAM:
		return (create_socket(l, SOCK_STREAM, retval));
	default:
		return (EINVAL);
	}
}

static int
makesocket(struct lwp *l, file_t **fp, int *fd, int domain, struct socket *soo)
{
	struct socket *so;
	int error;

	error = socreate(domain, &so, AF_UNIX, 0, l, soo);
	if (error != 0)
		return (error);
	error = fd_allocfile(fp, CAP_EVENT | CAP_FCNTL_SETFL | CAP_FSTAT |
	    CAP_SOCK_CLIENT | CAP_SOCK_SERVER, fd);
	if (error != 0) {
		soclose(so);
		return (error);
	}
	(*fp)->f_flag = FREAD | FWRITE | FNOSIGPIPE;
	(*fp)->f_type = DTYPE_SOCKET;
	(*fp)->f_ops = &socketops;
	(*fp)->f_socket = so;
	return (0);
}

static int
create_socketpair(struct lwp *l, int type, register_t *retval)
{
	file_t *fp1, *fp2;
	proc_t *p = l->l_proc;
	struct socket *so1, *so2;
	int fd, error;

	error = makesocket(l, &fp1, &fd, type, NULL);
	if (error)
		return (error);
	so1 = fp1->f_socket;
	retval[0] = fd;

	error = makesocket(l, &fp2, &fd, type, so1);
	if (error)
		goto out1;
	so2 = fp2->f_socket;
	retval[1] = fd;

	solock(so1);
	error = soconnect2(so1, so2);
	/* Datagram socket connection is asymmetric. */
	if (error == 0 && type == SOCK_DGRAM)
		error = soconnect2(so2, so1);
	sounlock(so1);
	if (error != 0)
		goto out2;

	fd_affix(p, fp1, retval[0]);
	fd_affix(p, fp2, retval[1]);
	return (0);
out2:
	fd_abort(p, fp2, retval[1]);
	soclose(so2);
out1:
	fd_abort(p, fp1, retval[0]);
	soclose(so1);
	return (error);
}

int
cloudabi_sys_fd_create2(struct lwp *l,
    const struct cloudabi_sys_fd_create2_args *uap, register_t *retval)
{

	switch (SCARG(uap, type)) {
	case CLOUDABI_FILETYPE_FIFO:
		return (pipe1(l, retval, 0,
		    CAP_EVENT | CAP_FCNTL_SETFL | CAP_FSTAT | CAP_READ,
		    CAP_EVENT | CAP_FCNTL_SETFL | CAP_FSTAT | CAP_WRITE));
	case CLOUDABI_FILETYPE_SOCKET_DGRAM:
		return (create_socketpair(l, SOCK_DGRAM, retval));
	case CLOUDABI_FILETYPE_SOCKET_SEQPACKET:
		return (create_socketpair(l, SOCK_SEQPACKET, retval));
	case CLOUDABI_FILETYPE_SOCKET_STREAM:
		return (create_socketpair(l, SOCK_STREAM, retval));
	default:
		return (EINVAL);
	}
}

int
cloudabi_sys_fd_datasync(struct lwp *l,
    const struct cloudabi_sys_fd_datasync_args *uap, register_t *retval)
{
	struct sys_fdatasync_args sys_fdatasync_args;
	int error;

	SCARG(&sys_fdatasync_args, fd) = SCARG(uap, fd);
	error = sys_fdatasync(l, &sys_fdatasync_args, retval);
	return (error == ENOTCAPABLE ? EBADF : error);
}

int
cloudabi_sys_fd_dup(struct lwp *l, const struct cloudabi_sys_fd_dup_args *uap,
    register_t *retval)
{
	struct sys_dup_args sys_dup_args;

	SCARG(&sys_dup_args, fd) = SCARG(uap, from);
	return (sys_dup(l, &sys_dup_args, retval));
}

int
cloudabi_sys_fd_replace(struct lwp *l,
    const struct cloudabi_sys_fd_replace_args *uap, register_t *retval)
{
	struct sys_dup2_args sys_dup2_args;
	register_t discard[2];

	/* This system call is supposed to return zero upon success. */
	/* TODO(ed): This should disallow dupping to unused descriptors. */
	SCARG(&sys_dup2_args, from) = SCARG(uap, from);
	SCARG(&sys_dup2_args, to) = SCARG(uap, to);
	return (sys_dup2(l, &sys_dup2_args, discard));
}

int
cloudabi_sys_fd_seek(struct lwp *l, const struct cloudabi_sys_fd_seek_args *uap,
    register_t *retval)
{
	struct sys_lseek_args sys_lseek_args;
	int error;

	SCARG(&sys_lseek_args, fd) = SCARG(uap, fd);
	SCARG(&sys_lseek_args, offset) = SCARG(uap, offset);

	switch (SCARG(uap, whence)) {
	case CLOUDABI_WHENCE_CUR:
		SCARG(&sys_lseek_args, whence) = SEEK_CUR;
		break;
	case CLOUDABI_WHENCE_END:
		SCARG(&sys_lseek_args, whence) = SEEK_END;
		break;
	case CLOUDABI_WHENCE_SET:
		SCARG(&sys_lseek_args, whence) = SEEK_SET;
		break;
	default:
		return (EINVAL);
	}

	error = sys_lseek(l, &sys_lseek_args, retval);
	return (error == ENOTCAPABLE ? ESPIPE : error);
}

/* Converts a file descriptor to a CloudABI file descriptor type. */
cloudabi_filetype_t
cloudabi_convert_filetype(const struct file *fp)
{

	switch (fp->f_type) {
	case DTYPE_KQUEUE:
		return (CLOUDABI_FILETYPE_POLL);
	case DTYPE_PIPE:
		return (CLOUDABI_FILETYPE_FIFO);
	case DTYPE_PROCDESC:
		return (CLOUDABI_FILETYPE_PROCESS);
	case DTYPE_SOCKET: {
		struct socket *so;

		so = fp->f_socket;
		switch (so->so_type) {
		case SOCK_DGRAM:
			return (CLOUDABI_FILETYPE_SOCKET_DGRAM);
		case SOCK_SEQPACKET:
			return (CLOUDABI_FILETYPE_SOCKET_SEQPACKET);
		default:
			return (CLOUDABI_FILETYPE_SOCKET_STREAM);
		}
	}
	case DTYPE_VNODE: {
		struct vnode *vp;

		vp = fp->f_vnode;
		switch (vp->v_type) {
		case VBLK:
			return (CLOUDABI_FILETYPE_BLOCK_DEVICE);
		case VCHR:
			return (CLOUDABI_FILETYPE_CHARACTER_DEVICE);
		case VDIR:
			return (CLOUDABI_FILETYPE_DIRECTORY);
		case VFIFO:
			return (CLOUDABI_FILETYPE_FIFO);
		case VLNK:
			return (CLOUDABI_FILETYPE_SYMBOLIC_LINK);
		case VREG:
			return (CLOUDABI_FILETYPE_REGULAR_FILE);
		case VSOCK:
			return (CLOUDABI_FILETYPE_SOCKET_STREAM);
		default:
			return (CLOUDABI_FILETYPE_UNKNOWN);
		}
	}
	default:
		return (CLOUDABI_FILETYPE_UNKNOWN);
	}

}

/*
 * Converts NetBSD's Capsicum rights to CloudABI's set of rights.
 */
static cloudabi_rights_t
convert_netbsd_rights(cap_rights_t rights)
{
	cloudabi_rights_t ret = 0;

#define MAPPING(cloudabi, netbsd) do {			\
	if ((rights & (netbsd)) == (netbsd))		\
		ret |= (cloudabi);			\
} while (0);
	RIGHT_MAPPINGS
#undef MAPPING
	return ret;
}

int
cloudabi_sys_fd_stat_get(struct lwp *l,
    const struct cloudabi_sys_fd_stat_get_args *uap, register_t *retval)
{
	cloudabi_fdstat_t fsb;
	file_t *fp;
	cap_rights_t base, inheriting;
	int error, oflags;

	memset(&fsb, '\0', sizeof(fsb));
	error = fd_getfile(SCARG(uap, fd), 0, &fp);
	if (error != 0)
		return (error);
	oflags = OFLAGS(fp->f_flag);
	fsb.fs_filetype = cloudabi_convert_filetype(fp);
	fd_getrights(SCARG(uap, fd), &base, &inheriting);
	fd_putfile(SCARG(uap, fd));

	/* Convert file descriptor flags. */
	if (oflags & O_APPEND)
		fsb.fs_flags |= CLOUDABI_FDFLAG_APPEND;
	if (oflags & O_DSYNC)
		fsb.fs_flags |= CLOUDABI_FDFLAG_DSYNC;
	if (oflags & O_NONBLOCK)
		fsb.fs_flags |= CLOUDABI_FDFLAG_NONBLOCK;
	if (oflags & O_RSYNC)
		fsb.fs_flags |= CLOUDABI_FDFLAG_RSYNC;
	if (oflags & O_SYNC)
		fsb.fs_flags |= CLOUDABI_FDFLAG_SYNC;

	fsb.fs_rights_base = convert_netbsd_rights(base);
	fsb.fs_rights_inheriting = convert_netbsd_rights(inheriting);
	return (copyout(&fsb, SCARG(uap, buf), sizeof(fsb)));
}

int
cloudabi_sys_fd_stat_put(struct lwp *l,
    const struct cloudabi_sys_fd_stat_put_args *uap, register_t *retval)
{
	cloudabi_fdstat_t fsb;
	int error;

	error = copyin(SCARG(uap, buf), &fsb, sizeof(fsb));
	if (error != 0)
		return (error);

	if (SCARG(uap, flags) == CLOUDABI_FDSTAT_FLAGS) {
		struct sys_fcntl_args sys_fcntl_args;
		intptr_t oflags;

		/* Convert flags. */
		SCARG(&sys_fcntl_args, fd) = SCARG(uap, fd);
		SCARG(&sys_fcntl_args, cmd) = F_SETFL;
		oflags = 0;
		if (fsb.fs_flags & CLOUDABI_FDFLAG_APPEND)
			oflags |= O_APPEND;
		if (fsb.fs_flags & CLOUDABI_FDFLAG_NONBLOCK)
			oflags |= O_NONBLOCK;
		if (fsb.fs_flags & (CLOUDABI_FDFLAG_SYNC |
		    CLOUDABI_FDFLAG_DSYNC | CLOUDABI_FDFLAG_RSYNC))
			oflags |= O_SYNC;
		SCARG(&sys_fcntl_args, arg) = (void *)oflags;;

		return (sys_fcntl(l, &sys_fcntl_args, retval));
	} else if (SCARG(uap, flags) == CLOUDABI_FDSTAT_RIGHTS) {
		/* TODO(ed): Implement. */
		return (ENOSYS);
	}
	return (EINVAL);
}

int
cloudabi_sys_fd_sync(struct lwp *l, const struct cloudabi_sys_fd_sync_args *uap,
    register_t *retval)
{
	struct sys_fsync_args sys_fsync_args;
	int error;

	SCARG(&sys_fsync_args, fd) = SCARG(uap, fd);
	error = sys_fsync(l, &sys_fsync_args, retval);
	return (error == ENOTCAPABLE ? EINVAL : error);
}
