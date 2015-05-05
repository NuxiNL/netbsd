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
#include <sys/domain.h>
#include <sys/filedesc.h>
#include <sys/kauth.h>
#include <sys/namei.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syscallargs.h>
#include <sys/unpcb.h>
#include <sys/vnode.h>

#include <netinet/in.h>

#include <compat/cloudabi/cloudabi_syscallargs.h>
#include <compat/cloudabi/cloudabi_util.h>

/* Converts NetBSD's struct sockaddr to CloudABI's cloudabi_sockaddr_t. */
void
cloudabi_convert_sockaddr(const struct sockaddr *sa, socklen_t sal,
    cloudabi_sockaddr_t *rsa)
{

	/* Zero-sized socket address. */
	if (sal < offsetof(struct sockaddr, sa_family) + sizeof(sa->sa_family))
		return;

	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;

		rsa->sa_family = CLOUDABI_AF_INET;
		if (sal < sizeof(struct sockaddr_in))
			return;
		memcpy(&rsa->sa_inet.addr, &sin->sin_addr,
		    sizeof(rsa->sa_inet.addr));
		rsa->sa_inet.port = ntohs(sin->sin_port);
		return;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 =
		    (const struct sockaddr_in6 *)sa;

		rsa->sa_family = CLOUDABI_AF_INET6;
		if (sal < sizeof(struct sockaddr_in6))
			return;
		memcpy(&rsa->sa_inet6.addr, &sin6->sin6_addr,
		    sizeof(rsa->sa_inet6.addr));
		rsa->sa_inet6.port = ntohs(sin6->sin6_port);
		return;
	}
	case AF_UNIX:
		rsa->sa_family = CLOUDABI_AF_UNIX;
		return;
	}
}

int
cloudabi_sys_sock_accept(struct lwp *l,
    const struct cloudabi_sys_sock_accept_args *uap, register_t *retval)
{
	cloudabi_sockstat_t ss;
	struct mbuf *name;
	int error;

	error = do_sys_accept(l, SCARG(uap, s), &name, retval, NULL, 0, 0);
	if (error != 0)
		return (error);

	memset(&ss, '\0', sizeof(ss));
	if (name != NULL) {
		cloudabi_convert_sockaddr(mtod(name, void *), name->m_len,
		    &ss.ss_peername);
		m_free(name);
	}
	if (SCARG(uap, buf) != NULL)
		error = copyout(&ss, SCARG(uap, buf), sizeof(ss));
	return (error);
}

int
cloudabi_sys_sock_bind(struct lwp *l,
    const struct cloudabi_sys_sock_bind_args *uap, register_t *retval)
{
	struct nameidata nd;
	struct vattr vattr;
	struct pathbuf *pb;
	struct socket *so;
	struct unpcb *unp;
	struct vnode *vp;
	int error;

	error = fd_getsock(SCARG(uap, s), &so);
	if (error != 0)
		return (error);
	solock(so);
	if (so->so_proto->pr_domain->dom_family != AF_UNIX) {
		/* Not a UNIX socket. */
		error = EAFNOSUPPORT;
		goto out1;
	}
	unp = sotounpcb(so);
	if (unp->unp_vnode != NULL) {
		/* Socket already bound. */
		error = EINVAL;
		goto out1;
	}
	if ((unp->unp_flags & UNP_BUSY) != 0) {
		/* Bind or connect already in progress. */
		error = EALREADY;
		goto out1;
	}
	unp->unp_flags |= UNP_BUSY;
	sounlock(so);

	/* Look up the target path. */
	error = pathbuf_copyin_length(SCARG(uap, path), SCARG(uap, pathlen),
	    &pb);
	if (error != 0) {
		solock(so);
		goto out2;
	}
	CLOUDABI_NDINIT(&nd, CREATE, FOLLOW | LOCKPARENT, pb);
	error = cloudabi_namei(l, SCARG(uap, fd), &nd);
	if (error != 0) {
		solock(so);
		goto out3;
	}
	vp = nd.ni_vp;
	if (vp != NULL) {
		/* Target already exists. */
		VOP_ABORTOP(nd.ni_dvp, &nd.ni_cnd);
		if (nd.ni_dvp == vp)
			vrele(nd.ni_dvp);
		else
			vput(nd.ni_dvp);
		vrele(vp);
		error = EADDRINUSE;
		solock(so);
		goto out3;
	}

	/* Create new socket file. */
	vattr_null(&vattr);
	vattr.va_type = VSOCK;
	vattr.va_mode = CLOUDABI_MODE(l);
	error = VOP_CREATE(nd.ni_dvp, &nd.ni_vp, &nd.ni_cnd, &vattr);
	if (error != 0) {
		solock(so);
		goto out4;
	}

	/* Connect socket to vnode. */
	vp = nd.ni_vp;
	vn_lock(vp , LK_EXCLUSIVE | LK_RETRY);
	solock(so);
	vp->v_socket = unp->unp_socket;
	unp->unp_vnode = vp;
	unp->unp_addrlen = 0;
	unp->unp_addr = NULL;
	unp->unp_connid.unp_pid = l->l_proc->p_pid;
	unp->unp_connid.unp_euid = kauth_cred_geteuid(l->l_cred);
	unp->unp_connid.unp_egid = kauth_cred_getegid(l->l_cred);
	unp->unp_flags |= UNP_EIDSBIND;
	VOP_UNLOCK(vp);
out4:
	vput(nd.ni_dvp);
out3:
	pathbuf_destroy(pb);
out2:
	unp->unp_flags &= ~UNP_BUSY;
out1:
	sounlock(so);
	fd_putfile(SCARG(uap, s));
	return (error);
}

int
cloudabi_sys_sock_connect(struct lwp *l,
    const struct cloudabi_sys_sock_connect_args *uap, register_t *retval)
{
	struct socket *so, *so2, *so3;
	struct unpcb *unp, *unp2, *unp3;
	struct vnode *vp;
	int error;

	error = fd_getsock(SCARG(uap, s), &so);
	if (error != 0)
		return (error);
	solock(so);
	if (so->so_options & SO_ACCEPTCONN) {
		/* Socket is already accepting connections. */
		error = EOPNOTSUPP;
		goto out1;
	} else if (so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING) &&
	    ((so->so_proto->pr_flags & PR_CONNREQUIRED) ||
	    (error = sodisconnect(so)))) {
		/* Socket is already connected. */
		error = EISCONN;
		goto out1;
	} else if (so->so_proto->pr_domain->dom_family != AF_UNIX) {
		/* Not a UNIX socket. */
		error = EAFNOSUPPORT;
		goto out1;
	}
	unp = sotounpcb(so);
	if ((unp->unp_flags & UNP_BUSY) != 0) {
		/* Bind or connect already in progress. */
		error = EALREADY;
		goto out1;
	}
	unp->unp_flags |= UNP_BUSY;
	sounlock(so);

	/* Look up the target path. */
	error = cloudabi_namei_simple(l,
	    SCARG(uap, fd) | CLOUDABI_LOOKUP_SYMLINK_FOLLOW, SCARG(uap, path),
	    SCARG(uap, pathlen), LOCKLEAF, &vp);
	if (error != 0) {
		solock(so);
		goto out2;
	}
	if (vp->v_type != VSOCK) {
		error = ENOTSOCK;
		solock(so);
		goto out3;
	}
	error = VOP_ACCESS(vp, VWRITE, l->l_cred);
	if (error != 0) {
		solock(so);
		goto out3;
	}

	/*
	 * Look up the destination socket and reset the lock on the source
	 * socket, so that acquiring the socket lock locks both.
	 */
	mutex_enter(vp->v_interlock);
	so2 = vp->v_socket;
	if (so2 == NULL || so->so_type != so2->so_type) {
		mutex_exit(vp->v_interlock);
		error = so2 == NULL ? ECONNREFUSED : EPROTOTYPE;
		solock(so);
		goto out3;
	}
	solock(so);
	unp_resetlock(so);
	mutex_exit(vp->v_interlock);

	/* Attempt to connect to the socket. */
	if ((so->so_proto->pr_flags & PR_CONNREQUIRED) != 0) {
		if ((so2->so_options & SO_ACCEPTCONN) == 0 ||
		    (so3 = sonewconn(so2, false)) == NULL) {
			error = ECONNREFUSED;
			goto out3;
		}
		unp2 = sotounpcb(so2);
		unp3 = sotounpcb(so3);
		if (unp2->unp_addr) {
			unp3->unp_addr = malloc(unp2->unp_addrlen,
			    M_SONAME, M_WAITOK);
			memcpy(unp3->unp_addr, unp2->unp_addr,
			    unp2->unp_addrlen);
			unp3->unp_addrlen = unp2->unp_addrlen;
		}
		unp3->unp_flags = unp2->unp_flags;
		so2 = so3;
	}
	error = unp_connect1(so, so2, l);
	if (error)
		goto out3;
	unp2 = sotounpcb(so2);
	if (so->so_type == SOCK_SEQPACKET || so->so_type == SOCK_STREAM) {
		unp2->unp_conn = unp;
		if ((unp->unp_flags | unp2->unp_flags) & UNP_CONNWAIT)
			soisconnecting(so);
		else
			soisconnected(so);
		soisconnected(so2);
		/*
		 * If the connection is fully established, break the
		 * association with uipc_lock and give the connected
		 * pair a seperate lock to share.
		 */
		KASSERT(so2->so_head != NULL);
		unp_setpeerlocks(so, so2);
	}

	/* TODO(ed): Call sowait() if still connecting. */

out3:
	vput(vp);
out2:
	unp->unp_flags &= ~UNP_BUSY;
out1:
	sounlock(so);
	fd_putfile(SCARG(uap, s));
	return (error);
}

int
cloudabi_sys_sock_stat_get(struct lwp *l,
    const struct cloudabi_sys_sock_stat_get_args *uap, register_t *retval)
{

	return (ENOSYS);
}

int
cloudabi_sys_sock_listen(struct lwp *l,
    const struct cloudabi_sys_sock_listen_args *uap, register_t *retval)
{
	struct sys_listen_args sys_listen_args;

	SCARG(&sys_listen_args, s) = SCARG(uap, s);
	SCARG(&sys_listen_args, backlog) = SCARG(uap, backlog);
	return (sys_listen(l, &sys_listen_args, retval));
}

int
cloudabi_sys_sock_shutdown(struct lwp *l,
    const struct cloudabi_sys_sock_shutdown_args *uap, register_t *retval)
{
	struct sys_shutdown_args sys_shutdown_args;

	SCARG(&sys_shutdown_args, s) = SCARG(uap, fd);
	switch (SCARG(uap, how)) {
	case CLOUDABI_SHUT_RD:
		SCARG(&sys_shutdown_args, how) = SHUT_RD;
		break;
	case CLOUDABI_SHUT_WR:
		SCARG(&sys_shutdown_args, how) = SHUT_WR;
		break;
	case CLOUDABI_SHUT_RD | CLOUDABI_SHUT_WR:
		SCARG(&sys_shutdown_args, how) = SHUT_RDWR;
		break;
	default:
		return (EINVAL);
	}
	return (sys_shutdown(l, &sys_shutdown_args, retval));
}
