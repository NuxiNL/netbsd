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

#include <sys/types.h>
#include <sys/exec.h>
#include <sys/exec_elf.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/signalvar.h>
#include <sys/syscallvar.h>

#include <machine/userret.h>

#include <compat/cloudabi/cloudabi_util.h>
#include <compat/cloudabi64/cloudabi64_syscall.h>
#include <compat/cloudabi64/cloudabi64_syscalldefs.h>

#include <crypto/cprng_fast/cprng_fast.h>

#include <uvm/uvm_extern.h>

#define	AUXVLEN		10
#define	CANARYLEN	64

extern struct sysent cloudabi64_sysent[];

static void
cloudabi64_setregs(struct lwp *l, struct exec_package *pack, vaddr_t stack)
{
	static const struct sigaction sigign = {
		.sa_handler = SIG_IGN,
	};
	struct trapframe *tf;

	/*
	 * Set registers to initial values. The first argument should
	 * point to the auxiliary vector.
	 */
	/* TODO(ed): Why do we need to fix up the stack alignment here? */
	setregs(l, pack, stack / 16 * 16 - 8);
	tf = l->l_md.md_regs;
	tf->tf_rdi = stack;

	/* Ignore SIGPIPE. */
	sigaction1(l, SIGPIPE, &sigign, NULL, NULL, 0);
}

static void
cloudabi64_syscall(struct trapframe *frame)
{
	const struct sysent *callp;
	struct proc *p;
	struct lwp *l;
	int error;
	register_t *args, code, rval[2];

	l = curlwp;
	p = l->l_proc;
	LWP_CACHE_CREDS(l, p);

	code = frame->tf_rax;
	code &= CLOUDABI64_SYS_NSYSENT - 1;
	callp = p->p_emul->e_sysent + code;

	args = &frame->tf_rdi;
	if (!__predict_false(p->p_trace_enabled || KDTRACE_ENTRY(callp->sy_entry))
	    || (error = trace_enter(code, callp, args)) == 0) {
		rval[0] = 0;
		rval[1] = frame->tf_rdx;
		error = sy_call(callp, l, args, rval);
	}

	switch (error) {
	case 0:
		frame->tf_rax = rval[0];
		frame->tf_rdx = rval[1];
		frame->tf_rflags &= ~PSL_C;	/* carry bit */
		break;
	case ERESTART:
		/*
		 * The offset to adjust the PC by depends on whether we entered
		 * the kernel through the trap or call gate.  We pushed the
		 * size of the instruction into tf_err on entry.
		 */
		frame->tf_rip -= frame->tf_err;
		break;
	case EJUSTRETURN:
		/* Nothing to do. */
		break;
	default:
		error = cloudabi_convert_errno(error);
		frame->tf_rax = error;
		frame->tf_rflags |= PSL_C;	/* carry bit */
		break;
	}

	if (__predict_false(p->p_trace_enabled || KDTRACE_ENTRY(callp->sy_return)))
		trace_exit(code, callp, args, rval, error);

	userret(l);
}

static void
cloudabi64_syscall_intern(struct proc *p)
{

	p->p_md.md_syscall = cloudabi64_syscall;
}

static void
cloudabi64_startlwp(void *arg)
{
	struct exec_package pack;
	cloudabi64_threadattr_t *threadattr = arg;
	struct lwp *l = curlwp;
	struct trapframe *tf;

	/* Reset register contents to initial values. */
	pack.ep_osversion = UINT32_MAX;
	pack.ep_entry = threadattr->entry_point;
	setregs(l, &pack,
	    (threadattr->stack + threadattr->stack_size) / 16 * 16 - 8);

	/*
	 * Set the first function argument to the thread ID. The second
	 * argument corresponds with the argument provided by the parent
	 * thread.
	 */
	tf = l->l_md.md_regs;
	tf->tf_rdi = cloudabi_gettid(l);
	tf->tf_rsi = threadattr->argument;

	kmem_free(threadattr, sizeof(*threadattr));
	userret(l);
}

static int
cloudabi64_elf_probe(struct lwp *l, struct exec_package *epp, void *veh,
    char *itp, vaddr_t *pos)
{
	Elf_Ehdr *eh = (Elf_Ehdr *)veh;

	/* Match the OSABI number. */
	return (eh->e_ident[EI_OSABI] == ELFOSABI_CLOUDABI ? 0 : ENOEXEC);
}

static int
cloudabi64_copyargs(struct lwp *l, struct exec_package *pack,
    struct ps_strings *arginfo, char **stackp, void *argp)
{
	char canarybuf[CANARYLEN];
	Elf_Ehdr *eh;
	const char *endp;
	size_t i, argdatalen;
	int error;

	/*
	 * Compute length of program arguments. As the argument data is
	 * binary safe, we had to add a trailing null byte. Undo this by
	 * reducing the length.
	 */
	endp = argp;
	for (i = 0; i < arginfo->ps_nargvstr; ++i)
		endp += strlen(endp) + 1;
	argdatalen = endp - (const char *)argp;
	if (argdatalen > 0)
		--argdatalen;

	/* Copy out the auxiliary vector. */
	eh = pack->ep_hdr;
	cloudabi64_auxv_t auxv[AUXVLEN] = {
#define	VAL(type, val)	{ .a_type = (type), .a_val = (val) }
#define	PTR(type, ptr)	{ .a_type = (type), .a_ptr = (uintptr_t)(ptr) }
		PTR(CLOUDABI_AT_ARGDATA,
		    *stackp + sizeof(auxv) + sizeof(canarybuf)),
		VAL(CLOUDABI_AT_ARGDATALEN, argdatalen),
		PTR(CLOUDABI_AT_CANARY, *stackp + sizeof(auxv)),
		VAL(CLOUDABI_AT_CANARYLEN, sizeof(canarybuf)),
		VAL(CLOUDABI_AT_NCPUS, ncpu),
		VAL(CLOUDABI_AT_PAGESZ, PAGE_SIZE),
		/* TODO(ed): Use proper offset instead of 0x400000. */
		PTR(CLOUDABI_AT_PHDR, eh->e_phoff + 0x400000),
		VAL(CLOUDABI_AT_PHNUM, eh->e_phnum),
		VAL(CLOUDABI_AT_TID, cloudabi_gettid(l)),
#undef VAL
#undef PTR
		{ .a_type = CLOUDABI_AT_NULL },
	};
	error = copyout(auxv, *stackp, sizeof(auxv));
	if (error != 0)
		return (error);
	*stackp += sizeof(auxv);

	/* Copy out the canary buffer for stack smashing protection. */
	cprng_fast(canarybuf, sizeof(canarybuf));
	error = copyout(canarybuf, *stackp, sizeof(canarybuf));
	if (error != 0)
		return (error);
	*stackp += sizeof(canarybuf);

	/* Copy out the argument data. */
	error = copyout(argp, *stackp, argdatalen);
	if (error != 0)
		return (error);
	*stackp += argdatalen;
	return (0);
}

static struct emul cloudabi64_emul = {
	.e_name			= "cloudabi64",
	.e_path			= NULL,
#ifndef __HAVE_MINIMAL_EMUL
	.e_flags		= 0,
	.e_errno		= NULL,
	.e_nosys		= 0,
	.e_nsysent		= CLOUDABI64_SYS_NSYSENT,
#endif
	.e_sysent		= cloudabi64_sysent,
#ifdef SYSCALL_DEBUG
	.e_syscallnames		= cloudabi64_syscallnames,
#else
	.e_syscallnames		= NULL,
#endif
	.e_sendsig		= NULL,
	.e_trapsignal		= trapsignal,
	.e_tracesig		= NULL,
	.e_sigcode		= NULL,
	.e_esigcode		= NULL,
	.e_sigobject		= NULL,
	.e_setregs		= cloudabi64_setregs,
	.e_proc_exec		= NULL,
	.e_proc_fork		= NULL,
	.e_proc_exit		= NULL,
	.e_lwp_fork		= NULL,
	.e_lwp_exit		= NULL,
#ifdef __HAVE_SYSCALL_INTERN
	.e_syscall_intern	= cloudabi64_syscall_intern,
#else
	.e_syscall_intern	= syscall,
#endif
	.e_sysctlovly		= NULL,
	.e_fault		= NULL,
	.e_vm_default_addr	= uvm_default_mapaddr,
	.e_usertrap		= NULL,
	.e_ucsize		= 0,
	.e_startlwp		= cloudabi64_startlwp,
	.e_dtrace_syscall	= NULL,
};

static struct execsw cloudabi64_execsw = {
	.es_hdrsz		= sizeof(Elf64_Ehdr),
	.es_makecmds		= exec_elf64_makecmds,
	.u.elf_probe_func	= cloudabi64_elf_probe,
	.es_emul		= &cloudabi64_emul,
	.es_prio		= EXECSW_PRIO_ANY,
	.es_arglen	      = sizeof(cloudabi64_auxv_t) * AUXVLEN + CANARYLEN,
	.es_copyargs		= cloudabi64_copyargs,
	.es_setregs		= NULL,
	.es_coredump		= coredump_elf64,
	.es_setup_stack		= exec_setup_stack,
};

static int
compat_cloudabi64_modcmd(modcmd_t cmd, void *arg)
{
	int error;

	switch (cmd) {
	case MODULE_CMD_INIT:
		/* TODO(ed): Futex initialization should go elsewhere. */
		cloudabi_futex_init();
		error = exec_add(&cloudabi64_execsw, 1);
		if (error != 0)
			cloudabi_futex_destroy();
		return (error);
	case MODULE_CMD_FINI:
		error = exec_remove(&cloudabi64_execsw, 1);
		if (error == 0)
			cloudabi_futex_destroy();
		return (error);
	default:
		return (ENOTTY);
	}
}

MODULE(MODULE_CLASS_EXEC, compat_cloudabi64, "exec_elf64");
