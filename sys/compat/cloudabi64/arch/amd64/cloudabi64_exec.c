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
#include <sys/module.h>
#include <sys/proc.h>

#include <uvm/uvm_extern.h>

#define ELF64_AUXSIZE (howmany(ELF_AUX_ENTRIES * sizeof(Aux64Info), \
    sizeof(Elf64_Addr)) + MAXPATHLEN + ALIGN(1))

extern struct sysent cloudabi64_sysent[];

static void
cloudabi64_syscall(struct trapframe *frame)
{

	/* TODO(ed): Implement. */
}

static void
cloudabi64_syscall_intern(struct proc *p)
{

	p->p_md.md_syscall = cloudabi64_syscall;
}

static int
cloudabi64_elf_probe(struct lwp *l, struct exec_package *epp, void *veh,
    char *itp, vaddr_t *pos)
{
	Elf_Ehdr *eh = (Elf_Ehdr *)veh;

	/* Match the OSABI number. */
	return (eh->e_ident[EI_OSABI] == ELFOSABI_CLOUDABI ? 0 : ENOEXEC);
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
	.e_trapsignal		= NULL,
	.e_tracesig		= NULL,
	.e_sigcode		= NULL,
	.e_esigcode		= NULL,
	.e_sigobject		= NULL,
	.e_setregs		= setregs,
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
	.e_startlwp		= NULL,
	.e_dtrace_syscall	= NULL,
};

static struct execsw cloudabi64_execsw = {
	.es_hdrsz		= sizeof(Elf64_Ehdr),
	.es_makecmds		= exec_elf64_makecmds,
	.u.elf_probe_func	= cloudabi64_elf_probe,
	.es_emul		= &cloudabi64_emul,
	.es_prio		= EXECSW_PRIO_ANY,
	.es_arglen		= ELF64_AUXSIZE,
	.es_copyargs		= elf64_copyargs,
	.es_setregs		= NULL,
	.es_coredump		= coredump_elf64,
	.es_setup_stack		= exec_setup_stack,
};

static int
compat_cloudabi64_modcmd(modcmd_t cmd, void *arg)
{

	switch (cmd) {
	case MODULE_CMD_INIT:
		return (exec_add(&cloudabi64_execsw, 1));
	case MODULE_CMD_FINI:
		return (exec_remove(&cloudabi64_execsw, 1));
	default:
		return (ENOTTY);
	}
}

MODULE(MODULE_CLASS_EXEC, compat_cloudabi64, "exec_elf64");
