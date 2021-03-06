/* $NetBSD$ */

/*
 * System call switch table.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD$");

#include <sys/param.h>
#include <sys/types.h>
#include <compat/cloudabi64/cloudabi64_syscalldefs.h>
#include <compat/cloudabi64/cloudabi64_syscallargs.h>

#define	s(type)	sizeof(type)
#define	n(type)	(sizeof(type)/sizeof (register_t))
#define	ns(type)	.sy_narg = n(type), .sy_argsize = s(type)

struct sysent cloudabi64_sysent[] = {
	{
		ns(struct cloudabi_sys_clock_res_get_args),
		.sy_call = (sy_call_t *)cloudabi_sys_clock_res_get
	},		/* 0 = clock_res_get */
	{
		ns(struct cloudabi_sys_clock_time_get_args),
		.sy_call = (sy_call_t *)cloudabi_sys_clock_time_get
	},		/* 1 = clock_time_get */
	{
		ns(struct cloudabi_sys_condvar_signal_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_condvar_signal
	},		/* 2 = condvar_signal */
	{
		ns(struct cloudabi_sys_fd_close_args),
		.sy_call = (sy_call_t *)cloudabi_sys_fd_close
	},		/* 3 = fd_close */
	{
		ns(struct cloudabi_sys_fd_create1_args),
		.sy_call = (sy_call_t *)cloudabi_sys_fd_create1
	},		/* 4 = fd_create1 */
	{
		ns(struct cloudabi_sys_fd_create2_args),
		.sy_call = (sy_call_t *)cloudabi_sys_fd_create2
	},		/* 5 = fd_create2 */
	{
		ns(struct cloudabi_sys_fd_datasync_args),
		.sy_call = (sy_call_t *)cloudabi_sys_fd_datasync
	},		/* 6 = fd_datasync */
	{
		ns(struct cloudabi_sys_fd_dup_args),
		.sy_call = (sy_call_t *)cloudabi_sys_fd_dup
	},		/* 7 = fd_dup */
	{
		ns(struct cloudabi64_sys_fd_pread_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_fd_pread
	},		/* 8 = fd_pread */
	{
		ns(struct cloudabi64_sys_fd_pwrite_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_fd_pwrite
	},		/* 9 = fd_pwrite */
	{
		ns(struct cloudabi64_sys_fd_read_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_fd_read
	},		/* 10 = fd_read */
	{
		ns(struct cloudabi_sys_fd_replace_args),
		.sy_call = (sy_call_t *)cloudabi_sys_fd_replace
	},		/* 11 = fd_replace */
	{
		ns(struct cloudabi_sys_fd_seek_args),
		.sy_call = (sy_call_t *)cloudabi_sys_fd_seek
	},		/* 12 = fd_seek */
	{
		ns(struct cloudabi_sys_fd_stat_get_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_fd_stat_get
	},		/* 13 = fd_stat_get */
	{
		ns(struct cloudabi_sys_fd_stat_put_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_fd_stat_put
	},		/* 14 = fd_stat_put */
	{
		ns(struct cloudabi_sys_fd_sync_args),
		.sy_call = (sy_call_t *)cloudabi_sys_fd_sync
	},		/* 15 = fd_sync */
	{
		ns(struct cloudabi64_sys_fd_write_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_fd_write
	},		/* 16 = fd_write */
	{
		ns(struct cloudabi_sys_file_advise_args),
		.sy_call = (sy_call_t *)cloudabi_sys_file_advise
	},		/* 17 = file_advise */
	{
		ns(struct cloudabi_sys_file_allocate_args),
		.sy_call = (sy_call_t *)cloudabi_sys_file_allocate
	},		/* 18 = file_allocate */
	{
		ns(struct cloudabi_sys_file_create_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_create
	},		/* 19 = file_create */
	{
		ns(struct cloudabi_sys_file_link_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_link
	},		/* 20 = file_link */
	{
		ns(struct cloudabi_sys_file_open_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_open
	},		/* 21 = file_open */
	{
		ns(struct cloudabi_sys_file_readdir_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_readdir
	},		/* 22 = file_readdir */
	{
		ns(struct cloudabi_sys_file_readlink_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_readlink
	},		/* 23 = file_readlink */
	{
		ns(struct cloudabi_sys_file_rename_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_rename
	},		/* 24 = file_rename */
	{
		ns(struct cloudabi_sys_file_stat_fget_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_stat_fget
	},		/* 25 = file_stat_fget */
	{
		ns(struct cloudabi_sys_file_stat_fput_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_stat_fput
	},		/* 26 = file_stat_fput */
	{
		ns(struct cloudabi_sys_file_stat_get_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_stat_get
	},		/* 27 = file_stat_get */
	{
		ns(struct cloudabi_sys_file_stat_put_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_stat_put
	},		/* 28 = file_stat_put */
	{
		ns(struct cloudabi_sys_file_symlink_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_symlink
	},		/* 29 = file_symlink */
	{
		ns(struct cloudabi_sys_file_unlink_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_file_unlink
	},		/* 30 = file_unlink */
	{
		ns(struct cloudabi_sys_lock_unlock_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_lock_unlock
	},		/* 31 = lock_unlock */
	{
		ns(struct cloudabi_sys_mem_advise_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_mem_advise
	},		/* 32 = mem_advise */
	{
		ns(struct cloudabi_sys_mem_lock_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_mem_lock
	},		/* 33 = mem_lock */
	{
		ns(struct cloudabi_sys_mem_map_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_mem_map
	},		/* 34 = mem_map */
	{
		ns(struct cloudabi_sys_mem_protect_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_mem_protect
	},		/* 35 = mem_protect */
	{
		ns(struct cloudabi_sys_mem_sync_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_mem_sync
	},		/* 36 = mem_sync */
	{
		ns(struct cloudabi_sys_mem_unlock_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_mem_unlock
	},		/* 37 = mem_unlock */
	{
		ns(struct cloudabi_sys_mem_unmap_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_mem_unmap
	},		/* 38 = mem_unmap */
	{
		ns(struct cloudabi64_sys_poll_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_poll
	},		/* 39 = poll */
	{
		ns(struct cloudabi_sys_proc_exec_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_proc_exec
	},		/* 40 = proc_exec */
	{
		ns(struct cloudabi_sys_proc_exit_args),
		.sy_call = (sy_call_t *)cloudabi_sys_proc_exit
	},		/* 41 = proc_exit */
	{
		.sy_call = (sy_call_t *)cloudabi64_sys_proc_fork
	},		/* 42 = proc_fork */
	{
		ns(struct cloudabi_sys_proc_raise_args),
		.sy_call = (sy_call_t *)cloudabi_sys_proc_raise
	},		/* 43 = proc_raise */
	{
		ns(struct cloudabi_sys_random_get_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_random_get
	},		/* 44 = random_get */
	{
		ns(struct cloudabi_sys_sock_accept_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_sock_accept
	},		/* 45 = sock_accept */
	{
		ns(struct cloudabi_sys_sock_bind_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_sock_bind
	},		/* 46 = sock_bind */
	{
		ns(struct cloudabi_sys_sock_connect_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_sock_connect
	},		/* 47 = sock_connect */
	{
		ns(struct cloudabi_sys_sock_listen_args),
		.sy_call = (sy_call_t *)cloudabi_sys_sock_listen
	},		/* 48 = sock_listen */
	{
		ns(struct cloudabi64_sys_sock_recv_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_sock_recv
	},		/* 49 = sock_recv */
	{
		ns(struct cloudabi64_sys_sock_send_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_sock_send
	},		/* 50 = sock_send */
	{
		ns(struct cloudabi_sys_sock_shutdown_args),
		.sy_call = (sy_call_t *)cloudabi_sys_sock_shutdown
	},		/* 51 = sock_shutdown */
	{
		ns(struct cloudabi_sys_sock_stat_get_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_sock_stat_get
	},		/* 52 = sock_stat_get */
	{
		ns(struct cloudabi64_sys_thread_create_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_thread_create
	},		/* 53 = thread_create */
	{
		ns(struct cloudabi_sys_thread_exit_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi_sys_thread_exit
	},		/* 54 = thread_exit */
	{
		ns(struct cloudabi64_sys_thread_tcb_set_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_thread_tcb_set
	},		/* 55 = thread_tcb_set */
	{
		.sy_call = (sy_call_t *)cloudabi_sys_thread_yield
	},		/* 56 = thread_yield */
	{
		ns(struct cloudabi64_sys_poll_fd_args),
		.sy_flags = SYCALL_ARG_PTR,
		.sy_call = (sy_call_t *)cloudabi64_sys_poll_fd
	},		/* 57 = poll_fd */
	{
		.sy_call = sys_nosys,
	},		/* 58 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 59 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 60 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 61 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 62 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 63 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 64 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 65 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 66 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 67 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 68 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 69 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 70 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 71 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 72 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 73 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 74 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 75 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 76 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 77 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 78 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 79 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 80 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 81 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 82 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 83 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 84 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 85 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 86 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 87 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 88 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 89 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 90 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 91 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 92 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 93 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 94 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 95 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 96 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 97 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 98 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 99 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 100 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 101 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 102 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 103 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 104 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 105 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 106 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 107 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 108 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 109 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 110 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 111 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 112 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 113 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 114 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 115 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 116 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 117 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 118 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 119 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 120 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 121 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 122 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 123 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 124 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 125 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 126 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 127 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 128 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 129 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 130 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 131 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 132 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 133 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 134 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 135 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 136 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 137 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 138 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 139 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 140 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 141 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 142 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 143 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 144 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 145 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 146 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 147 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 148 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 149 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 150 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 151 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 152 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 153 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 154 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 155 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 156 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 157 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 158 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 159 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 160 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 161 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 162 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 163 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 164 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 165 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 166 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 167 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 168 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 169 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 170 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 171 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 172 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 173 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 174 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 175 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 176 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 177 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 178 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 179 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 180 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 181 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 182 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 183 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 184 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 185 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 186 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 187 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 188 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 189 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 190 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 191 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 192 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 193 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 194 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 195 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 196 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 197 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 198 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 199 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 200 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 201 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 202 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 203 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 204 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 205 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 206 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 207 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 208 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 209 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 210 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 211 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 212 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 213 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 214 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 215 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 216 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 217 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 218 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 219 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 220 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 221 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 222 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 223 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 224 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 225 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 226 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 227 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 228 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 229 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 230 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 231 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 232 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 233 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 234 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 235 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 236 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 237 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 238 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 239 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 240 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 241 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 242 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 243 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 244 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 245 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 246 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 247 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 248 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 249 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 250 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 251 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 252 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 253 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 254 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 255 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 256 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 257 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 258 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 259 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 260 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 261 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 262 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 263 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 264 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 265 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 266 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 267 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 268 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 269 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 270 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 271 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 272 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 273 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 274 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 275 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 276 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 277 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 278 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 279 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 280 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 281 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 282 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 283 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 284 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 285 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 286 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 287 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 288 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 289 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 290 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 291 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 292 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 293 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 294 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 295 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 296 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 297 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 298 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 299 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 300 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 301 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 302 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 303 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 304 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 305 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 306 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 307 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 308 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 309 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 310 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 311 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 312 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 313 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 314 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 315 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 316 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 317 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 318 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 319 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 320 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 321 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 322 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 323 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 324 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 325 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 326 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 327 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 328 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 329 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 330 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 331 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 332 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 333 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 334 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 335 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 336 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 337 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 338 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 339 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 340 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 341 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 342 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 343 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 344 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 345 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 346 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 347 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 348 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 349 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 350 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 351 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 352 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 353 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 354 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 355 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 356 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 357 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 358 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 359 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 360 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 361 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 362 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 363 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 364 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 365 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 366 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 367 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 368 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 369 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 370 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 371 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 372 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 373 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 374 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 375 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 376 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 377 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 378 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 379 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 380 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 381 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 382 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 383 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 384 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 385 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 386 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 387 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 388 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 389 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 390 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 391 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 392 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 393 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 394 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 395 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 396 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 397 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 398 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 399 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 400 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 401 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 402 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 403 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 404 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 405 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 406 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 407 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 408 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 409 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 410 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 411 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 412 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 413 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 414 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 415 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 416 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 417 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 418 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 419 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 420 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 421 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 422 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 423 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 424 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 425 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 426 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 427 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 428 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 429 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 430 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 431 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 432 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 433 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 434 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 435 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 436 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 437 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 438 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 439 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 440 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 441 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 442 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 443 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 444 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 445 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 446 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 447 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 448 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 449 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 450 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 451 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 452 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 453 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 454 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 455 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 456 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 457 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 458 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 459 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 460 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 461 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 462 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 463 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 464 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 465 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 466 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 467 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 468 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 469 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 470 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 471 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 472 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 473 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 474 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 475 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 476 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 477 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 478 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 479 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 480 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 481 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 482 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 483 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 484 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 485 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 486 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 487 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 488 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 489 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 490 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 491 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 492 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 493 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 494 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 495 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 496 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 497 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 498 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 499 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 500 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 501 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 502 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 503 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 504 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 505 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 506 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 507 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 508 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 509 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 510 = filler */
	{
		.sy_call = sys_nosys,
	},		/* 511 = filler */
};
