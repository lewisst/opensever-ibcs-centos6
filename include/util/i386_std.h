#ifndef _I386_STD_H_
#define _I386_STD_H_

/*
 * This file contains the system call numbers.
 */

#define __NR_IBCS_restart_syscall	  0
#define __NR_IBCS_exit			  1
#define __NR_IBCS_fork			  2
#define __NR_IBCS_read			  3
#define __NR_IBCS_write			  4
#define __NR_IBCS_open			  5
#define __NR_IBCS_close			  6
#define __NR_IBCS_waitpid		  7
#define __NR_IBCS_creat			  8
#define __NR_IBCS_link			  9
#define __NR_IBCS_unlink		 10
#define __NR_IBCS_execve		 11
#define __NR_IBCS_chdir			 12
#define __NR_IBCS_time			 13
#define __NR_IBCS_mknod			 14
#define __NR_IBCS_chmod			 15
#define __NR_IBCS_lchown		 16
#define __NR_IBCS_break			 17
#define __NR_IBCS_oldstat		 18
#define __NR_IBCS_lseek			 19
#define __NR_IBCS_getpid		 20
#define __NR_IBCS_mount			 21
#define __NR_IBCS_umount		 22
#define __NR_IBCS_setuid		 23
#define __NR_IBCS_getuid		 24
#define __NR_IBCS_stime			 25
#define __NR_IBCS_ptrace		 26
#define __NR_IBCS_alarm			 27
#define __NR_IBCS_oldfstat		 28
#define __NR_IBCS_pause			 29
#define __NR_IBCS_utime			 30
#define __NR_IBCS_stty			 31
#define __NR_IBCS_gtty			 32
#define __NR_IBCS_access		 33
#define __NR_IBCS_nice			 34
#define __NR_IBCS_ftime			 35
#define __NR_IBCS_sync			 36
#define __NR_IBCS_kill			 37
#define __NR_IBCS_rename		 38
#define __NR_IBCS_mkdir			 39
#define __NR_IBCS_rmdir			 40
#define __NR_IBCS_dup			 41
#define __NR_IBCS_pipe			 42
#define __NR_IBCS_times			 43
#define __NR_IBCS_prof			 44
#define __NR_IBCS_brk			 45
#define __NR_IBCS_setgid		 46
#define __NR_IBCS_getgid		 47
#define __NR_IBCS_signal		 48
#define __NR_IBCS_geteuid		 49
#define __NR_IBCS_getegid		 50
#define __NR_IBCS_acct			 51
#define __NR_IBCS_umount2		 52
#define __NR_IBCS_lock			 53
#define __NR_IBCS_ioctl			 54
#define __NR_IBCS_fcntl			 55
#define __NR_IBCS_mpx			 56
#define __NR_IBCS_setpgid		 57
#define __NR_IBCS_ulimit		 58
#define __NR_IBCS_oldolduname		 59
#define __NR_IBCS_umask			 60
#define __NR_IBCS_chroot		 61
#define __NR_IBCS_ustat			 62
#define __NR_IBCS_dup2			 63
#define __NR_IBCS_getppid		 64
#define __NR_IBCS_getpgrp		 65
#define __NR_IBCS_setsid		 66
#define __NR_IBCS_sigaction		 67
#define __NR_IBCS_sgetmask		 68
#define __NR_IBCS_ssetmask		 69
#define __NR_IBCS_setreuid		 70
#define __NR_IBCS_setregid		 71
#define __NR_IBCS_sigsuspend		 72
#define __NR_IBCS_sigpending		 73
#define __NR_IBCS_sethostname		 74
#define __NR_IBCS_setrlimit		 75
#define __NR_IBCS_getrlimit		 76	/* Back compatible 2Gig limited rlimit */
#define __NR_IBCS_getrusage		 77
#define __NR_IBCS_gettimeofday		 78
#define __NR_IBCS_settimeofday		 79
#define __NR_IBCS_getgroups		 80
#define __NR_IBCS_setgroups		 81
#define __NR_IBCS_select		 82
#define __NR_IBCS_symlink		 83
#define __NR_IBCS_oldlstat		 84
#define __NR_IBCS_readlink		 85
#define __NR_IBCS_uselib		 86
#define __NR_IBCS_swapon		 87
#define __NR_IBCS_reboot		 88
#define __NR_IBCS_readdir		 89
#define __NR_IBCS_mmap			 90
#define __NR_IBCS_munmap		 91
#define __NR_IBCS_truncate		 92
#define __NR_IBCS_ftruncate		 93
#define __NR_IBCS_fchmod		 94
#define __NR_IBCS_fchown		 95
#define __NR_IBCS_getpriority		 96
#define __NR_IBCS_setpriority		 97
#define __NR_IBCS_profil		 98
#define __NR_IBCS_statfs		 99
#define __NR_IBCS_fstatfs		100
#define __NR_IBCS_ioperm		101
#define __NR_IBCS_socketcall		102
#define __NR_IBCS_syslog		103
#define __NR_IBCS_setitimer		104
#define __NR_IBCS_getitimer		105
#define __NR_IBCS_stat			106
#define __NR_IBCS_lstat			107
#define __NR_IBCS_fstat			108
#define __NR_IBCS_olduname		109
#define __NR_IBCS_iopl			110
#define __NR_IBCS_vhangup		111
#define __NR_IBCS_idle			112
#define __NR_IBCS_vm86old		113
#define __NR_IBCS_wait4			114
#define __NR_IBCS_swapoff		115
#define __NR_IBCS_sysinfo		116
#define __NR_IBCS_ipc			117
#define __NR_IBCS_fsync			118
#define __NR_IBCS_sigreturn		119
#define __NR_IBCS_clone			120
#define __NR_IBCS_setdomainname		121
#define __NR_IBCS_uname			122
#define __NR_IBCS_modify_ldt		123
#define __NR_IBCS_adjtimex		124
#define __NR_IBCS_mprotect		125
#define __NR_IBCS_sigprocmask		126
#define __NR_IBCS_create_module		127
#define __NR_IBCS_init_module		128
#define __NR_IBCS_delete_module		129
#define __NR_IBCS_get_kernel_syms	130
#define __NR_IBCS_quotactl		131
#define __NR_IBCS_getpgid		132
#define __NR_IBCS_fchdir		133
#define __NR_IBCS_bdflush		134
#define __NR_IBCS_sysfs			135
#define __NR_IBCS_personality		136
#define __NR_IBCS_afs_syscall		137 /* Syscall for Andrew File System */
#define __NR_IBCS_setfsuid		138
#define __NR_IBCS_setfsgid		139
#define __NR_IBCS__llseek		140
#define __NR_IBCS_getdents		141
#define __NR_IBCS__newselect		142
#define __NR_IBCS_flock			143
#define __NR_IBCS_msync			144
#define __NR_IBCS_readv			145
#define __NR_IBCS_writev		146
#define __NR_IBCS_getsid		147
#define __NR_IBCS_fdatasync		148
#define __NR_IBCS__sysctl		149
#define __NR_IBCS_mlock			150
#define __NR_IBCS_munlock		151
#define __NR_IBCS_mlockall		152
#define __NR_IBCS_munlockall		153
#define __NR_IBCS_sched_setparam	154
#define __NR_IBCS_sched_getparam	155
#define __NR_IBCS_sched_setscheduler	156
#define __NR_IBCS_sched_getscheduler	157
#define __NR_IBCS_sched_yield		158
#define __NR_IBCS_sched_get_priority_max 159
#define __NR_IBCS_sched_get_priority_min 160
#define __NR_IBCS_sched_rr_get_interval	161
#define __NR_IBCS_nanosleep		162
#define __NR_IBCS_mremap		163
#define __NR_IBCS_setresuid		164
#define __NR_IBCS_getresuid		165
#define __NR_IBCS_vm86			166
#define __NR_IBCS_query_module		167
#define __NR_IBCS_poll			168
#define __NR_IBCS_nfsservctl		169
#define __NR_IBCS_setresgid		170
#define __NR_IBCS_getresgid		171
#define __NR_IBCS_prctl			172
#define __NR_IBCS_rt_sigreturn		173
#define __NR_IBCS_rt_sigaction		174
#define __NR_IBCS_rt_sigprocmask	175
#define __NR_IBCS_rt_sigpending		176
#define __NR_IBCS_rt_sigtimedwait	177
#define __NR_IBCS_rt_sigqueueinfo	178
#define __NR_IBCS_rt_sigsuspend		179
#define __NR_IBCS_pread64		180
#define __NR_IBCS_pwrite64		181
#define __NR_IBCS_chown			182
#define __NR_IBCS_getcwd		183
#define __NR_IBCS_capget		184
#define __NR_IBCS_capset		185
#define __NR_IBCS_sigaltstack		186
#define __NR_IBCS_sendfile		187
#define __NR_IBCS_getpmsg		188	/* some people actually want streams */
#define __NR_IBCS_putpmsg		189	/* some people actually want streams */
#define __NR_IBCS_vfork			190
#define __NR_IBCS_ugetrlimit		191	/* SuS compliant getrlimit */
#define __NR_IBCS_mmap2			192
#define __NR_IBCS_truncate64		193
#define __NR_IBCS_ftruncate64		194
#define __NR_IBCS_stat64		195
#define __NR_IBCS_lstat64		196
#define __NR_IBCS_fstat64		197
#define __NR_IBCS_lchown32		198
#define __NR_IBCS_getuid32		199
#define __NR_IBCS_getgid32		200
#define __NR_IBCS_geteuid32		201
#define __NR_IBCS_getegid32		202
#define __NR_IBCS_setreuid32		203
#define __NR_IBCS_setregid32		204
#define __NR_IBCS_getgroups32		205
#define __NR_IBCS_setgroups32		206
#define __NR_IBCS_fchown32		207
#define __NR_IBCS_setresuid32		208
#define __NR_IBCS_getresuid32		209
#define __NR_IBCS_setresgid32		210
#define __NR_IBCS_getresgid32		211
#define __NR_IBCS_chown32		212
#define __NR_IBCS_setuid32		213
#define __NR_IBCS_setgid32		214
#define __NR_IBCS_setfsuid32		215
#define __NR_IBCS_setfsgid32		216
#define __NR_IBCS_pivot_root		217
#define __NR_IBCS_mincore		218
#define __NR_IBCS_madvise		219
#define __NR_IBCS_madvise1		219	/* delete when C lib stub is removed */
#define __NR_IBCS_getdents64		220
#define __NR_IBCS_fcntl64		221
/* 223 is unused */
#define __NR_IBCS_gettid		224
#define __NR_IBCS_readahead		225
#define __NR_IBCS_setxattr		226
#define __NR_IBCS_lsetxattr		227
#define __NR_IBCS_fsetxattr		228
#define __NR_IBCS_getxattr		229
#define __NR_IBCS_lgetxattr		230
#define __NR_IBCS_fgetxattr		231
#define __NR_IBCS_listxattr		232
#define __NR_IBCS_llistxattr		233
#define __NR_IBCS_flistxattr		234
#define __NR_IBCS_removexattr		235
#define __NR_IBCS_lremovexattr		236
#define __NR_IBCS_fremovexattr		237
#define __NR_IBCS_tkill			238
#define __NR_IBCS_sendfile64		239
#define __NR_IBCS_futex			240
#define __NR_IBCS_sched_setaffinity	241
#define __NR_IBCS_sched_getaffinity	242
#define __NR_IBCS_set_thread_area	243
#define __NR_IBCS_get_thread_area	244
#define __NR_IBCS_io_setup		245
#define __NR_IBCS_io_destroy		246
#define __NR_IBCS_io_getevents		247
#define __NR_IBCS_io_submit		248
#define __NR_IBCS_io_cancel		249
#define __NR_IBCS_fadvise64		250

#define __NR_IBCS_exit_group		252
#define __NR_IBCS_lookup_dcookie	253
#define __NR_IBCS_epoll_create		254
#define __NR_IBCS_epoll_ctl		255
#define __NR_IBCS_epoll_wait		256
#define __NR_IBCS_remap_file_pages	257
#define __NR_IBCS_set_tid_address	258
#define __NR_IBCS_timer_create		259
#define __NR_IBCS_timer_settime		(__NR_IBCS_timer_create+1)
#define __NR_IBCS_timer_gettime		(__NR_IBCS_timer_create+2)
#define __NR_IBCS_timer_getoverrun	(__NR_IBCS_timer_create+3)
#define __NR_IBCS_timer_delete		(__NR_IBCS_timer_create+4)
#define __NR_IBCS_clock_settime		(__NR_IBCS_timer_create+5)
#define __NR_IBCS_clock_gettime		(__NR_IBCS_timer_create+6)
#define __NR_IBCS_clock_getres		(__NR_IBCS_timer_create+7)
#define __NR_IBCS_clock_nanosleep	(__NR_IBCS_timer_create+8)
#define __NR_IBCS_statfs64		268
#define __NR_IBCS_fstatfs64		269
#define __NR_IBCS_tgkill		270
#define __NR_IBCS_utimes		271
#define __NR_IBCS_fadvise64_64		272
#define __NR_IBCS_vserver		273

#define NR_IBCS_syscalls		274

#define SEMOP		 1
#define SEMGET		 2
#define SEMCTL		 3
#define SEMTIMEDOP	 4
#define MSGSND		11
#define MSGRCV		12
#define MSGGET		13
#define MSGCTL		14
#define SHMAT		21
#define SHMDT		22
#define SHMGET		23
#define SHMCTL		24
/* Used by the DIPC package, try and avoid reusing it */
#define DIPC            25
#define IPCCALL(version,op)	((version)<<16 | (op))

#endif /* _I386_STD_H_ */
