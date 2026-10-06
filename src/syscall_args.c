#include "ft_strace.h"

int get_syscall_arg_count(long number, int is_64bit)
{
	if (is_64bit) {
		switch (number) {
			// 0 arguments
			case 15:  // rt_sigreturn
			case 24:  // sched_yield
			case 34:  // pause
			case 39:  // getpid
			case 57:  // fork
			case 58:  // vfork
			case 102: // getuid
			case 104: // getgid
			case 107: // geteuid
			case 108: // getegid
			case 110: // getppid
			case 111: // getpgrp
			case 112: // setsid
			case 162: // sync
			case 186: // gettid
				return 0;

			// 1 argument
			case 3:   // close
			case 12:  // brk
			case 22:  // pipe
			case 32:  // dup
			case 60:  // exit
			case 63:  // uname
			case 74:  // fsync
			case 80:  // chdir
			case 81:  // fchdir
			case 84:  // rmdir
			case 87:  // unlink
			case 95:  // umask
			case 99:  // sysinfo
			case 105: // setuid
			case 106: // setgid
			case 121: // getpgid
			case 124: // getsid
			case 161: // chroot
			case 201: // time
			case 218: // set_tid_address
			case 231: // exit_group
				return 1;

			// 2 arguments
			case 4:   // stat
			case 5:   // fstat
			case 6:   // lstat
			case 11:  // munmap
			case 21:  // access
			case 33:  // dup2
			case 35:  // nanosleep
			case 48:  // shutdown
			case 50:  // listen
			case 62:  // kill
			case 77:  // ftruncate
			case 79:  // getcwd
			case 82:  // rename
			case 83:  // mkdir
			case 90:  // chmod
			case 91:  // fchmod
			case 96:  // gettimeofday
			case 97:  // getrlimit
			case 98:  // getrusage
			case 109: // setpgid
			case 131: // sigaltstack
			case 137: // statfs
			case 138: // fstatfs
			case 158: // arch_prctl
			case 200: // tkill
			case 227: // clock_settime
			case 228: // clock_gettime
			case 229: // clock_getres
			case 273: // set_robust_list
			case 293: // pipe2
			case 319: // memfd_create
			case 435: // clone3
				return 2;

			// 3 arguments
			case 0:   // read
			case 1:   // write
			case 2:   // open
			case 7:   // poll
			case 8:   // lseek
			case 10:  // mprotect
			case 16:  // ioctl
			case 19:  // readv
			case 20:  // writev
			case 28:  // madvise
			case 41:  // socket
			case 42:  // connect
			case 43:  // accept
			case 49:  // bind
			case 51:  // getsockname
			case 52:  // getpeername
			case 59:  // execve
			case 72:  // fcntl
			case 78:  // getdents
			case 89:  // readlink
			case 92:  // chown
			case 93:  // fchown
			case 94:  // lchown
			case 194: // listxattr
			case 195: // llistxattr
			case 196: // flistxattr
			case 204: // sched_getaffinity
			case 217: // getdents64
			case 234: // tgkill
			case 258: // mkdirat
			case 263: // unlinkat
			case 292: // dup3
			case 318: // getrandom
			case 324: // membarrier
			case 436: // close_range
				return 3;

			// 4 arguments
			case 13:  // rt_sigaction
			case 14:  // rt_sigprocmask
			case 17:  // pread64
			case 18:  // pwrite64
			case 40:  // sendfile
			case 53:  // socketpair
			case 61:  // wait4
			case 191: // getxattr
			case 192: // lgetxattr
			case 193: // fgetxattr
			case 221: // fadvise64
			case 230: // clock_nanosleep
			case 232: // epoll_wait
			case 257: // openat
			case 262: // newfstatat
			case 267: // readlinkat
			case 288: // accept4
			case 302: // prlimit64
			case 334: // rseq
			case 437: // openat2
			case 439: // faccessat2
				return 4;

			// 5 arguments
			case 23:  // select
			case 25:  // mremap
			case 54:  // setsockopt
			case 55:  // getsockopt
			case 56:  // clone
			case 157: // prctl
			case 271: // ppoll
			case 332: // statx
				return 5;

			// 6 arguments
			case 9:   // mmap
			case 44:  // sendto
			case 45:  // recvfrom
			case 202: // futex
			case 270: // pselect6
				return 6;

			default:
				// Par défaut, afficher jusqu'à 6 arguments
				return 6;
		}
	} else {
		// 32-bit
		switch (number) {
			// 0 arguments
			case 2:   // fork
			case 20:  // getpid
			case 24:  // getuid
			case 47:  // getgid
			case 49:  // geteuid
			case 50:  // getegid
			case 64:  // getppid
			case 65:  // getpgrp
			case 224: // gettid
			case 199: // getuid32
			case 200: // getgid32
			case 201: // geteuid32
			case 202: // getegid32
				return 0;

			// 1 argument
			case 1:   // exit
			case 6:   // close
			case 12:  // chdir
			case 45:  // brk
			case 60:  // umask
			case 61:  // chroot
			case 252: // exit_group
			case 122: // uname
			case 243: // set_thread_area
			case 258: // set_tid_address
				return 1;

			// 2 arguments
			case 10:  // unlink
			case 33:  // access
			case 38:  // rename
			case 39:  // mkdir
			case 40:  // rmdir
			case 41:  // dup
			case 63:  // dup2
			case 85:  // readlink
			case 91:  // munmap
			case 191: // ugetrlimit
			case 197: // fstat64
			case 311: // set_robust_list
			case 403: // clock_gettime64
				return 2;

			// 3 arguments
			case 3:   // read
			case 4:   // write
			case 5:   // open
			case 8:   // creat
			case 11:  // execve
			case 15:  // chmod
			case 54:  // ioctl
			case 106: // stat
			case 107: // lstat
			case 108: // fstat
			case 220: // getdents64
			case 125: // mprotect
			case 221: // fcntl64
			case 355: // getrandom
				return 3;

			// 4 arguments
			case 114: // wait4
			case 295: // openat
			case 300: // fstatat64
			case 340: // prlimit64
			case 386: // rseq
				return 4;

			// 5 arguments
			case 140: // _llseek
			case 180: // pread64 (offset sur 2 registres)
			case 181: // pwrite64
			case 383: // statx
				return 5;

			// 6 arguments
			case 90:  // mmap
			case 192: // mmap2
				return 6;

			default:
				return 6;
		}
	}
}