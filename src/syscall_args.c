#include "ft_strace.h"

int get_syscall_arg_count(long number, int is_64bit)
{
	if (is_64bit) {
		switch (number) {
			// 0 arguments
			case 39:  // getpid
			case 57:  // fork
			case 58:  // vfork
			case 102: // getuid
			case 104: // getgid
			case 107: // geteuid
			case 108: // getegid
			case 110: // getppid
			case 111: // getpgrp
			case 186: // gettid
				return 0;

			// 1 argument
			case 3:   // close
			case 12:  // brk
			case 60:  // exit
			case 80:  // chdir
			case 95:  // umask
			case 161: // chroot
			case 162: // sync
			case 231: // exit_group
				return 1;

			// 2 arguments
			case 11:  // munmap
			case 21:  // access
			case 32:  // dup
			case 33:  // dup2
			case 79:  // getcwd
			case 82:  // rename
			case 83:  // mkdir
			case 84:  // rmdir
			case 87:  // unlink
			case 89:  // readlink
			case 90:  // chmod
			case 91:  // fchmod
			case 218: // set_tid_address
			case 273: // set_robust_list
				return 2;

			// 3 arguments
			case 0:   // read
			case 1:   // write
			case 2:   // open
			case 4:   // stat
			case 5:   // fstat
			case 6:   // lstat
			case 7:   // poll
			case 8:   // lseek
			case 10:  // mprotect
			case 16:  // ioctl
			case 17:  // pread64
			case 18:  // pwrite64
			case 19:  // readv
			case 20:  // writev
			case 41:  // socket
			case 42:  // connect
			case 49:  // bind
			case 59:  // execve
			case 72:  // fcntl
			case 92:  // chown
			case 93:  // fchown
			case 94:  // lchown
			case 217: // getdents64
				return 3;

			// 4 arguments
			case 13:  // rt_sigaction
			case 14:  // rt_sigprocmask
			case 23:  // select
			case 61:  // wait4
			case 96:  // gettimeofday
			case 227: // clock_settime
			case 228: // clock_gettime
			case 257: // openat
			case 262: // newfstatat
			case 302: // prlimit64
			case 334: // rseq
				return 4;

			// 5 arguments
			case 44:  // sendto
			case 45:  // recvfrom
				return 5;

			// 6 arguments
			case 9:   // mmap
			case 40:  // sendfile
			case 158: // arch_prctl
			case 270: // pselect6
			case 271: // ppoll
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
				return 0;

			// 1 argument
			case 1:   // exit
			case 6:   // close
			case 12:  // chdir
			case 45:  // brk
			case 60:  // umask
			case 61:  // chroot
			case 252: // exit_group
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
				return 3;

			// 4 arguments
			case 114: // wait4
			case 295: // openat
			case 300: // fstatat64
			case 340: // prlimit64
				return 4;

			// 5 arguments
				return 5;

			// 6 arguments
			case 90:  // mmap
				return 6;

			default:
				return 6;
		}
	}
}