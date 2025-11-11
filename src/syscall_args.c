#include "ft_strace.h"

// Retourne le nombre d'arguments pour un syscall donné
// Cette fonction simplifie l'affichage en ne montrant que les args pertinents
int get_syscall_arg_count(long number, int is_64bit)
{
	if (is_64bit) {
		// Syscalls 64-bit courants
		switch (number) {
			case 0:   // read
			case 1:   // write
			case 2:   // open
			case 17:  // pread64
			case 18:  // pwrite64
				return 3;
			case 3:   // close
			case 12:  // brk
			case 39:  // getpid
			case 57:  // fork
			case 60:  // exit
			case 79:  // getcwd
			case 102: // getuid
			case 104: // getgid
			case 107: // geteuid
			case 108: // getegid
			case 110: // getppid
				return 1;
			case 9:   // mmap
				return 6;
			case 10:  // mprotect
			case 59:  // execve
				return 3;
			case 11:  // munmap
			case 21:  // access
			case 32:  // dup
			case 33:  // dup2
				return 2;
			case 13:  // rt_sigaction
			case 14:  // rt_sigprocmask
				return 4;
			case 16:  // ioctl
				return 3;
			case 41:  // socket
				return 3;
			case 42:  // connect
			case 49:  // bind
				return 3;
			case 72:  // fcntl
				return 3;
			case 217: // getdents64
				return 3;
			case 257: // openat
				return 4;
			case 262: // newfstatat
				return 4;
			case 302: // prlimit64
				return 4;
			case 334: // rseq
				return 4;
			default:
				return 6; // Par défaut, tous les args
		}
	} else {
		// Pour 32-bit, similaire mais avec numéros différents
		switch (number) {
			case 1:   // exit
			case 20:  // getpid
			case 24:  // getuid
			case 47:  // getgid
			case 49:  // geteuid
			case 50:  // getegid
			case 64:  // getppid
				return 1;
			case 3:   // read
			case 4:   // write
			case 5:   // open
				return 3;
			case 6:   // close
			case 45:  // brk
				return 1;
			default:
				return 6;
		}
	}
}