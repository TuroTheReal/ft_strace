#include "ft_strace.h"

#define AT_FDCWD -100

void print_signal(pid_t pid, int sig)
{
	siginfo_t si;

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &si) == 0) {
		fprintf(stderr, "--- %s {si_signo=%d, si_code=%d} ---\n",
			strsignal(sig), si.si_signo, si.si_code);
	} else {
		fprintf(stderr, "--- %s ---\n", strsignal(sig));
	}
}

// Vérifier si le contenu est affichable
static int is_printable_content(const char *buf, size_t len)
{
	size_t i;
	size_t printable = 0;

	if (len > 32) len = 32;  // Limiter la vérification

	for (i = 0; i < len; i++) {
		if ((buf[i] >= 32 && buf[i] < 127) || buf[i] == '\n' || buf[i] == '\t' || buf[i] == '\r') {
			printable++;
		}
	}

	return len > 0 && (printable * 100 / len) > 70;  // Si >70% printable
}

// Lire la mémoire via /proc/PID/mem
static int read_process_memory(pid_t pid, unsigned long long addr, void *buf, size_t len)
{
	char mem_path[64];
	int fd;
	ssize_t nread;

	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

	fd = open(mem_path, O_RDONLY);
	if (fd == -1) {
		return -1;
	}

	// Chercher à l'adresse
	if (lseek(fd, addr, SEEK_SET) == -1) {
		close(fd);
		return -1;
	}

	// Lire
	nread = read(fd, buf, len);
	close(fd);

	return (nread == (ssize_t)len) ? 0 : -1;
}

// Lire une chaîne depuis le processus tracé
static void print_string_arg(pid_t pid, unsigned long long addr, int max_len)
{
	char buffer[256];
	int i;

	memset(buffer, 0, sizeof(buffer));

	if (addr == 0) {
		printf("NULL");
		return;
	}

	// Lire via /proc
	if (read_process_memory(pid, addr, buffer, max_len < 255 ? max_len : 255) != 0) {
		printf("%#llx", addr);  // Si échec, afficher l'adresse
		return;
	}

	buffer[255] = '\0';

	printf("\"");
	for (i = 0; buffer[i] && i < 32; i++) {
		if (buffer[i] >= 32 && buffer[i] < 127) {
			putchar(buffer[i]);
		} else if (buffer[i] == '\n') {
			printf("\\n");
		} else if (buffer[i] == '\t') {
			printf("\\t");
		} else if (buffer[i] == '\r') {
			printf("\\r");
		} else {
			printf("\\x%02x", (unsigned char)buffer[i]);
		}
	}

	if (buffer[i]) {
		printf("...");
	}
	printf("\"");
}

// Formatter les arguments selon le syscall
static void print_syscall_args(t_syscall_info *info, pid_t pid)
{
	int i;
	long num = info->number;
	int is_64 = info->is_64bit;

	// exit_group - afficher l'argument en décimal
	if ((is_64 && num == 231) || (!is_64 && num == 252)) {
		printf("%d", (int)info->args[0]);
		return;
	}

	// close - afficher le fd en décimal
	if ((is_64 && num == 3) || (!is_64 && num == 6)) {
		printf("%d", (int)info->args[0]);
		return;
	}

	// read
	if ((is_64 && num == 0) || (!is_64 && num == 3)) {
		printf("%d, ", (int)info->args[0]);
		printf("%#llx, ", info->args[1]);
		printf("%llu", info->args[2]);
		return;
	}

	// write - essayer d'afficher le contenu
	if ((is_64 && num == 1) || (!is_64 && num == 4)) {
		printf("%d, ", (int)info->args[0]);

		unsigned long long addr = info->args[1];
		unsigned long long size = info->args[2];

		if (size > 0 && size <= 1024) {
			char buffer[1025];
			size_t to_read = size > 1024 ? 1024 : size;

			memset(buffer, 0, sizeof(buffer));

			// Utiliser /proc au lieu de ptrace
			if (read_process_memory(pid, addr, buffer, to_read) == 0
				&& is_printable_content(buffer, to_read)) {
				printf("\"");
				size_t display_len = to_read > 32 ? 32 : to_read;
				for (size_t j = 0; j < display_len; j++) {
					if (buffer[j] >= 32 && buffer[j] < 127) {
						putchar(buffer[j]);
					} else if (buffer[j] == '\n') {
						printf("\\n");
					} else if (buffer[j] == '\t') {
						printf("\\t");
					} else if (buffer[j] == '\r') {
						printf("\\r");
					} else {
						printf("\\x%02x", (unsigned char)buffer[j]);
					}
				}
				if (to_read > 32) {
					printf("...");
				}
				printf("\", %llu", size);
			} else {
				printf("%#llx, %llu", addr, size);
			}
		} else {
			printf("%#llx, %llu", addr, size);
		}
		return;
	}

	// open
	if ((is_64 && num == 2) || (!is_64 && num == 5)) {
		print_string_arg(pid, info->args[0], 32);
		printf(", ");
		unsigned long flags = info->args[1];
		if (flags & 0x40) printf("O_CREAT|");
		if (flags & 0x200) printf("O_DIRECTORY|");
		if (flags & 0x80000) printf("O_CLOEXEC|");
		if ((flags & 0x3) == 0) printf("O_RDONLY");
		else if ((flags & 0x3) == 1) printf("O_WRONLY");
		else if ((flags & 0x3) == 2) printf("O_RDWR");
		return;
	}

	// access
	if ((is_64 && num == 21) || (!is_64 && num == 33)) {
		print_string_arg(pid, info->args[0], 32);
		printf(", ");
		switch(info->args[1]) {
			case 0: printf("F_OK"); break;
			case 1: printf("X_OK"); break;
			case 2: printf("W_OK"); break;
			case 4: printf("R_OK"); break;
			default: printf("%#llx", info->args[1]);
		}
		return;
	}

	// openat
	if (is_64 && num == 257) {
		// Traiter comme un int signé 32-bit
		int fd = (int)info->args[0];

		if (fd == -100) {
			printf("AT_FDCWD, ");
		} else {
			printf("%d, ", fd);
		}
		print_string_arg(pid, info->args[1], 32);
		printf(", ");
		unsigned long flags = info->args[2];
		if (flags & 0x40) printf("O_CREAT|");
		if (flags & 0x200) printf("O_DIRECTORY|");
		if (flags & 0x80000) printf("O_CLOEXEC|");
		if ((flags & 0x3) == 0) printf("O_RDONLY");
		else if ((flags & 0x3) == 1) printf("O_WRONLY");
		else if ((flags & 0x3) == 2) printf("O_RDWR");
		if (info->arg_count > 3 && info->args[3] != 0) {
			printf(", %#llo", info->args[3]);
		}
		return;
	}

	// execve
	if ((is_64 && num == 59) || (!is_64 && num == 11)) {
		print_string_arg(pid, info->args[0], 32);
		printf(", ");
		printf("%#llx, %#llx", info->args[1], info->args[2]);
		return;
	}

	// newfstatat
	if (is_64 && num == 262) {
		// Traiter comme un int signé 32-bit
		int fd = (int)info->args[0];

		if (fd == -100) {
			printf("AT_FDCWD, ");
		} else {
			printf("%d, ", fd);
		}
		print_string_arg(pid, info->args[1], 32);
		printf(", %#llx, ", info->args[2]);
		if (info->args[3] == 0x1000) {
			printf("AT_EMPTY_PATH");
		} else if (info->args[3] == 0) {
			printf("0");
		} else {
			printf("%#llx", info->args[3]);
		}
		return;
	}

	// mmap
	if ((is_64 && num == 9)) {
		if (info->args[0] == 0) {
			printf("NULL");
		} else {
			printf("%#llx", info->args[0]);
		}
		printf(", %llu, ", info->args[1]);

		unsigned long prot = info->args[2];
		if (prot == 0) printf("PROT_NONE");
		else {
			int first = 1;
			if (prot & 0x1) { printf("PROT_READ"); first = 0; }
			if (prot & 0x2) { if (!first) printf("|"); printf("PROT_WRITE"); first = 0; }
			if (prot & 0x4) { if (!first) printf("|"); printf("PROT_EXEC"); }
		}
		printf(", ");

		unsigned long flags = info->args[3];
		int first = 1;
		if (flags & 0x01) { printf("MAP_SHARED"); first = 0; }
		if (flags & 0x02) { if (!first) printf("|"); printf("MAP_PRIVATE"); first = 0; }
		if (flags & 0x20) { if (!first) printf("|"); printf("MAP_ANONYMOUS"); first = 0; }
		if (flags & 0x10) { if (!first) printf("|"); printf("MAP_FIXED"); first = 0; }
		if (flags & 0x4000) { if (!first) printf("|"); printf("MAP_DENYWRITE"); }
		printf(", ");

		if (info->args[4] == (unsigned long long)-1) {
			printf("-1");
		} else {
			printf("%d", (int)info->args[4]);
		}
		printf(", ");
		if (info->args[5] == 0) {
			printf("0");
		} else {
			printf("%#llx", info->args[5]);
		}
		return;
	}

	// mprotect
	if ((is_64 && num == 10)) {
		printf("%#llx, %llu, ", info->args[0], info->args[1]);
		unsigned long prot = info->args[2];
		if (prot == 0) printf("PROT_NONE");
		else {
			int first = 1;
			if (prot & 0x1) { printf("PROT_READ"); first = 0; }
			if (prot & 0x2) { if (!first) printf("|"); printf("PROT_WRITE"); first = 0; }
			if (prot & 0x4) { if (!first) printf("|"); printf("PROT_EXEC"); }
		}
		return;
	}

	// munmap
	if (is_64 && num == 11) {
		printf("%#llx, %llu", info->args[0], info->args[1]);
		return;
	}

	// brk
	if (is_64 && num == 12) {
		if (info->args[0] == 0) {
			printf("NULL");
		} else {
			printf("%#llx", info->args[0]);
		}
		return;
	}

	// ioctl
	if (is_64 && num == 16) {
		printf("%d, ", (int)info->args[0]);
		unsigned long cmd = info->args[1];
		if (cmd == 0x5401) printf("TCGETS");
		else if (cmd == 0x5413) printf("TIOCGWINSZ");
		else printf("%#lx", cmd);
		if (info->arg_count > 2) {
			printf(", %#llx", info->args[2]);
		}
		return;
	}

	// pread64, pwrite64
	if ((is_64 && num == 17) || (is_64 && num == 18)) {
		printf("%d, %#llx, %llu", (int)info->args[0], info->args[1], info->args[2]);
		if (info->arg_count > 3) {
			printf(", %#llx", info->args[3]);
		}
		return;
	}

	// statfs
	if (is_64 && num == 137) {
		print_string_arg(pid, info->args[0], 32);
		printf(", %#llx", info->args[1]);
		return;
	}

	// arch_prctl
	if (is_64 && num == 158) {
		printf("%#llx, %#llx", info->args[0], info->args[1]);
		if (info->arg_count > 2 && info->args[2] != 0) {
			printf(", %#llx", info->args[2]);
		}
		if (info->arg_count > 3 && info->args[3] != 0) {
			printf(", %#llx", info->args[3]);
		}
		return;
	}

	// getdents64
	if (is_64 && num == 217) {
		printf("%d, %#llx, %llu", (int)info->args[0], info->args[1], info->args[2]);
		return;
	}

	// set_tid_address
	if (is_64 && num == 218) {
		printf("%#llx", info->args[0]);
		return;
	}

	// set_robust_list
	if (is_64 && num == 273) {
		printf("%#llx, %llu", info->args[0], info->args[1]);
		return;
	}

	// prlimit64
	if (is_64 && num == 302) {
		if (info->args[0] == 0) {
			printf("0");
		} else {
			printf("%d", (int)info->args[0]);
		}
		printf(", %#llx, %#llx, %#llx", info->args[1], info->args[2], info->args[3]);
		return;
	}

	// getrandom
	if (is_64 && num == 318) {
		printf("%#llx, %llu, %#llx", info->args[0], info->args[1], info->args[2]);
		return;
	}

	// rseq
	if (is_64 && num == 334) {
		printf("%#llx, %#llx, %#llx, %#llx",
			info->args[0], info->args[1], info->args[2], info->args[3]);
		return;
	}

	// Affichage par défaut
	for (i = 0; i < info->arg_count; i++) {
		if (i > 0)
			printf(", ");

		if (info->args[i] == 0) {
			printf("NULL");
		} else {
			printf("%#llx", info->args[i]);
		}
	}
}

void print_syscall_enter(t_syscall_info *info, pid_t pid)
{
	if (info->name == NULL) {
		printf("syscall_%ld(", info->number);
	} else {
		printf("%s(", info->name);
	}

	print_syscall_args(info, pid);

	fflush(stdout);
}

void print_syscall_exit(t_syscall_info *info)
{
	printf(") = ");

	if (info->ret_val < 0 && info->ret_val >= -4095) {
		printf("%lld %s", info->ret_val, strerror((int)-info->ret_val));
	} else if (info->ret_val == 0) {
		printf("0");
	} else {
		long num = info->number;
		int is_64 = info->is_64bit;

		// Syscalls qui retournent des file descriptors (afficher en décimal)
		if ((is_64 && (num == 2 || num == 3 || num == 257)) ||   // open, close, openat
			(!is_64 && (num == 5 || num == 6 || num == 295))) {  // open, close, openat
			printf("%lld", info->ret_val);
		}
		// Syscalls qui retournent des tailles (read, write)
		else if ((is_64 && (num == 0 || num == 1)) ||
				(!is_64 && (num == 3 || num == 4))) {
			printf("%lld", info->ret_val);
		}
		// Par défaut en hexa
		else {
			printf("%#lx", (unsigned long)info->ret_val);
		}
	}

	printf("\n");
}
