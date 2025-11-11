#include "ft_strace.h"

// Lire une chaîne depuis le processus tracé
static void print_string_arg(pid_t pid, unsigned long long addr, int max_len)
{
	char buffer[256];
	int i;
	long data;

	// FIX: Initialiser le buffer pour éviter les valeurs non initialisées
	memset(buffer, 0, sizeof(buffer));

	if (addr == 0) {
		printf("NULL");
		return;
	}

	printf("\"");
	for (i = 0; i < max_len && i < 255; i += sizeof(long)) {
		errno = 0;
		data = ptrace(PTRACE_PEEKDATA, pid, addr + i, NULL);
		if (errno != 0) {
			printf("...");
			break;
		}

		// Copier les octets du long dans le buffer
		memcpy(buffer + i, &data, sizeof(long));

		// Vérifier s'il y a un null byte
		int j;
		for (j = 0; j < (int)sizeof(long) && i + j < 255; j++) {
			if (buffer[i + j] == '\0') {
				buffer[i + j] = '\0';
				i = max_len; // Sortir de la boucle externe
				break;
			}
		}
	}
	buffer[255] = '\0';

	// Afficher la chaîne avec échappement
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

	// Syscalls avec des arguments spécifiques à formater
	if ((is_64 && num == 0) || (!is_64 && num == 3)) { // read
		printf("%d, ", (int)info->args[0]);
		printf("%#llx, ", info->args[1]);
		printf("%llu", info->args[2]);
		return;
	}

	if ((is_64 && num == 1) || (!is_64 && num == 4)) { // write
		printf("%d, ", (int)info->args[0]);
		printf("%#llx, ", info->args[1]);
		printf("%llu", info->args[2]);
		return;
	}

	if ((is_64 && num == 2) || (!is_64 && num == 5)) { // open
		print_string_arg(pid, info->args[0], 32);
		printf(", ");
		// Flags
		unsigned long flags = info->args[1];
		if (flags & 0x40) printf("O_CREAT|");
		if (flags & 0x200) printf("O_DIRECTORY|");
		if (flags & 0x80000) printf("O_CLOEXEC|");
		if ((flags & 0x3) == 0) printf("O_RDONLY");
		else if ((flags & 0x3) == 1) printf("O_WRONLY");
		else if ((flags & 0x3) == 2) printf("O_RDWR");
		return;
	}

	if ((is_64 && num == 21) || (!is_64 && num == 33)) { // access
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

	if (is_64 && num == 257) { // openat
		printf("%d, ", (int)(long)info->args[0]);
		print_string_arg(pid, info->args[1], 32);
		printf(", ");
		// Flags
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

	if ((is_64 && num == 59) || (!is_64 && num == 11)) { // execve
		print_string_arg(pid, info->args[0], 32);
		printf(", ");
		// Pour argv et envp, on pourrait les lire mais c'est complexe
		// On affiche juste les adresses
		printf("%#llx, %#llx", info->args[1], info->args[2]);
		return;
	}

	if (is_64 && num == 262) { // newfstatat
		printf("%d, ", (int)(long)info->args[0]);
		print_string_arg(pid, info->args[1], 32);
		printf(", %#llx, ", info->args[2]);
		// Flags
		if (info->args[3] == 0x1000) {
			printf("AT_EMPTY_PATH");
		} else if (info->args[3] == 0) {
			printf("0");
		} else {
			printf("%#llx", info->args[3]);
		}
		return;
	}

	if ((is_64 && num == 9)) { // mmap
		if (info->args[0] == 0) {
			printf("NULL");
		} else {
			printf("%#llx", info->args[0]);
		}
		printf(", %#llx, ", info->args[1]);
		// Prot flags
		unsigned long prot = info->args[2];
		if (prot == 0) printf("PROT_NONE");
		else {
			int first = 1;
			if (prot & 0x1) { printf("PROT_READ"); first = 0; }
			if (prot & 0x2) { if (!first) printf("|"); printf("PROT_WRITE"); first = 0; }
			if (prot & 0x4) { if (!first) printf("|"); printf("PROT_EXEC"); }
		}
		printf(", ");
		// Map flags
		unsigned long flags = info->args[3];
		int first = 1;
		if (flags & 0x01) { printf("MAP_SHARED"); first = 0; }
		if (flags & 0x02) { if (!first) printf("|"); printf("MAP_PRIVATE"); first = 0; }
		if (flags & 0x20) { if (!first) printf("|"); printf("MAP_ANONYMOUS"); }
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

	if ((is_64 && num == 10)) { // mprotect
		printf("%#llx, %#llx, ", info->args[0], info->args[1]);
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

	if (is_64 && num == 16) { // ioctl
		printf("%d, ", (int)info->args[0]);
		// Commandes ioctl courantes
		unsigned long cmd = info->args[1];
		if (cmd == 0x5401) printf("TCGETS");
		else if (cmd == 0x5413) printf("TIOCGWINSZ");
		else printf("%#lx", cmd);
		if (info->arg_count > 2) {
			printf(", %#llx", info->args[2]);
		}
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
	long num = info->number;
	int is_64 = info->is_64bit;

	printf(") = ");

	if (info->ret_val < 0 && info->ret_val >= -4095) {
		printf("%lld %s", info->ret_val, strerror((int)-info->ret_val));
	} else if (info->ret_val == 0) {
		printf("0");
	} else {
		// Syscalls qui retournent des valeurs décimales
		if ((is_64 && (num == 0 || num == 1 || num == 3)) ||  // read, write, close
		    (!is_64 && (num == 3 || num == 4 || num == 6))) { // read, write, close (32-bit)
			printf("%lld", info->ret_val);
		} else {
			printf("%#lx", (unsigned long)info->ret_val);
		}
	}

	printf("\n");
}

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