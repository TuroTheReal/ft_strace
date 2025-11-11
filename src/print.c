#include "ft_strace.h"

void print_syscall_enter(t_syscall_info *info)
{
	int i;

	if (info->name == NULL) {
		printf("syscall_%ld(", info->number);
	} else {
		printf("%s(", info->name);
	}

	// N'afficher que le nombre d'arguments réels
	for (i = 0; i < info->arg_count; i++) {
		if (i > 0)
			printf(", ");

		// Afficher NULL pour les pointeurs null
		if (info->args[i] == 0) {
			printf("NULL");
		} else {
			printf("%#llx", info->args[i]);
		}
	}

	fflush(stdout);
}

void print_syscall_exit(t_syscall_info *info)
{
	printf(") = ");

	if (info->ret_val < 0 && info->ret_val >= -4095) {
		printf("-1 (errno %lld)", -info->ret_val);
	} else {
		printf("%#lx", (unsigned long)info->ret_val);
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
