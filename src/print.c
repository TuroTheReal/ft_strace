#include "ft_strace.h"

// Format: nom_syscall(arg1, arg2, arg3
void print_syscall_enter(t_syscall_info *info)
{
	int i;

	// Si pas le nom, "syscall_XXX"
	if (info->name == NULL) {
		printf("syscall_%ld(", info->number);
	} else {
		printf("%s(", info->name);
	}

	for (i = 0; i < 6; i++) {
		if (i > 0)
			printf(", ");
		printf("%#lx", info->args[i]);
	}

	fflush(stdout);
}

// Format: ) = valeur_retour
void print_syscall_exit(t_syscall_info *info)
{
	// Compléter la ligne de print_syscall_enter
	printf(") = ");

	// Si < 0, errno
	if (info->ret_val < 0 && info->ret_val >= -4095) {
		// Convention Linux : les erreurs sont entre -1 et -4095 == -1
		printf("-1 (errno %ld)", -info->ret_val);
	} else {
		printf("%ld", info->ret_val);
	}

	printf("\n");
}

void print_signal(pid_t pid, int sig)
{
	siginfo_t si;

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &si) == 0) {
		printf("--- %s {si_signo=%d, si_code=%d} ---\n",
			strsignal(sig), si.si_signo, si.si_code);
	} else {
		printf("--- %s ---\n", strsignal(sig));
	}
}
