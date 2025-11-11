#include "ft_strace.h"

void print_syscall_enter(t_syscall_info *info)
{
	int i;

	if (info->name == NULL) {
		printf("syscall_%ld(", info->number);
	} else {
		printf("%s(", info->name);
	}

	for (i = 0; i < 6; i++) {
		if (i > 0)
			printf(", ");
		printf("%#llx", info->args[i]);
	}

	fflush(stdout);
}

void print_syscall_exit(t_syscall_info *info)
{
	printf(") = ");

	if (info->ret_val < 0 && info->ret_val >= -4095) {
		printf("-1 (errno %lld)", -info->ret_val);
	} else {
		printf("%lld", info->ret_val);
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