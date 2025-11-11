#include "ft_strace.h"

void print_usage(void)
{
	fprintf(stderr, "Usage: ft_strace command [args...]\n");
	fprintf(stderr, "Example: ./ft_strace /bin/ls -la\n");
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		print_usage();
		return 1;
	}

	return start_trace(argv + 1, envp);
}