#include "ft_strace.h"

void print_usage(void)
{
	fprintf(stderr, "Usage: ft_strace [-c] command [args...]\n");
	fprintf(stderr, "  -c    Count time, calls, and errors for each syscall\n");
	fprintf(stderr, "Example: ./ft_strace /bin/ls -la\n");
	fprintf(stderr, "Example: ./ft_strace -c /bin/ls\n");
}

int main(int argc, char **argv, char **envp)
{
	int option_c = 0;
	int arg_offset = 1;

	if (argc < 2) {
		print_usage();
		return 1;
	}

	// Parse option -c
	if (strcmp(argv[1], "-c") == 0) {
		option_c = 1;
		arg_offset = 2;
		if (argc < 3) {
			print_usage();
			return 1;
		}
	}

	return start_trace(argv + arg_offset, envp, option_c);
}