#include "ft_strace.h"

int detect_architecture(pid_t pid)
{
	struct iovec iov;
	struct user_regs_struct regs;

	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);

	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
		perror("ptrace GETREGSET");
		return -1;
	}

	return (iov.iov_len == sizeof(struct user_regs_struct)) ? 1 : 0;
}

void trace_loop(t_tracer *tracer)
{
	int status;
	t_syscall_info info;
	struct iovec iov;

	iov.iov_base = &tracer->regs;
	iov.iov_len = sizeof(tracer->regs);

	while (1) {
		if (ptrace(PTRACE_SYSCALL, tracer->child_pid, NULL, NULL) == -1) {
			perror("ptrace SYSCALL");
			break;
		}

		if (waitpid(tracer->child_pid, &status, 0) == -1) {
			perror("waitpid");
			break;
		}

		if (WIFEXITED(status)) {
			if (!tracer->option_c) {
				fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
			}
			break;
		}

		if (WIFSIGNALED(status)) {
			if (!tracer->option_c) {
				fprintf(stderr, "+++ killed by signal %d +++\n", WTERMSIG(status));
			}
			break;
		}

		if (WIFSTOPPED(status)) {
			int sig = WSTOPSIG(status);

			if (sig == (SIGTRAP | 0x80)) {
				if (ptrace(PTRACE_GETREGSET, tracer->child_pid,
						  NT_PRSTATUS, &iov) == -1) {
					perror("ptrace GETREGSET");
					continue;
				}

				if (!tracer->in_syscall) {
					// ENTRÉE du syscall
					memset(&info, 0, sizeof(info));
					info.is_64bit = tracer->is_64bit;
					get_syscall_info(tracer, &info);

					// Enregistrer le temps de début
					gettimeofday(&info.start_time, NULL);

					if (!tracer->option_c) {
						print_syscall_enter(&info);
					}

					// Sauvegarder pour option -c
					tracer->current_syscall = info;
					tracer->in_syscall = 1;
				} else {
					// SORTIE du syscall
					memset(&info, 0, sizeof(info));
					info.is_64bit = tracer->is_64bit;
					info.number = tracer->current_syscall.number;
					info.name = tracer->current_syscall.name;
					info.start_time = tracer->current_syscall.start_time;

					get_syscall_retval(tracer, &info);

					// Enregistrer le temps de fin
					gettimeofday(&info.end_time, NULL);

					if (!tracer->option_c) {
						print_syscall_exit(&info);
					} else {
						update_stats(tracer, &info);
					}

					tracer->in_syscall = 0;
				}
			} else {
				// Signal réel
				if (!tracer->option_c) {
					print_signal(tracer->child_pid, sig);
				}
			}
		}
	}
}

int start_trace(char **argv, char **envp, int option_c)
{
	t_tracer tracer;
	int status;
	char *path_resolved = NULL;

	memset(&tracer, 0, sizeof(tracer));
	tracer.option_c = option_c;

	// Gestion du PATH (bonus)
	if (argv[0][0] != '/' && argv[0][0] != '.') {
		path_resolved = find_in_path(argv[0]);
		if (path_resolved) {
			argv[0] = path_resolved;
		}
	}

	// Initialiser les stats pour option -c
	if (option_c) {
		init_stats(&tracer);
	}

	tracer.child_pid = fork();
	if (tracer.child_pid == -1) {
		perror("fork");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	if (tracer.child_pid == 0) {
		// PROCESSUS ENFANT
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("ptrace TRACEME");
			exit(1);
		}
		execve(argv[0], argv, envp);
		perror(argv[0]);
		exit(1);
	}

	// PROCESSUS PARENT
	if (waitpid(tracer.child_pid, &status, 0) == -1) {
		perror("waitpid");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "Child not stopped\n");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	tracer.is_64bit = detect_architecture(tracer.child_pid);
	if (tracer.is_64bit == -1) {
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	if (ptrace(PTRACE_SETOPTIONS, tracer.child_pid, NULL,
			   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SETOPTIONS");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	trace_loop(&tracer);

	// Afficher les stats pour option -c
	if (option_c) {
		print_stats(&tracer);
		free_stats(&tracer);
	}

	if (path_resolved)
		free(path_resolved);

	return 0;
}