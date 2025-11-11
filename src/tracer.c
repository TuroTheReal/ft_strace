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
					memset(&info, 0, sizeof(info));
					info.is_64bit = tracer->is_64bit;
					get_syscall_info(tracer, &info);
					gettimeofday(&info.start_time, NULL);

					if (!tracer->option_c) {
						print_syscall_enter(&info);
					}

					tracer->current_syscall = info;
					tracer->in_syscall = 1;
				} else {
					memset(&info, 0, sizeof(info));
					info.is_64bit = tracer->is_64bit;
					info.number = tracer->current_syscall.number;
					info.name = tracer->current_syscall.name;
					info.start_time = tracer->current_syscall.start_time;
					info.arg_count = tracer->current_syscall.arg_count;

					get_syscall_retval(tracer, &info);
					gettimeofday(&info.end_time, NULL);

					if (!tracer->option_c) {
						print_syscall_exit(&info);
					} else {
						update_stats(tracer, &info);
					}

					tracer->in_syscall = 0;
				}
			} else {
				// Autre signal que SIGTRAP|0x80
				if (!tracer->option_c) {
					print_signal(tracer->child_pid, sig);
				}
			}
		}
	}
}

static int count_env_vars(char **envp)
{
	int count = 0;
	while (envp && envp[count])
		count++;
	return count;
}

int start_trace(char **argv, char **envp, int option_c)
{
	t_tracer tracer;
	int status;
	char *path_resolved = NULL;
	pid_t pid;

	memset(&tracer, 0, sizeof(tracer));
	tracer.option_c = option_c;

	// Résolution du PATH (bonus)
	if (argv[0][0] != '/' && argv[0][0] != '.') {
		path_resolved = find_in_path(argv[0]);
		if (path_resolved) {
			argv[0] = path_resolved;
		}
	}

	if (option_c) {
		init_stats(&tracer);
	}

	pid = fork();
	if (pid == -1) {
		perror("fork");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	if (pid == 0) {
		// CHILD : raise(SIGSTOP) pour permettre au parent de s'attacher
		raise(SIGSTOP);
		execve(argv[0], argv, envp);
		perror(argv[0]);
		exit(1);
	}

	// PARENT
	tracer.child_pid = pid;

	// Attendre que le child soit arrêté par SIGSTOP
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
		fprintf(stderr, "Child not stopped by SIGSTOP\n");
		kill(pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// PTRACE_SEIZE : S'attacher au processus
	if (ptrace(PTRACE_SEIZE, pid, NULL,
	           PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SEIZE");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// PTRACE_INTERRUPT : Interrompre le processus (déjà arrêté, mais nécessaire après SEIZE)
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1) {
		perror("ptrace INTERRUPT");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Attendre l'arrêt suite à INTERRUPT
	if (waitpid(pid, &status, 0) == -1) {
		perror("waitpid after INTERRUPT");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Détecter l'architecture
	tracer.is_64bit = detect_architecture(pid);
	if (tracer.is_64bit == -1) {
		kill(pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// PTRACE_SETOPTIONS : Options de traçage
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL,
	           PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SETOPTIONS");
		kill(pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Afficher execve AVANT la boucle (le processus n'a pas encore exécuté execve)
	if (!option_c) {
		printf("execve(\"%s\", [", argv[0]);
		for (int i = 0; argv[i]; i++) {
			if (i > 0) printf(", ");
			printf("\"%s\"", argv[i]);
		}
		printf("], %p /* %d vars */) = 0\n",
		       (void*)envp, count_env_vars(envp));
	}

	// Relancer le processus avec PTRACE_LISTEN (après SEIZE/INTERRUPT)
	if (ptrace(PTRACE_LISTEN, pid, NULL, NULL) == -1) {
		perror("ptrace LISTEN");
		kill(pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Lancer la boucle de traçage
	trace_loop(&tracer);

	if (option_c) {
		print_stats(&tracer);
		free_stats(&tracer);
	}

	if (path_resolved)
		free(path_resolved);

	return 0;
}