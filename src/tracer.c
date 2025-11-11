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
				fprintf(stderr, "\n+++ exited with %d +++\n", WEXITSTATUS(status));
			}
			break;
		}

		if (WIFSIGNALED(status)) {
			if (!tracer->option_c) {
				fprintf(stderr, "\n+++ killed by SIG%s +++\n",
					strsignal(WTERMSIG(status)));
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
					// Entrée dans le syscall
					memset(&info, 0, sizeof(info));
					info.is_64bit = tracer->is_64bit;
					get_syscall_info(tracer, &info);
					gettimeofday(&info.start_time, NULL);

					if (!tracer->option_c) {
						print_syscall_enter(&info, tracer->child_pid);
					}

					tracer->current_syscall = info;
					tracer->in_syscall = 1;
				} else {
					// Sortie du syscall
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
			} else if (sig == SIGTRAP) {
				// SIGTRAP normal
			} else {
				// Autre signal
				if (!tracer->option_c) {
					print_signal(tracer->child_pid, sig);
				}
				if (ptrace(PTRACE_SYSCALL, tracer->child_pid, NULL, sig) == -1) {
					perror("ptrace SYSCALL with signal");
					break;
				}
				continue;
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
		// Processus enfant - exécuter directement
		// Le parent nous attachera avec PTRACE_SEIZE
		execve(argv[0], argv, envp);
		perror(argv[0]);
		exit(1);
	}

	// Processus parent
	// Attacher avec PTRACE_SEIZE avant que l'enfant n'appelle execve
	usleep(1000); // Petit délai pour laisser l'enfant commencer

	if (ptrace(PTRACE_SEIZE, tracer.child_pid, NULL,
	           PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SEIZE");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Interrompre le processus pour le synchroniser
	if (ptrace(PTRACE_INTERRUPT, tracer.child_pid, NULL, NULL) == -1) {
		perror("ptrace INTERRUPT");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Attendre l'arrêt
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

	// Détecter l'architecture
	tracer.is_64bit = detect_architecture(tracer.child_pid);
	if (tracer.is_64bit == -1) {
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Configurer les options de ptrace
	if (ptrace(PTRACE_SETOPTIONS, tracer.child_pid, NULL,
			   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SETOPTIONS");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Démarrer le traçage
	trace_loop(&tracer);

	// Afficher les statistiques si option -c
	if (option_c) {
		print_stats(&tracer);
		free_stats(&tracer);
	}

	if (path_resolved)
		free(path_resolved);

	return 0;
}