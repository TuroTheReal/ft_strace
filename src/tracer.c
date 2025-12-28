#include "ft_strace.h"

static t_cleanup g_cleanup = {-1, -1, NULL};

static void signal_handler(int sig)
{
	(void)sig;
	if (g_cleanup.pipe_fd != -1)
		close(g_cleanup.pipe_fd);
	if (g_cleanup.child_pid > 0)
		kill(g_cleanup.child_pid, SIGKILL);
	if (g_cleanup.path_resolved)
		free(g_cleanup.path_resolved);
	_exit(128 + sig);
}

void cleanup(char *str)
{
	if (str)
		free(str);
	g_cleanup.child_pid = -1;
	g_cleanup.pipe_fd = -1;
	g_cleanup.path_resolved = NULL;
}

int detect_architecture(pid_t pid)
{
	struct iovec iov;
	struct user_regs_struct regs;

	memset(&regs, 0, sizeof(regs));
	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);

	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
		perror("ptrace GETREGSET");
		return -1;
	}

	unsigned long cs = regs.cs & 0xFFFF;
	if (cs == 0x23)
		return 32;
	else if (cs == 0x33)
		return 64;
	return -1;
}

void trace_loop(t_tracer *tracer)
{
	int status;
	t_syscall_info info;
	struct iovec iov;
	int first_syscall = 1;

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
			if (tracer->in_syscall) {
				long num = tracer->current_syscall.number;
				int is_64 = tracer->current_syscall.is_64bit;
				if ((is_64 && num == 231) || (!is_64 && num == 252)) {
					if (!tracer->option_c) {
						printf(") = ?\n");
					}
				}
			}
			if (!tracer->option_c) {
				fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
			}
			break;
		}

		if (WIFSIGNALED(status)) {
			if (tracer->in_syscall && !tracer->option_c) {
				long num = tracer->current_syscall.number;
				int is_64 = tracer->current_syscall.is_64bit;
				if ((is_64 && num == 231) || (!is_64 && num == 252)) {
					printf(") = ?\n");
				}
			}
			if (!tracer->option_c) {
				fprintf(stderr, "+++ killed by SIG%s +++\n",
					strsignal(WTERMSIG(status)));
			}
			break;
		}

		if (WIFSTOPPED(status)) {
			int sig = WSTOPSIG(status);

			if (sig == (SIGTRAP | 0x80)) {
				iov.iov_len = sizeof(tracer->regs);
				if (ptrace(PTRACE_GETREGSET, tracer->child_pid,
						  NT_PRSTATUS, &iov) == -1) {
					perror("ptrace GETREGSET");
					continue;
				}

				// Détecter l'architecture via la taille retournée
				tracer->regs_size = iov.iov_len;
				tracer->is_64bit = (iov.iov_len == sizeof(struct user_regs_struct)) ? 1 : 0;

				if (!tracer->in_syscall) {
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

					// Afficher le message 32-bit après le premier execve UNIQUEMENT
					if (first_syscall) {
						long num = info.number;
						// Vérifier si c'est execve (59 en 64bit, 11 en 32bit)
						if (num == 59 || num == 11) {
							// C'est execve - mettre first_syscall à 0 ET afficher si 32-bit
							first_syscall = 0;
							if (!tracer->is_64bit && !tracer->option_c) {
								fflush(stdout);
								fprintf(stderr, "[ Process PID=%d runs in 32 bit mode. ]\n",
									tracer->child_pid);
							}
						}
						// Si ce n'est pas execve, on garde first_syscall=1
					}

					tracer->in_syscall = 0;
				}
			} else if (sig == SIGTRAP) {
				// SIGTRAP normal
			} else {
				if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
					if (ptrace(PTRACE_SYSCALL, tracer->child_pid, NULL, sig) == -1) {
						perror("ptrace SYSCALL with signal");
						break;
					}
					continue;
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
	int pipefd[2];

	memset(&tracer, 0, sizeof(tracer));
	tracer.option_c = option_c;

	if (argv[0][0] != '/' && argv[0][0] != '.') {
		path_resolved = find_in_path(argv[0]);
		if (path_resolved) {
			argv[0] = path_resolved;
		}
	}

	if (option_c) {
		init_stats(&tracer);
	}

	if (pipe(pipefd) == -1) {
		perror("pipe");
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	tracer.child_pid = fork();
	if (tracer.child_pid == -1) {
		perror("fork");
		if (path_resolved)
			free(path_resolved);
		close(pipefd[0]);
		close(pipefd[1]);
		return 1;
	}

	if (tracer.child_pid == 0) {
		// Enfant: attendre signal du parent puis execve
		char c;
		close(pipefd[1]);
		read(pipefd[0], &c, 1);
		close(pipefd[0]);

		execve(argv[0], argv, envp);
		perror("execve");
		_exit(127);
	}

	close(pipefd[0]);

	g_cleanup.child_pid = tracer.child_pid;
	g_cleanup.pipe_fd = pipefd[1];
	g_cleanup.path_resolved = path_resolved;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// Petit délai pour que l'enfant soit bloqué sur read()
	usleep(1000);

	// PTRACE_SEIZE avec les options
	if (ptrace(PTRACE_SEIZE, tracer.child_pid, NULL,
			   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SEIZE");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	// PTRACE_INTERRUPT pour stopper le processus (bloqué dans read)
	if (ptrace(PTRACE_INTERRUPT, tracer.child_pid, NULL, NULL) == -1) {
		perror("ptrace INTERRUPT");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	// Attendre l'interruption
	if (waitpid(tracer.child_pid, &status, 0) == -1) {
		perror("waitpid interrupt");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	// Débloquer le read() et fermer le pipe
	write(pipefd[1], "x", 1);
	close(pipefd[1]);
	g_cleanup.pipe_fd = -1;

	// Utiliser PTRACE_LISTEN pour reprendre après INTERRUPT
	// Cela permet au processus de continuer sans tracer le syscall read
	if (ptrace(PTRACE_LISTEN, tracer.child_pid, NULL, NULL) == -1) {
		perror("ptrace LISTEN");
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	// Petit délai pour laisser read() se terminer
	usleep(2000);

	// Maintenant interrompre à nouveau juste avant execve
	if (ptrace(PTRACE_INTERRUPT, tracer.child_pid, NULL, NULL) == -1) {
		perror("ptrace INTERRUPT 2");
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	// Attendre la seconde interruption
	if (waitpid(tracer.child_pid, &status, 0) == -1) {
		perror("waitpid interrupt 2");
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	trace_loop(&tracer);

	g_cleanup.child_pid = -1;
	g_cleanup.path_resolved = NULL;
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	if (option_c) {
		print_stats(&tracer);
		free_stats(&tracer);
	}

	if (path_resolved)
		free(path_resolved);

	return 0;
}