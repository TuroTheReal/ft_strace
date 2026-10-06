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

// Retourne le code de sortie à propager (comme strace)
int trace_loop(t_tracer *tracer)
{
	int status;
	t_syscall_info info;
	struct iovec iov;
	int first_syscall = 1;
	int started = 0;        // Rien n'est affiché avant l'entrée du premier execve
	int sig_to_inject = 0;  // Signal à livrer au tracee au prochain redémarrage
	int listening = 0;      // Tracee en group-stop: attendre sans le relancer
	int exit_code = 1;

	iov.iov_base = &tracer->regs;
	iov.iov_len = sizeof(tracer->regs);

	while (1) {
		// Un seul redémarrage par arrêt: le signal en attente part avec lui
		// ESRCH = tracee mort entre-temps, waitpid donnera la raison
		if (!listening && ptrace(PTRACE_SYSCALL, tracer->child_pid, NULL,
				(void *)(long)sig_to_inject) == -1 && errno != ESRCH) {
			perror("ptrace SYSCALL");
			break;
		}
		sig_to_inject = 0;
		listening = 0;

		if (waitpid(tracer->child_pid, &status, 0) == -1) {
			perror("waitpid");
			break;
		}

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			// Syscall en cours sans retour (exit_group, SIGKILL...)
			if (tracer->in_syscall && started) {
				if (!tracer->option_c) {
					print_syscall_unfinished();
				} else {
					// strace -c compte aussi exit_group
					gettimeofday(&tracer->current_syscall.end_time, NULL);
					update_stats(tracer, &tracer->current_syscall);
				}
			}
			if (WIFEXITED(status)) {
				exit_code = WEXITSTATUS(status);
				if (!tracer->option_c)
					fprintf(stderr, "+++ exited with %d +++\n", exit_code);
			} else {
				// 128 + sig comme un shell, sans se tuer soi-même (pas de faux crash)
				exit_code = 128 + WTERMSIG(status);
				if (!tracer->option_c)
					fprintf(stderr, "+++ killed by %s%s +++\n",
						signal_name(WTERMSIG(status)),
						WCOREDUMP(status) ? " (core dumped)" : "");
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

				// Avant execve, la boucle a pu démarrer au milieu d'un syscall (read du pipe):
				// à l'entrée, le kernel met -ENOSYS dans rax, ce qui dit si c'est une entrée
				if (!started) {
					long long rax = tracer->is_64bit ? (long long)tracer->regs.regs_64.rax
						: (long long)(int)tracer->regs.regs_32.eax;
					tracer->in_syscall = (rax != -ENOSYS);
				}

				if (!tracer->in_syscall) {
					memset(&info, 0, sizeof(info));
					info.is_64bit = tracer->is_64bit;
					get_syscall_info(tracer, &info);
					gettimeofday(&info.start_time, NULL);

					// L'enfant est un fork de ft_strace (64 bit): execve = 59
					if (!started && info.is_64bit && info.number == 59)
						started = 1;
					if (started && !tracer->option_c) {
						print_syscall_enter(&info, tracer->child_pid);
					}

					tracer->current_syscall = info;
					tracer->in_syscall = 1;
				} else {
					// On garde les arguments d'entrée: certains s'affichent à la sortie
					info = tracer->current_syscall;
					info.is_64bit = tracer->is_64bit;

					get_syscall_retval(tracer, &info);
					gettimeofday(&info.end_time, NULL);

					// Syscalls de synchro (read/close du pipe) avant execve: masqués
					if (started) {
						// Afficher normalement
						if (!tracer->option_c) {
							print_syscall_exit(&info, tracer->child_pid);
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
									fprintf(stderr, "[ Process PID=%d runs in 32 bit mode. ]\n",
										tracer->child_pid);
								}
							}
							// Si ce n'est pas execve, on garde first_syscall=1
						}
					}

					tracer->in_syscall = 0;
				}
			} else if ((status >> 16) == PTRACE_EVENT_STOP) {
				// Arrêt propre à SEIZE: group-stop ou PTRACE_INTERRUPT
				if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
					if (!tracer->option_c)
						fprintf(stderr, "--- stopped by %s ---\n", signal_name(sig));
					// LISTEN: reste arrêté, on sera notifié au SIGCONT
					if (ptrace(PTRACE_LISTEN, tracer->child_pid, NULL, NULL) == -1) {
						perror("ptrace LISTEN");
						break;
					}
					listening = 1;
				}
				// Sinon (SIGTRAP d'un INTERRUPT): simple relance
			} else {
				// Signal-delivery-stop: afficher, puis livrer au prochain PTRACE_SYSCALL
				if (!tracer->option_c)
					print_signal(tracer->child_pid, sig);
				sig_to_inject = sig;
			}
		}
	}
	return exit_code;
}

int start_trace(char **argv, char **envp, int option_c)
{
	t_tracer tracer;
	int status;
	char *path_resolved = NULL;
	int pipefd[2];

	memset(&tracer, 0, sizeof(tracer));
	tracer.option_c = option_c;

	// Comme strace (et execvp): recherche dans le PATH seulement si pas de '/'
	if (!strchr(argv[0], '/')) {
		path_resolved = find_in_path(argv[0]);
		if (!path_resolved) {
			fprintf(stderr, "ft_strace: Cannot find executable '%s'\n", argv[0]);
			return 1;
		}
	} else {
		struct stat st;

		if (stat(argv[0], &st) == -1) {
			fprintf(stderr, "ft_strace: Cannot stat '%s': %s\n", argv[0], strerror(errno));
			return 1;
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

		// argv[0] reste tel que tapé (comme strace), seul le chemin exécuté change
		execve(path_resolved ? path_resolved : argv[0], argv, envp);
		perror("execve");
		_exit(127);
	}

	close(pipefd[0]);

	g_cleanup.child_pid = tracer.child_pid;
	g_cleanup.pipe_fd = pipefd[1];
	g_cleanup.path_resolved = path_resolved;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// L'enfant est bloqué sur read() du pipe tant qu'on n'écrit pas:
	// il ne peut pas faire execve avant d'être tracé, sans aucune hypothèse de timing
	// PTRACE_SEIZE avec les options
	if (ptrace(PTRACE_SEIZE, tracer.child_pid, NULL,
			   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SEIZE");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	// PTRACE_INTERRUPT: le tracee doit être arrêté pour accepter PTRACE_SYSCALL
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

	// Débloquer le read() et fermer le pipe, la boucle prend le relais
	write(pipefd[1], "x", 1);
	close(pipefd[1]);
	g_cleanup.pipe_fd = -1;

	int exit_code = trace_loop(&tracer);

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

	return exit_code;
}