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
			// Si on était dans exit_group, fermer la parenthèse
			if (tracer->in_syscall) {
				long num = tracer->current_syscall.number;
				int is_64 = tracer->current_syscall.is_64bit;
				if ((is_64 && num == 231) || (!is_64 && num == 252)) {
					printf(") = ?\n");
				}
			}
			if (!tracer->option_c) {
				fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
			}
			break;
		}

		if (WIFSIGNALED(status)) {
			// Si on était dans exit_group, fermer la parenthèse
			if (tracer->in_syscall) {
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
				// SIGTRAP normal - continuer sans relayer le signal
			} else {
				// Autre signal - le relayer au processus tracé
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
	int pipefd[2];

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

	// Créer un pipe pour synchroniser parent et enfant
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
		// Processus enfant
		char dummy;

		close(pipefd[1]); // Fermer le côté écriture

		// Attendre que le parent soit prêt (bloque sur read)
		read(pipefd[0], &dummy, 1);
		close(pipefd[0]);

		// Maintenant execve
		execve(argv[0], argv, envp);
		// Si on arrive ici, execve a échoué
		_exit(127);
	}

	// Processus parent
	close(pipefd[0]); // Fermer le côté lecture

	// Attacher avec PTRACE_SEIZE AVANT que l'enfant n'appelle execve
	if (ptrace(PTRACE_SEIZE, tracer.child_pid, NULL,
	           PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SEIZE");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Interrompre le processus pour le synchroniser
	if (ptrace(PTRACE_INTERRUPT, tracer.child_pid, NULL, NULL) == -1) {
		perror("ptrace INTERRUPT");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Attendre l'arrêt
	if (waitpid(tracer.child_pid, &status, 0) == -1) {
		perror("waitpid");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "Child not stopped\n");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Détecter l'architecture
	tracer.is_64bit = detect_architecture(tracer.child_pid);
	if (tracer.is_64bit == -1) {
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Configurer les options de ptrace
	if (ptrace(PTRACE_SETOPTIONS, tracer.child_pid, NULL,
			   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SETOPTIONS");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		if (path_resolved)
			free(path_resolved);
		return 1;
	}

	// Débloquer l'enfant pour qu'il puisse faire execve
	write(pipefd[1], "X", 1);
	close(pipefd[1]);

	// ============================================================
	// NOUVEAU : Skip tous les syscalls jusqu'à la SORTIE d'execve
	// ============================================================
	int seen_execve_exit = 0;
	struct iovec iov;
	iov.iov_base = &tracer.regs;
	iov.iov_len = sizeof(tracer.regs);

	while (!seen_execve_exit) {
		if (ptrace(PTRACE_SYSCALL, tracer.child_pid, NULL, NULL) == -1) {
			perror("ptrace SYSCALL in skip loop");
			kill(tracer.child_pid, SIGKILL);
			if (path_resolved)
				free(path_resolved);
			return 1;
		}

		if (waitpid(tracer.child_pid, &status, 0) == -1) {
			perror("waitpid in skip loop");
			kill(tracer.child_pid, SIGKILL);
			if (path_resolved)
				free(path_resolved);
			return 1;
		}

		// Si le processus s'est terminé avant execve (erreur)
		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			if (path_resolved)
				free(path_resolved);
			return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
		}

		if (WIFSTOPPED(status)) {
			int sig = WSTOPSIG(status);

			if (sig == (SIGTRAP | 0x80)) {
				// C'est un syscall-stop
				if (ptrace(PTRACE_GETREGSET, tracer.child_pid,
						  NT_PRSTATUS, &iov) == -1) {
					perror("ptrace GETREGSET in skip loop");
					continue;
				}

				// Récupérer le numéro de syscall
				long syscall_num = tracer.is_64bit ?
					tracer.regs.orig_rax :
					(tracer.regs.orig_rax & 0xFFFFFFFF);

				// Vérifier si c'est execve
				// 59 = execve (64-bit), 11 = execve (32-bit)
				int is_execve = (tracer.is_64bit && syscall_num == 59) ||
				                (!tracer.is_64bit && syscall_num == 11);

				if (is_execve) {
					if (!tracer.in_syscall) {
						// Entrée dans execve - on note et on continue
						tracer.in_syscall = 1;
					} else {
						// Sortie d'execve - on commence le vrai traçage
						tracer.in_syscall = 0;
						seen_execve_exit = 1;
					}
				}
			} else if (sig != SIGTRAP) {
				// Autre signal pendant le skip - le relayer
				if (ptrace(PTRACE_SYSCALL, tracer.child_pid, NULL, sig) == -1) {
					perror("ptrace SYSCALL with signal in skip");
					kill(tracer.child_pid, SIGKILL);
					if (path_resolved)
						free(path_resolved);
					return 1;
				}
				continue;
			}
		}
	}

	// Maintenant on démarre le vrai traçage (après execve)
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