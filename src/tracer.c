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

	// Méthode fiable: CS (Code Segment)
	// 0x23 = 32-bit, 0x33 = 64-bit
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
				// Réinitialiser iov_len avant chaque appel
				iov.iov_len = sizeof(tracer->regs);

				if (ptrace(PTRACE_GETREGSET, tracer->child_pid,
						  NT_PRSTATUS, &iov) == -1) {
					perror("ptrace GETREGSET");
					continue;
				}

				if (!tracer->in_syscall) {
					// Détecter l'architecture : en 32-bit, orig_rax contient le syscall dans les bits bas
					// et souvent une valeur spécifique dans les bits hauts
					// La méthode la plus fiable : vérifier si orig_rax > 0xFFFFFFFF
					// Si oui, c'est probablement un syscall 32-bit (avec __X32_SYSCALL_BIT)
					long long orig = tracer->regs.orig_rax;
					long syscall_num = orig & 0xFFFFFFFF;

					// Les syscalls 32-bit ont souvent orig_rax avec les bits hauts != 0
					// ou on peut utiliser CS: 0x23 = 32-bit, 0x33 = 64-bit
					unsigned long cs = tracer->regs.cs & 0xFFFF;

					// Détection combinée
					if (cs == 0x23) {
						tracer->is_64bit = 0;  // Clairement 32-bit
					} else if (cs == 0x33 && syscall_num <= 547) {  // 547 = dernier syscall 64-bit courant
						tracer->is_64bit = 1;  // Probablement 64-bit
					} else {
						tracer->is_64bit = 1;  // Par défaut 64-bit
					}

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

					tracer->in_syscall = 0;
				}
			} else if (sig == SIGTRAP) {
				// SIGTRAP normal - ne rien faire, continuer le tracing
			} else {
				// Signal reçu par le tracé
				// Vérifier si c'est un signal qui devrait arrêter le processus
				if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
					// Signaux de stop - les relayer
					if (ptrace(PTRACE_SYSCALL, tracer->child_pid, NULL, sig) == -1) {
						perror("ptrace SYSCALL with signal");
						break;
					}
					continue;
				}
				// Pour les autres signaux, les relayer sans les afficher
				// (sauf si le sujet demande de les afficher)
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
		// Child process
		close(pipefd[1]);
		close(pipefd[0]);

		// Se mettre en mode tracé AVANT l'execve
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("ptrace TRACEME");
			_exit(127);
		}

		// Envoyer SIGSTOP à soi-même pour que le parent puisse nous setup
		raise(SIGSTOP);

		// Exécuter le programme cible
		execve(argv[0], argv, envp);
		perror("execve");
		_exit(127);
	}

	// Parent process
	close(pipefd[0]);

	g_cleanup.child_pid = tracer.child_pid;
	g_cleanup.pipe_fd = pipefd[1];
	g_cleanup.path_resolved = path_resolved;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// Attendre que l'enfant s'arrête (via raise(SIGSTOP))
	if (waitpid(tracer.child_pid, &status, 0) == -1) {
		perror("waitpid");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	if (!WIFSTOPPED(status)) {
		fprintf(stderr, "Child not stopped\n");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	// Configurer les options de tracing
	if (ptrace(PTRACE_SETOPTIONS, tracer.child_pid, NULL,
			   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SETOPTIONS");
		close(pipefd[1]);
		kill(tracer.child_pid, SIGKILL);
		cleanup(path_resolved);
		return 1;
	}

	// Fermer le pipe (non utilisé avec PTRACE_TRACEME)
	close(pipefd[1]);
	g_cleanup.pipe_fd = -1;

	// Attendre et afficher l'execve initial
	int execve_success = 0;
	struct iovec iov;
	iov.iov_base = &tracer.regs;
	iov.iov_len = sizeof(tracer.regs);
	t_syscall_info execve_info;

	while (!execve_success) {
		if (ptrace(PTRACE_SYSCALL, tracer.child_pid, NULL, NULL) == -1) {
			perror("ptrace SYSCALL in skip");
			kill(tracer.child_pid, SIGKILL);
			cleanup(path_resolved);
			return 1;
		}

		if (waitpid(tracer.child_pid, &status, 0) == -1) {
			perror("waitpid in skip");
			kill(tracer.child_pid, SIGKILL);
			cleanup(path_resolved);
			return 1;
		}

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			cleanup(path_resolved);
			return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
		}

		if (WIFSTOPPED(status)) {
			int sig = WSTOPSIG(status);

			if (sig == (SIGTRAP | 0x80)) {
				// Syscall-stop
				memset(&tracer.regs, 0, sizeof(tracer.regs));
				if (ptrace(PTRACE_GETREGSET, tracer.child_pid,
						NT_PRSTATUS, &iov) == -1) {
					perror("ptrace GETREGSET in skip");
					continue;
				}

				// Lire le numéro de syscall
				long syscall_num = tracer.regs.orig_rax & 0xFFFFFFFF;

				// Vérifier si c'est execve (syscall 59 en 64-bit, 11 en 32-bit)
				if (syscall_num == 59 || syscall_num == 11) {
					// Avant l'execve, le processus est toujours 64-bit (fork du parent)
					// C'est l'entrée dans execve - afficher si pas en mode -c
					if (!option_c) {
						memset(&execve_info, 0, sizeof(execve_info));
						execve_info.is_64bit = 1; // Toujours 64-bit avant l'execve
						execve_info.number = syscall_num;
						execve_info.name = "execve";
						execve_info.args[0] = tracer.regs.rdi;
						execve_info.args[1] = tracer.regs.rsi;
						execve_info.args[2] = tracer.regs.rdx;
						execve_info.arg_count = 3;
						print_syscall_enter(&execve_info, tracer.child_pid);
					}

					// Attendre la sortie d'execve
					if (ptrace(PTRACE_SYSCALL, tracer.child_pid, NULL, NULL) == -1) {
						kill(tracer.child_pid, SIGKILL);
						cleanup(path_resolved);
						return 1;
					}

					if (waitpid(tracer.child_pid, &status, 0) == -1) {
						kill(tracer.child_pid, SIGKILL);
						cleanup(path_resolved);
						return 1;
					}

					if (WIFEXITED(status) || WIFSIGNALED(status)) {
						cleanup(path_resolved);
						return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
					}

					// Lire les registres à la sortie d'execve
					if (ptrace(PTRACE_GETREGSET, tracer.child_pid,
							NT_PRSTATUS, &iov) == -1) {
						perror("ptrace GETREGSET after execve");
						kill(tracer.child_pid, SIGKILL);
						cleanup(path_resolved);
						return 1;
					}

					// Afficher l'execve avec succès (= 0)
					// Note: pour les programmes 32-bit, le kernel peut retourner ENOSYS
					// mais le programme s'exécute quand même, donc on affiche = 0
					if (!option_c) {
						execve_info.ret_val = 0;
						print_syscall_exit(&execve_info);
					}

					// Sortir de la boucle - l'execve est fait
					execve_success = 1;
				}
			} else if (sig != SIGTRAP) {
				// Relayer les signaux sans les afficher
				if (ptrace(PTRACE_SYSCALL, tracer.child_pid, NULL, sig) == -1) {
					perror("ptrace SYSCALL with signal");
					kill(tracer.child_pid, SIGKILL);
					cleanup(path_resolved);
					return 1;
				}
				continue;
			}
		}
	}

	// Reset de l'état
	tracer.in_syscall = 0;
	memset(&tracer.current_syscall, 0, sizeof(tracer.current_syscall));

	// Maintenant tracer normalement le programme cible
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