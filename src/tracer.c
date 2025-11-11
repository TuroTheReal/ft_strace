#include "ft_strace.h"

// 32 ou 64 ?
int detect_architecture(pid_t pid)
{
	struct iovec iov;
	struct user_regs_struct regs;

	iov.iov_base = &regs;
	iov.iov_len = sizeof(regs);

	// PTRACE_GETREGSET récupère les registres
	if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
		perror("ptrace GETREGSET");
		return -1;
	}

	// Si taille == full struct --> 64-bit, sinon 32
	return (iov.iov_len == sizeof(struct user_regs_struct)) ? 1 : 0;
}

void trace_loop(t_tracer *tracer)
{
	int status;
	t_syscall_info info;
	struct iovec iov;

	// Configuration pour récupérer les registres
	iov.iov_base = &tracer->regs;
	iov.iov_len = sizeof(tracer->regs);

	while (1) {
		// PTRACE_SYSCALL : continue jusqu'au prochain syscall
		// Le processus s'arrête à l'ENTRÉE et à la SORTIE de chaque syscall
		if (ptrace(PTRACE_SYSCALL, tracer->child_pid, NULL, NULL) == -1) {
			perror("ptrace SYSCALL");
			break;
		}

		// wait proces to stop
		if (waitpid(tracer->child_pid, &status, 0) == -1) {
			perror("waitpid");
			break;
		}

		// process ended
		if (WIFEXITED(status)) {
			fprintf(stderr, "+++ exited with %d +++\n", WEXITSTATUS(status));
			break;
		}

		// process killed
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "+++ killed by signal %d +++\n", WTERMSIG(status));
			break;
		}

		// process stopped
		if (WIFSTOPPED(status)) {
			int sig = WSTOPSIG(status);

			// Le bit indique un syscall-stop grâce à PTRACE_O_TRACESYSGOOD
			if (sig == (SIGTRAP | 0x80)) {
				// arrêt dû à un syscall

				// Récupérer les registres
				if (ptrace(PTRACE_GETREGSET, tracer->child_pid,
						  NT_PRSTATUS, &iov) == -1) {
					perror("ptrace GETREGSET");
					continue;
				}

				if (!tracer->in_syscall) {
					// *** ENTRÉE du syscall ***
					memset(&info, 0, sizeof(info));
					info.is_64bit = tracer->is_64bit;

					//Get syscall info & print
					get_syscall_info(tracer, &info);
					print_syscall_enter(&info);

					tracer->in_syscall = 1;
				} else {
					// *** SORTIE du syscall ***
					memset(&info, 0, sizeof(info));
					info.is_64bit = tracer->is_64bit;

					// Get return value & print
					get_syscall_retval(tracer, &info);
					print_syscall_exit(&info);

					tracer->in_syscall = 0;
				}
			} else {
				//  vrai signal
				print_signal(tracer->child_pid, sig);

				// IMPORTANT : Transmettre le signal au processus tracé
				// Sinon le signal est "mangé" par ptrace
				if (ptrace(PTRACE_SYSCALL, tracer->child_pid, NULL, sig) == -1) {
					perror("ptrace SYSCALL with signal");
					break;
				}
			}
		}
	}
}


// Fork le processus et lance la boucle de traçage
int start_trace(char **argv, char **envp)
{
	t_tracer tracer;
	int status;

	memset(&tracer, 0, sizeof(tracer));

	tracer.child_pid = fork();
	if (tracer.child_pid == -1) {
		perror("fork");
		return 1;
	}

	if (tracer.child_pid == 0) {
		// *** PROCESSUS ENFANT ***

		// PTRACE_TRACEME : indique que ce processus veut être tracé
		// Dès qu'on fera execve, le parent pourra nous tracer
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("ptrace TRACEME");
			exit(1);
		}

		execve(argv[0], argv, envp);
		perror(argv[0]);
		exit(1);
	}

	// *** PROCESSUS PARENT (le traceur) ***
	// Attendre que l'enfant soit prêt (arrêté après execve)
	if (waitpid(tracer.child_pid, &status, 0) == -1) {
		perror("waitpid");
		return 1;
	}

	// 32 ou 64 bit
	tracer.is_64bit = detect_architecture(tracer.child_pid);
	if (tracer.is_64bit == -1) {
		return 1;
	}

	// PTRACE_SETOPTIONS : configurer les options de traçage
	// PTRACE_O_TRACESYSGOOD : ajoute 0x80 à SIGTRAP pour les syscalls (syscalls vs vrais signaux)
	// PTRACE_O_EXITKILL : tue l'enfant si le parent meurt
	if (ptrace(PTRACE_SETOPTIONS, tracer.child_pid, NULL,
			   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) == -1) {
		perror("ptrace SETOPTIONS");
		return 1;
	}

	trace_loop(&tracer);

	return 0;
}
