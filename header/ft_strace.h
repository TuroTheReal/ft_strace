#ifndef FT_STRACE_H
# define FT_STRACE_H

# include <sys/ptrace.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <sys/user.h>
# include <sys/reg.h>
# include <sys/syscall.h>
# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <errno.h>
# include <signal.h>
# include <elf.h>
# include <sys/uio.h>

// Syscalls
typedef struct s_syscall_info {
	long number;			// Numéro du syscall
	const char *name;		// Nom du syscall
	long args[6];			// Arguments (max 6)
	long ret_val;			// Valeur de retour
	int is_64bit;			// 1 si 64-bit, 0 si 32-bit
} t_syscall_info;

// Traceur
typedef struct s_tracer {
	pid_t child_pid;			// PID du processus tracé
	int in_syscall;				// 0 = entrée, 1 = sortie
	int is_64bit;					// Architecture détectée
	struct user_regs_struct regs;	// Registres du processus
} t_tracer;

int		main(int argc, char **argv, char **envp);
void	print_usage(void);

int		start_trace(char **argv, char **envp);
void	trace_loop(t_tracer *tracer);
int		detect_architecture(pid_t pid);

void	get_syscall_info(t_tracer *tracer, t_syscall_info *info);
void	get_syscall_args(t_tracer *tracer, t_syscall_info *info);
void	get_syscall_retval(t_tracer *tracer, t_syscall_info *info);

void	print_syscall_enter(t_syscall_info *info);
void	print_syscall_exit(t_syscall_info *info);
void	print_signal(pid_t pid, int sig);

const char *get_syscall_name_64(long number);
const char *get_syscall_name_32(long number);

#endif