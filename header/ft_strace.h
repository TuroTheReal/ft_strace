#ifndef FT_STRACE_H
# define FT_STRACE_H

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <elf.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>

typedef struct s_cleanup {
	pid_t child_pid;
	int pipe_fd;
	char *path_resolved;
} t_cleanup;

typedef struct s_syscall_info {
	long number;
	const char *name;
	unsigned long long args[6];
	long long ret_val;
	int is_64bit;
	struct timeval start_time;
	struct timeval end_time;
	int arg_count;
} t_syscall_info;

typedef struct s_syscall_stats {
	const char *name;
	long count;
	double total_time;
	long errors;
} t_syscall_stats;

typedef struct s_tracer {
	pid_t child_pid;
	struct user_regs_struct regs;
	int is_64bit;
	int in_syscall;
	int option_c; // -c bonus
	t_syscall_stats *stats;
	int stats_count;
	int stats_capacity;
	t_syscall_info current_syscall;
} t_tracer;

// Prototypes
int			start_trace(char **argv, char **envp, int option_c);
void		trace_loop(t_tracer *tracer);
int			detect_architecture(pid_t pid);
void		get_syscall_info(t_tracer *tracer, t_syscall_info *info);
void		get_syscall_retval(t_tracer *tracer, t_syscall_info *info);
void		print_syscall_enter(t_syscall_info *info, pid_t pid);
void		print_syscall_exit(t_syscall_info *info);
void		print_signal(pid_t pid, int sig);
const char	*get_syscall_name_64(long number);
const char	*get_syscall_name_32(long number);
int			get_syscall_arg_count(long number, int is_64bit);
void		init_stats(t_tracer *tracer);
void		update_stats(t_tracer *tracer, t_syscall_info *info);
void		print_stats(t_tracer *tracer);
void		free_stats(t_tracer *tracer);
char		*find_in_path(const char *cmd);

#endif
