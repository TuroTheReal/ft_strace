// Signaux (rt_sigprocmask, rt_sigaction), ioctl de terminal et fork (clone)
// A lancer dans un vrai terminal pour que les ioctl reussissent
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <sys/syscall.h>
#include <stdint.h>

static void h(int s) { (void)s; }
static void hi(int s, siginfo_t *i, void *c) { (void)s; (void)i; (void)c; }

int main(void)
{
	sigset_t set, old;
	struct sigaction sa, osa;
	struct winsize ws;
	struct termios t;
	pid_t pg;
	int n;

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGCHLD);
	sigprocmask(SIG_BLOCK, &set, &old);
	sigprocmask(SIG_SETMASK, &old, NULL);
	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, &old);
	sigprocmask(SIG_SETMASK, &old, NULL);
	sigemptyset(&set);
	for (int i = 1; i <= 32; i++) sigaddset(&set, i);
	sigprocmask(SIG_BLOCK, &set, NULL);
	sigprocmask(SIG_UNBLOCK, &set, NULL);
	{
		uint64_t m32 = 0xffffffffULL, m33 = 0x1ffffffffULL, all = ~0ULL;
		syscall(SYS_rt_sigprocmask, SIG_BLOCK, &m32, NULL, 8);
		syscall(SYS_rt_sigprocmask, SIG_BLOCK, &m33, NULL, 8);
		syscall(SYS_rt_sigprocmask, SIG_BLOCK, &all, NULL, 8);
		syscall(SYS_rt_sigprocmask, SIG_SETMASK, &old, NULL, 8);
		syscall(SYS_rt_sigprocmask, SIG_BLOCK, 1, NULL, 8);
		syscall(SYS_rt_sigprocmask, 42, NULL, NULL, 8);
		syscall(SYS_rt_sigaction, SIGUSR1, 1, NULL, 8);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = h;
	sigaddset(&sa.sa_mask, SIGTERM);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &sa, &osa);
	sa.sa_sigaction = hi;
	sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESETHAND | SA_ONSTACK;
	sigaction(SIGUSR2, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
	sigaction(SIGUSR1, NULL, &osa);

	ioctl(0, TIOCGWINSZ, &ws);
	ioctl(0, TCGETS, &t);
	ioctl(0, TIOCGPGRP, &pg);
	ioctl(0, FIONREAD, &n);
	ioctl(0, TIOCSWINSZ, &ws);
	ioctl(0, 0xdead, NULL);
	isatty(1);

	if (fork() == 0) _exit(0);
	wait(NULL);
	return 0;
}
