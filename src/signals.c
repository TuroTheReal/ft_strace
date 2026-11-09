#include "ft_strace.h"

// Lu par le handler, rempli par start_trace (tracer.c)
t_cleanup g_cleanup = {-1, -1, NULL};

static sigset_t g_blocked_set;  // Signaux masqués pendant le traitement
static sigset_t g_empty_set;    // Aucun signal bloqué, pendant l'attente

// Comme strace: les signaux ne sont acceptés que pendant waitpid, le seul
// moment où le tracer ne fait rien. Ailleurs ils restent en attente (pending)
// et le handler ne peut jamais couper un fprintf ou une mise à jour d'état
pid_t wait_unblocked(pid_t pid, int *status)
{
	pid_t ret;
	int saved_errno;

	sigprocmask(SIG_SETMASK, &g_empty_set, NULL);
	ret = waitpid(pid, status, 0);
	saved_errno = errno;  // sigprocmask ne doit pas écraser l'errno de waitpid
	sigprocmask(SIG_BLOCK, &g_blocked_set, NULL);
	errno = saved_errno;
	return ret;
}

// Uniquement des fonctions async-signal-safe (write, close, kill, _exit).
// Le détachement ne fait pas partie des requêtes autorisées: on ne peut pas
// relâcher le tracee comme strace, on le tue.
static void signal_handler(int sig)
{
	static const char unfinished[] = " <unfinished ...>\n";

	if (g_line_open) {
		// Rien à faire si l'écriture échoue: on quitte de toute façon
		ssize_t ret = write(STDERR_FILENO, unfinished, sizeof(unfinished) - 1);
		(void)ret;
	}
	if (g_cleanup.pipe_fd != -1)
		close(g_cleanup.pipe_fd);
	if (g_cleanup.child_pid > 0)
		kill(g_cleanup.child_pid, SIGKILL);
	_exit(128 + sig);
}

// Signaux qui arrêtent ft_strace (Ctrl-C, kill, fermeture du terminal, Ctrl-\)
static const int g_handled_signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};
#define NB_HANDLED_SIGNALS (sizeof(g_handled_signals) / sizeof(g_handled_signals[0]))

// À appeler après le fork, dans le parent seulement: le masque est hérité par
// fork et conservé par execve, l'enfant ignorerait sinon Ctrl-C
void setup_signals(void)
{
	// 1. Construire les deux ensembles utilisés autour de chaque waitpid
	sigemptyset(&g_empty_set);
	sigemptyset(&g_blocked_set);
	for (size_t i = 0; i < NB_HANDLED_SIGNALS; i++)
		sigaddset(&g_blocked_set, g_handled_signals[i]);

	// 2. QUAND: bloqués dès maintenant, ouverts seulement pendant waitpid
	sigprocmask(SIG_BLOCK, &g_blocked_set, NULL);

	// 3. QUOI: action exécutée quand un de ces signaux est livré
	for (size_t i = 0; i < NB_HANDLED_SIGNALS; i++)
		signal(g_handled_signals[i], signal_handler);
}

// Fin de trace: plus rien à protéger, comportement par défaut rétabli
void restore_signals(void)
{
	sigprocmask(SIG_SETMASK, &g_empty_set, NULL);
	for (size_t i = 0; i < NB_HANDLED_SIGNALS; i++)
		signal(g_handled_signals[i], SIG_DFL);
}
