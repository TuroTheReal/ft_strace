#include "ft_strace.h"
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_STRLEN 32      // Longueur max des chaînes/tableaux affichés (strace -s 32)
#define MAX_PATHLEN 4096   // Les chemins sont affichés en entier, comme strace
#define RET_COLUMN 40      // strace aligne "= " sur la colonne 40

typedef struct s_flag {
	unsigned long long val;
	const char *name;
} t_flag;

#define FLAGS(v, tab, zero) print_flags(v, tab, sizeof(tab) / sizeof(tab[0]), zero)
#define ARRAY_LEN(tab) (sizeof(tab) / sizeof(tab[0]))

// Colonne courante de la ligne de trace, pour aligner le " = "
static int g_col = 0;

volatile sig_atomic_t g_line_open = 0;

static void out(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void out(const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (n > 0)
		g_col += n;
}

/* ************************************************************************** */
/*                                  SIGNAUX                                   */
/* ************************************************************************** */

// Nom court du signal ("SIGSEGV"), strsignal() donne la description longue
const char *signal_name(int sig)
{
	static const char *names[] = {
		[SIGHUP] = "SIGHUP", [SIGINT] = "SIGINT", [SIGQUIT] = "SIGQUIT",
		[SIGILL] = "SIGILL", [SIGTRAP] = "SIGTRAP", [SIGABRT] = "SIGABRT",
		[SIGBUS] = "SIGBUS", [SIGFPE] = "SIGFPE", [SIGKILL] = "SIGKILL",
		[SIGUSR1] = "SIGUSR1", [SIGSEGV] = "SIGSEGV", [SIGUSR2] = "SIGUSR2",
		[SIGPIPE] = "SIGPIPE", [SIGALRM] = "SIGALRM", [SIGTERM] = "SIGTERM",
		[SIGSTKFLT] = "SIGSTKFLT", [SIGCHLD] = "SIGCHLD", [SIGCONT] = "SIGCONT",
		[SIGSTOP] = "SIGSTOP", [SIGTSTP] = "SIGTSTP", [SIGTTIN] = "SIGTTIN",
		[SIGTTOU] = "SIGTTOU", [SIGURG] = "SIGURG", [SIGXCPU] = "SIGXCPU",
		[SIGXFSZ] = "SIGXFSZ", [SIGVTALRM] = "SIGVTALRM", [SIGPROF] = "SIGPROF",
		[SIGWINCH] = "SIGWINCH", [SIGIO] = "SIGIO", [SIGPWR] = "SIGPWR",
		[SIGSYS] = "SIGSYS",
	};
	static char buf[16];

	if (sig > 0 && sig < (int)ARRAY_LEN(names) && names[sig])
		return names[sig];
	snprintf(buf, sizeof(buf), "SIG%d", sig);
	return buf;
}

// si_code: valeurs génériques (<= 0 ou SI_KERNEL) puis spécifiques au signal
static void print_si_code(const siginfo_t *si)
{
	switch (si->si_code) {
		case SI_USER: fprintf(stderr, "SI_USER"); return;
		case SI_KERNEL: fprintf(stderr, "SI_KERNEL"); return;
		case SI_QUEUE: fprintf(stderr, "SI_QUEUE"); return;
		case SI_TIMER: fprintf(stderr, "SI_TIMER"); return;
		case SI_TKILL: fprintf(stderr, "SI_TKILL"); return;
	}
	if (si->si_signo == SIGCHLD) {
		static const char *cld[] = {NULL, "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED",
			"CLD_TRAPPED", "CLD_STOPPED", "CLD_CONTINUED"};
		if (si->si_code >= CLD_EXITED && si->si_code <= CLD_CONTINUED) {
			fprintf(stderr, "%s", cld[si->si_code]);
			return;
		}
	}
	if (si->si_signo == SIGSEGV && si->si_code == SEGV_MAPERR) {
		fprintf(stderr, "SEGV_MAPERR");
		return;
	}
	if (si->si_signo == SIGSEGV && si->si_code == SEGV_ACCERR) {
		fprintf(stderr, "SEGV_ACCERR");
		return;
	}
	fprintf(stderr, "%d", si->si_code);
}

// Format strace: --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, ...} ---
void print_signal(pid_t pid, int sig)
{
	siginfo_t si;
	const char *name = signal_name(sig);

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &si) == -1) {
		fprintf(stderr, "--- %s ---\n", name);
		return;
	}
	fprintf(stderr, "--- %s {si_signo=%s, si_code=", name, name);
	print_si_code(&si);

	if (si.si_code <= 0) {
		// Envoyé par un processus (kill, tkill, sigqueue)
		fprintf(stderr, ", si_pid=%d, si_uid=%u", si.si_pid, si.si_uid);
	} else if (sig == SIGCHLD) {
		fprintf(stderr, ", si_pid=%d, si_uid=%u, si_status=%d, si_utime=%ld, si_stime=%ld",
			si.si_pid, si.si_uid, si.si_status, (long)si.si_utime, (long)si.si_stime);
	} else if ((sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE)
			&& si.si_code != SI_KERNEL) {
		if (si.si_addr)
			fprintf(stderr, ", si_addr=%p", si.si_addr);
		else
			fprintf(stderr, ", si_addr=NULL");
	}
	fprintf(stderr, "} ---\n");
}

/* ************************************************************************** */
/*                         LECTURE MÉMOIRE DU TRACEE                          */
/* ************************************************************************** */

// La lecture mémoire via ptrace est interdite: on lit /proc/PID/mem (autorisé car on est le tracer)
// Retourne le nombre d'octets lus (peut être partiel en bord de mapping) ou -1
static ssize_t read_mem(pid_t pid, unsigned long long addr, void *buf, size_t len)
{
	char path[64];
	int fd;
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return -1;
	n = pread(fd, buf, len, (off_t)addr);
	close(fd);
	return n;
}

// Échappement façon strace: \n, \t, \", octal pour le reste ("\177ELF\2\1")
static void print_quoted(const unsigned char *s, size_t len, int hex)
{
	out("\"");
	for (size_t i = 0; i < len; i++) {
		unsigned char c = s[i];

		if (hex) {
			out("\\x%02x", c);
			continue;
		}
		switch (c) {
			case '"': out("\\\""); break;
			case '\\': out("\\\\"); break;
			case '\n': out("\\n"); break;
			case '\t': out("\\t"); break;
			case '\r': out("\\r"); break;
			case '\v': out("\\v"); break;
			case '\f': out("\\f"); break;
			default:
				if (c >= 32 && c < 127)
					out("%c", c);
				// 3 chiffres si un chiffre suit, sinon "\1" serait ambigu
				else if (i + 1 < len && s[i + 1] >= '0' && s[i + 1] <= '9')
					out("\\%03o", c);
				else
					out("\\%o", c);
		}
	}
	out("\"");
}

// Buffer de taille connue (read, write...): MAX_STRLEN octets max puis "..."
static void print_buffer(pid_t pid, unsigned long long addr, unsigned long long len, int hex)
{
	unsigned char buf[MAX_STRLEN] = {0};
	size_t n = len > MAX_STRLEN ? MAX_STRLEN : len;

	if (!addr) {
		out("NULL");
		return;
	}
	if (n && read_mem(pid, addr, buf, n) != (ssize_t)n) {
		out("%#llx", addr);
		return;
	}
	print_quoted(buf, n, hex);
	if (len > MAX_STRLEN)
		out("...");
}

// Chaîne terminée par NUL, tronquée à max caractères puis "..."
static void print_cstring(pid_t pid, unsigned long long addr, size_t max)
{
	unsigned char buf[MAX_PATHLEN + 1];
	ssize_t n;
	size_t len;

	if (!addr) {
		out("NULL");
		return;
	}
	if (max > MAX_PATHLEN)
		max = MAX_PATHLEN;
	n = read_mem(pid, addr, buf, max + 1);
	if (n <= 0) {
		out("%#llx", addr);
		return;
	}
	len = strnlen((char *)buf, (size_t)n);
	if (len > max) {
		print_quoted(buf, max, 0);
		out("...");
	} else {
		print_quoted(buf, len, 0);
	}
}

static void print_path(pid_t pid, unsigned long long addr)
{
	print_cstring(pid, addr, MAX_PATHLEN);
}

// Lit le i-ème pointeur d'un tableau (argv, envp): 8 octets en 64 bit, 4 en 32 bit
static int read_ptr(pid_t pid, unsigned long long addr, int i, int is_64,
		unsigned long long *ptr)
{
	size_t psize = is_64 ? 8 : 4;

	*ptr = 0;
	return read_mem(pid, addr + i * psize, ptr, psize) == (ssize_t)psize ? 0 : -1;
}

// execve argv: ["/bin/ls", "-la"]
static void print_argv(pid_t pid, unsigned long long addr, int is_64)
{
	unsigned long long p;

	if (!addr) {
		out("NULL");
		return;
	}
	out("[");
	for (int i = 0; read_ptr(pid, addr, i, is_64, &p) == 0 && p; i++) {
		if (i == MAX_STRLEN) {
			out(", ...");
			break;
		}
		if (i)
			out(", ");
		print_cstring(pid, p, MAX_STRLEN);
	}
	out("]");
}

// execve envp: adresse + nombre de variables, comme strace
static void print_envp(pid_t pid, unsigned long long addr, int is_64)
{
	unsigned long long p;
	int count = 0;

	if (!addr) {
		out("NULL");
		return;
	}
	while (count < 100000 && read_ptr(pid, addr, count, is_64, &p) == 0 && p)
		count++;
	out("%#llx /* %d var%s */", addr, count, count == 1 ? "" : "s");
}

/* ************************************************************************** */
/*                              HELPERS DE FORMAT                             */
/* ************************************************************************** */

// Bits connus séparés par |, reste en hexa, zero si rien
static void print_flags(unsigned long long v, const t_flag *f, size_t n, const char *zero)
{
	int first = 1;

	for (size_t i = 0; i < n; i++) {
		if (f[i].val && (v & f[i].val) == f[i].val) {
			out("%s%s", first ? "" : "|", f[i].name);
			v &= ~f[i].val;
			first = 0;
		}
	}
	if (v) {
		out("%s%#llx", first ? "" : "|", v);
		first = 0;
	}
	if (first)
		out("%s", zero);
}

// Nom pour une valeur exacte, sinon décimal
static void print_enum(long long v, const t_flag *f, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if ((long long)f[i].val == v) {
			out("%s", f[i].name);
			return;
		}
	}
	out("%lld", v);
}

static void print_ptr(unsigned long long v)
{
	if (v)
		out("%#llx", v);
	else
		out("NULL");
}

static void print_fd(unsigned long long v)
{
	out("%d", (int)v);
}

// dirfd des syscalls *at(): AT_FDCWD ou numéro
static void print_dirfd(unsigned long long v)
{
	if ((int)v == -100)
		out("AT_FDCWD");
	else
		out("%d", (int)v);
}

// Argument inconnu: petit entier en décimal, gros (pointeur, flags) en hexa
static void print_default_arg(unsigned long long v, int is_64)
{
	long long s = is_64 ? (long long)v : (long long)(int)v;

	if (v == 0)
		out("NULL");
	else if (s >= -4096 && s <= 65535)
		out("%lld", s);
	else
		out("%#llx", is_64 ? v : (unsigned int)v);
}

static void print_open_flags(unsigned long long flags)
{
	static const t_flag fl[] = {
		{0x40, "O_CREAT"}, {0x80, "O_EXCL"}, {0x100, "O_NOCTTY"},
		{0x200, "O_TRUNC"}, {0x400, "O_APPEND"}, {0x800, "O_NONBLOCK"},
		{0x1000, "O_DSYNC"}, {0x2000, "O_ASYNC"}, {0x4000, "O_DIRECT"},
		{0x8000, "O_LARGEFILE"}, {0x40000, "O_NOATIME"}, {0x80000, "O_CLOEXEC"},
		{0x200000, "O_PATH"}, {0x10000, "O_DIRECTORY"}, {0x20000, "O_NOFOLLOW"},
	};
	static const char *mode[] = {"O_RDONLY", "O_WRONLY", "O_RDWR", "O_ACCMODE"};

	// Access mode d'abord
	out("%s", mode[flags & 0x3]);
	if (flags & ~0x3ULL) {
		out("|");
		FLAGS(flags & ~0x3ULL, fl, "");
	}
}

static void print_prot(unsigned long long prot)
{
	static const t_flag fl[] = {
		{0x1, "PROT_READ"}, {0x2, "PROT_WRITE"}, {0x4, "PROT_EXEC"},
		{0x01000000, "PROT_GROWSDOWN"}, {0x02000000, "PROT_GROWSUP"},
	};

	FLAGS(prot, fl, "PROT_NONE");
}

static void print_mmap_flags(unsigned long long flags)
{
	static const t_flag fl[] = {
		{0x1, "MAP_SHARED"}, {0x2, "MAP_PRIVATE"}, {0x10, "MAP_FIXED"},
		{0x20, "MAP_ANONYMOUS"}, {0x40, "MAP_32BIT"}, {0x100, "MAP_GROWSDOWN"},
		{0x800, "MAP_DENYWRITE"}, {0x1000, "MAP_EXECUTABLE"}, {0x2000, "MAP_LOCKED"},
		{0x4000, "MAP_NORESERVE"}, {0x8000, "MAP_POPULATE"}, {0x10000, "MAP_NONBLOCK"},
		{0x20000, "MAP_STACK"}, {0x40000, "MAP_HUGETLB"}, {0x100000, "MAP_FIXED_NOREPLACE"},
	};

	FLAGS(flags, fl, "0");
}

static const t_flag g_at_flags[] = {
	{0x100, "AT_SYMLINK_NOFOLLOW"}, {0x200, "AT_REMOVEDIR"},
	{0x400, "AT_SYMLINK_FOLLOW"}, {0x800, "AT_NO_AUTOMOUNT"},
	{0x1000, "AT_EMPTY_PATH"}, {0x2000, "AT_STATX_FORCE_SYNC"},
	{0x4000, "AT_STATX_DONT_SYNC"},
};

// "S_IFREG|0644"
static void print_mode(unsigned int mode)
{
	static const t_flag types[] = {
		{S_IFREG, "S_IFREG"}, {S_IFDIR, "S_IFDIR"}, {S_IFCHR, "S_IFCHR"},
		{S_IFBLK, "S_IFBLK"}, {S_IFIFO, "S_IFIFO"}, {S_IFLNK, "S_IFLNK"},
		{S_IFSOCK, "S_IFSOCK"},
	};

	// Bits spéciaux nommés (S_ISUID, S_ISGID, S_ISVTX), droits en octal, comme strace
	print_enum(mode & S_IFMT, types, ARRAY_LEN(types));
	if (mode & S_ISUID)
		out("|S_ISUID");
	if (mode & S_ISGID)
		out("|S_ISGID");
	if (mode & S_ISVTX)
		out("|S_ISVTX");
	out("|%#o", mode & 0777);
}

// struct stat (64 bit uniquement: le layout 32 bit est différent)
static void print_stat(pid_t pid, unsigned long long addr, int is_64)
{
	struct stat st;

	if (!is_64 || read_mem(pid, addr, &st, sizeof(st)) != (ssize_t)sizeof(st)) {
		print_ptr(addr);
		return;
	}
	out("{st_mode=");
	print_mode(st.st_mode);
	// Device: strace affiche major/minor au lieu de la taille
	if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
		out(", st_rdev=makedev(%#x, %#x), ...}", major(st.st_rdev), minor(st.st_rdev));
	else
		out(", st_size=%lld, ...}", (long long)st.st_size);
}

static void print_statx_mask(unsigned long long mask)
{
	static const t_flag fl[] = {
		{0x7ff, "STATX_BASIC_STATS"},
		{0x1, "STATX_TYPE"}, {0x2, "STATX_MODE"}, {0x4, "STATX_NLINK"},
		{0x8, "STATX_UID"}, {0x10, "STATX_GID"}, {0x20, "STATX_ATIME"},
		{0x40, "STATX_MTIME"}, {0x80, "STATX_CTIME"}, {0x100, "STATX_INO"},
		{0x200, "STATX_SIZE"}, {0x400, "STATX_BLOCKS"}, {0x800, "STATX_BTIME"},
		{0x1000, "STATX_MNT_ID"},
	};

	FLAGS(mask, fl, "0");
}

// struct statx: même layout en 32 et 64 bit (lecture par offsets, cf. linux/stat.h)
static void print_statx(pid_t pid, unsigned long long addr)
{
	static const t_flag attrs[] = {
		{0x4, "STATX_ATTR_COMPRESSED"}, {0x10, "STATX_ATTR_IMMUTABLE"},
		{0x20, "STATX_ATTR_APPEND"}, {0x40, "STATX_ATTR_NODUMP"},
		{0x800, "STATX_ATTR_ENCRYPTED"}, {0x1000, "STATX_ATTR_AUTOMOUNT"},
		{0x2000, "STATX_ATTR_MOUNT_ROOT"}, {0x100000, "STATX_ATTR_VERITY"},
		{0x200000, "STATX_ATTR_DAX"},
	};
	unsigned char b[48];
	unsigned int mask;
	unsigned long long attributes;
	unsigned short mode;
	unsigned long long size;

	if (read_mem(pid, addr, b, sizeof(b)) != (ssize_t)sizeof(b)) {
		print_ptr(addr);
		return;
	}
	memcpy(&mask, b + 0, sizeof(mask));
	memcpy(&attributes, b + 8, sizeof(attributes));
	memcpy(&mode, b + 28, sizeof(mode));
	memcpy(&size, b + 40, sizeof(size));
	out("{stx_mask=");
	print_statx_mask(mask);
	out(", stx_attributes=");
	FLAGS(attributes, attrs, "0");
	out(", stx_mode=");
	print_mode(mode);
	out(", stx_size=%llu, ...}", size);
}


// {sa_family=AF_UNIX, sun_path="/run/..."} ou {sa_family=AF_INET, sin_port=..., sin_addr=...}
static void print_sockaddr(pid_t pid, unsigned long long addr, unsigned long long len)
{
	struct sockaddr_storage ss;
	size_t n = len < sizeof(ss) ? len : sizeof(ss);

	memset(&ss, 0, sizeof(ss));
	if (!addr || n < sizeof(sa_family_t)
		|| read_mem(pid, addr, &ss, n) != (ssize_t)n) {
		print_ptr(addr);
		return;
	}
	if (ss.ss_family == AF_UNIX) {
		struct sockaddr_un *un = (struct sockaddr_un *)&ss;
		size_t plen = n - offsetof(struct sockaddr_un, sun_path);

		out("{sa_family=AF_UNIX, sun_path=");
		// Socket abstraite: premier octet nul, strace l'affiche avec @
		if (plen > 0 && un->sun_path[0] == '\0') {
			out("@");
			print_quoted((unsigned char *)un->sun_path + 1, strnlen(un->sun_path + 1, plen - 1), 0);
		} else {
			print_quoted((unsigned char *)un->sun_path, strnlen(un->sun_path, plen), 0);
		}
		out("}");
	} else if (ss.ss_family == AF_INET && n >= sizeof(struct sockaddr_in)) {
		struct sockaddr_in *in = (struct sockaddr_in *)&ss;
		char ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
		out("{sa_family=AF_INET, sin_port=htons(%u), sin_addr=inet_addr(\"%s\")}",
			ntohs(in->sin_port), ip);
	} else if (ss.ss_family == AF_INET6 && n >= sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;
		char ip[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
		out("{sa_family=AF_INET6, sin6_port=htons(%u), sin6_addr=\"%s\"}",
			ntohs(in6->sin6_port), ip);
	} else {
		out("{sa_family=%u, ...}", ss.ss_family);
	}
}

static const char *g_rlimit_names[] = {
	"RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_DATA", "RLIMIT_STACK",
	"RLIMIT_CORE", "RLIMIT_RSS", "RLIMIT_NPROC", "RLIMIT_NOFILE",
	"RLIMIT_MEMLOCK", "RLIMIT_AS", "RLIMIT_LOCKS", "RLIMIT_SIGPENDING",
	"RLIMIT_MSGQUEUE", "RLIMIT_NICE", "RLIMIT_RTPRIO", "RLIMIT_RTTIME",
};

static void print_rlimit_resource(unsigned long long r)
{
	if (r < ARRAY_LEN(g_rlimit_names))
		out("%s", g_rlimit_names[r]);
	else
		out("%#llx /* RLIMIT_??? */", r);
}

// Une limite: infini, multiple de 1024 ("8192*1024") ou valeur brute
static void print_rlim_value(unsigned long long v, int word, const char *inf)
{
	if ((word == 8 && v == ~0ULL) || (word == 4 && v == 0xffffffffULL))
		out("%s", inf);
	else if (v > 1024 && v % 1024 == 0)
		out("%llu*1024", v / 1024);
	else
		out("%llu", v);
}

// struct rlimit {rlim_cur, rlim_max}: mots de 8 octets (64 bit, prlimit64) ou 4 (32 bit)
static void print_rlimit(pid_t pid, unsigned long long addr, int word, const char *inf)
{
	unsigned long long cur = 0;
	unsigned long long max = 0;

	if (!addr || read_mem(pid, addr, &cur, word) != word
		|| read_mem(pid, addr + word, &max, word) != word) {
		print_ptr(addr);
		return;
	}
	out("{rlim_cur=");
	print_rlim_value(cur, word, inf);
	out(", rlim_max=");
	print_rlim_value(max, word, inf);
	out("}");
}

// Nombre d'entrées d'un buffer getdents64 (struct linux_dirent64, d_reclen à l'offset 16)
static int count_dirents(pid_t pid, unsigned long long addr, long long len)
{
	unsigned char *buf;
	int count = 0;
	long long off = 0;

	if (len <= 0)
		return 0;
	buf = malloc((size_t)len);
	if (!buf)
		return -1;
	if (read_mem(pid, addr, buf, (size_t)len) != (ssize_t)len) {
		free(buf);
		return -1;
	}
	while (off + 18 <= len) {
		unsigned short reclen;

		memcpy(&reclen, buf + off + 16, sizeof(reclen));
		if (reclen == 0)
			break;
		off += reclen;
		count++;
	}
	free(buf);
	return count;
}

static const t_flag g_af[] = {
	{AF_UNSPEC, "AF_UNSPEC"}, {AF_UNIX, "AF_UNIX"}, {AF_INET, "AF_INET"},
	{AF_INET6, "AF_INET6"}, {AF_NETLINK, "AF_NETLINK"}, {AF_PACKET, "AF_PACKET"},
};

// Mode de access(): F_OK (0) ou combinaison R_OK|W_OK|X_OK
static void print_access_mode(unsigned long long mode)
{
	static const t_flag fl[] = {{4, "R_OK"}, {2, "W_OK"}, {1, "X_OK"}};

	if (mode == 0)
		out("F_OK");
	else
		FLAGS(mode, fl, "0");
}

/* ************************************************************************** */
/*                        SIGNAUX: MASQUES ET SIGACTION                       */
/* ************************************************************************** */

// Nom court dans un masque, comme strace: INT, CHLD, RTMIN (32), RT_n (32 + n)
static void print_sig_short(int sig)
{
	if (sig == 32)
		out("RTMIN");
	else if (sig > 32)
		out("RT_%d", sig - 32);
	else
		out("%s", signal_name(sig) + 3);  // saute le "SIG"
}

// sigset_t du kernel: 1 bit par signal, bit 0 = signal 1.
// Au-delà de 2/3 des bits à 1, strace affiche l'inverse (~[...]), plus court
static void print_sigset_val(uint64_t mask, int nbits)
{
	int first = 1;

	if (__builtin_popcountll(mask) >= nbits * 2 / 3) {
		out("~");
		mask = ~mask;
		if (nbits < 64)
			mask &= (1ULL << nbits) - 1;
	}
	out("[");
	for (int i = 0; i < nbits; i++) {
		if (mask & (1ULL << i)) {
			out("%s", first ? "" : " ");
			print_sig_short(i + 1);
			first = 0;
		}
	}
	out("]");
}

// Le masque vit dans la mémoire du tracee: on le lit, sinon adresse brute
static void print_sigset(pid_t pid, unsigned long long addr, unsigned long long size)
{
	uint64_t mask = 0;

	if (!addr) {
		out("NULL");
		return;
	}
	if (size == 0 || size > sizeof(mask)
		|| read_mem(pid, addr, &mask, (size_t)size) != (ssize_t)size) {
		print_ptr(addr);
		return;
	}
	print_sigset_val(mask, (int)size * 8);
}

// Valeurs du kernel (asm/signal.h), même ordre d'affichage que strace
static const t_flag g_sa_flags[] = {
	{0x04000000, "SA_RESTORER"}, {0x08000000, "SA_ONSTACK"},
	{0x10000000, "SA_RESTART"}, {0x40000000, "SA_NODEFER"},
	{0x80000000, "SA_RESETHAND"}, {0x00000004, "SA_SIGINFO"},
	{0x00000001, "SA_NOCLDSTOP"}, {0x00000002, "SA_NOCLDWAIT"},
};

// struct sigaction du KERNEL, pas celle de la libc: handler, flags, restorer, mask
// x86_64: 3 champs de 8 octets ; i386: 3 champs de 4 octets ; mask: 8 octets
static void print_sigaction(pid_t pid, unsigned long long addr, int is_64)
{
	unsigned char buf[32];
	size_t word = is_64 ? 8 : 4;
	size_t len = 3 * word + sizeof(uint64_t);
	unsigned long long handler = 0, flags = 0, restorer = 0;
	uint64_t mask;

	if (!addr) {
		out("NULL");
		return;
	}
	if (read_mem(pid, addr, buf, len) != (ssize_t)len) {
		print_ptr(addr);
		return;
	}
	// x86 est little-endian: copier 4 octets dans un 8 octets à zéro est correct
	memcpy(&handler, buf, word);
	memcpy(&flags, buf + word, word);
	memcpy(&restorer, buf + 2 * word, word);
	memcpy(&mask, buf + 3 * word, sizeof(mask));

	out("{sa_handler=");
	if (handler == 0)
		out("SIG_DFL");
	else if (handler == 1)
		out("SIG_IGN");
	else
		out("%#llx", handler);
	out(", sa_mask=");
	print_sigset_val(mask, 64);
	out(", sa_flags=");
	FLAGS(flags, g_sa_flags, "0");
	if (flags & 0x04000000)
		out(", sa_restorer=%#llx", restorer);
	out("}");
}

/* ************************************************************************** */
/*                                   IOCTL                                    */
/* ************************************************************************** */

static const t_flag g_ioctl_req[] = {
	{0x5401, "TCGETS"}, {0x5402, "TCSETS"}, {0x5403, "TCSETSW"},
	{0x5404, "TCSETSF"}, {0x5409, "TCSBRK"}, {0x540A, "TCXONC"},
	{0x540B, "TCFLSH"}, {0x540E, "TIOCSCTTY"}, {0x540F, "TIOCGPGRP"},
	{0x5410, "TIOCSPGRP"}, {0x5411, "TIOCOUTQ"}, {0x5413, "TIOCGWINSZ"},
	{0x5414, "TIOCSWINSZ"}, {0x541B, "FIONREAD"}, {0x5421, "FIONBIO"},
	{0x5422, "TIOCNOTTY"}, {0x5429, "TIOCGSID"}, {0x5450, "FIONCLEX"},
	{0x5451, "FIOCLEX"}, {0x80045430, "TIOCGPTN"}, {0x40045431, "TIOCSPTLCK"},
};

// Requête connue par son nom, sinon décomposée comme strace:
// direction (bits 30-31), type (8-15), numéro (0-7), taille de l'argument (16-29)
static void print_ioctl_request(unsigned int req)
{
	static const char *dir[] = {
		"_IOC_NONE", "_IOC_WRITE", "_IOC_READ", "_IOC_READ|_IOC_WRITE",
	};

	for (size_t i = 0; i < ARRAY_LEN(g_ioctl_req); i++) {
		if (g_ioctl_req[i].val == req) {
			out("%s", g_ioctl_req[i].name);
			return;
		}
	}
	out("_IOC(%s, %#x, %#x, %#x)", dir[req >> 30], (req >> 8) & 0xff,
		req & 0xff, (req >> 16) & 0x3fff);
}

// c_oflag: 6 champs de délai (NL0, CR0...) toujours affichés, puis les bits
static void print_termios_oflag(unsigned int v)
{
	static const char *nl[] = {"NL0", "NL1"};
	static const char *cr[] = {"CR0", "CR1", "CR2", "CR3"};
	static const char *tab[] = {"TAB0", "TAB1", "TAB2", "TAB3"};
	static const char *bs[] = {"BS0", "BS1"};
	static const char *vt[] = {"VT0", "VT1"};
	static const char *ff[] = {"FF0", "FF1"};
	static const t_flag fl[] = {
		{0x01, "OPOST"}, {0x02, "OLCUC"}, {0x04, "ONLCR"}, {0x08, "OCRNL"},
		{0x10, "ONOCR"}, {0x20, "ONLRET"}, {0x40, "OFILL"}, {0x80, "OFDEL"},
	};

	out("%s|%s|%s|%s|%s|%s", nl[(v >> 8) & 1], cr[(v >> 9) & 3],
		tab[(v >> 11) & 3], bs[(v >> 13) & 1], vt[(v >> 14) & 1], ff[(v >> 15) & 1]);
	v &= ~0xff00u;
	if (v) {
		out("|");
		FLAGS(v, fl, "");
	}
}

// c_cflag: vitesse (champ CBAUD), taille de caractère (CSIZE), puis les bits
static void print_termios_cflag(unsigned int v)
{
	static const char *low[] = {
		"B0", "B50", "B75", "B110", "B134", "B150", "B200", "B300", "B600",
		"B1200", "B1800", "B2400", "B4800", "B9600", "B19200", "B38400",
	};
	static const char *high[] = {
		"BOTHER", "B57600", "B115200", "B230400", "B460800", "B500000",
		"B576000", "B921600", "B1000000", "B1152000", "B1500000", "B2000000",
		"B2500000", "B3000000", "B3500000", "B4000000",
	};
	static const t_flag fl[] = {
		{0x40, "CSTOPB"}, {0x80, "CREAD"}, {0x100, "PARENB"}, {0x200, "PARODD"},
		{0x400, "HUPCL"}, {0x800, "CLOCAL"}, {0x40000000, "CMSPAR"},
		{0x80000000, "CRTSCTS"},
	};

	out("%s|CS%u", (v & 0x1000) ? high[v & 0xf] : low[v & 0xf], 5 + ((v >> 4) & 3));
	v &= ~0x103fu;
	if (v) {
		out("|");
		FLAGS(v, fl, "");
	}
}

// struct termios du kernel: 4 x u32 (iflag, oflag, cflag, lflag), puis c_line et c_cc
// strace n'affiche que les 4 flags suivis de "..."
static void print_termios(pid_t pid, unsigned long long addr)
{
	static const t_flag iflag[] = {
		{0x1, "IGNBRK"}, {0x2, "BRKINT"}, {0x4, "IGNPAR"}, {0x8, "PARMRK"},
		{0x10, "INPCK"}, {0x20, "ISTRIP"}, {0x40, "INLCR"}, {0x80, "IGNCR"},
		{0x100, "ICRNL"}, {0x200, "IUCLC"}, {0x400, "IXON"}, {0x800, "IXANY"},
		{0x1000, "IXOFF"}, {0x2000, "IMAXBEL"}, {0x4000, "IUTF8"},
	};
	static const t_flag lflag[] = {
		{0x1, "ISIG"}, {0x2, "ICANON"}, {0x4, "XCASE"}, {0x8, "ECHO"},
		{0x10, "ECHOE"}, {0x20, "ECHOK"}, {0x40, "ECHONL"}, {0x80, "NOFLSH"},
		{0x8000, "IEXTEN"}, {0x200, "ECHOCTL"}, {0x400, "ECHOPRT"},
		{0x800, "ECHOKE"}, {0x1000, "FLUSHO"}, {0x4000, "PENDIN"},
		{0x100, "TOSTOP"}, {0x10000, "EXTPROC"},
	};
	unsigned int f[4];

	if (read_mem(pid, addr, f, sizeof(f)) != (ssize_t)sizeof(f)) {
		print_ptr(addr);
		return;
	}
	out("{c_iflag=");
	FLAGS(f[0], iflag, "0");
	out(", c_oflag=");
	print_termios_oflag(f[1]);
	out(", c_cflag=");
	print_termios_cflag(f[2]);
	out(", c_lflag=");
	FLAGS(f[3], lflag, "0");
	out(", ...}");
}

// struct winsize: 4 x unsigned short
static void print_winsize(pid_t pid, unsigned long long addr)
{
	unsigned short ws[4];

	if (read_mem(pid, addr, ws, sizeof(ws)) != (ssize_t)sizeof(ws)) {
		print_ptr(addr);
		return;
	}
	out("{ws_row=%hu, ws_col=%hu, ws_xpixel=%hu, ws_ypixel=%hu}", ws[0], ws[1], ws[2], ws[3]);
}

// Entier pointé (pid, compteur): [42]
static void print_int_ptr(pid_t pid, unsigned long long addr)
{
	int v;

	if (read_mem(pid, addr, &v, sizeof(v)) != (ssize_t)sizeof(v))
		print_ptr(addr);
	else
		out("[%d]", v);
}

// 3e argument d'ioctl, à la sortie du syscall.
// Requêtes "get": le kernel remplit la struct, décodée seulement en cas de succès.
// Requêtes "set": la struct vient du programme, toujours décodée
static void print_ioctl_arg(pid_t pid, unsigned int req, unsigned long long arg, int failed)
{
	switch (req) {
		case 0x5401:  // TCGETS
			if (failed)
				print_ptr(arg);
			else
				print_termios(pid, arg);
			return;
		case 0x5402:  // TCSETS
		case 0x5403:  // TCSETSW
		case 0x5404:  // TCSETSF
			print_termios(pid, arg);
			return;
		case 0x5413:  // TIOCGWINSZ
			if (failed)
				print_ptr(arg);
			else
				print_winsize(pid, arg);
			return;
		case 0x5414:  // TIOCSWINSZ
			print_winsize(pid, arg);
			return;
		case 0x540F:  // TIOCGPGRP
		case 0x541B:  // FIONREAD
		case 0x5429:  // TIOCGSID
		case 0x5411:  // TIOCOUTQ
		case 0x80045430: // TIOCGPTN
			if (failed)
				print_ptr(arg);
			else
				print_int_ptr(pid, arg);
			return;
		case 0x5410:  // TIOCSPGRP
		case 0x5421:  // FIONBIO
		case 0x40045431: // TIOCSPTLCK
			print_int_ptr(pid, arg);
			return;
		default:      // Argument inconnu: valeur brute
			out("%#llx", arg);
			return;
	}
}

/* ************************************************************************** */
/*                                   CLONE                                    */
/* ************************************************************************** */

// Octet bas = signal envoyé au parent à la mort de l'enfant (SIGCHLD pour fork)
static void print_clone_flags(unsigned long long v)
{
	static const t_flag fl[] = {
		{0x100, "CLONE_VM"}, {0x200, "CLONE_FS"}, {0x400, "CLONE_FILES"},
		{0x800, "CLONE_SIGHAND"}, {0x1000, "CLONE_PIDFD"}, {0x2000, "CLONE_PTRACE"},
		{0x4000, "CLONE_VFORK"}, {0x8000, "CLONE_PARENT"}, {0x10000, "CLONE_THREAD"},
		{0x20000, "CLONE_NEWNS"}, {0x40000, "CLONE_SYSVSEM"}, {0x80000, "CLONE_SETTLS"},
		{0x100000, "CLONE_PARENT_SETTID"}, {0x200000, "CLONE_CHILD_CLEARTID"},
		{0x400000, "CLONE_DETACHED"}, {0x800000, "CLONE_UNTRACED"},
		{0x1000000, "CLONE_CHILD_SETTID"}, {0x2000000, "CLONE_NEWCGROUP"},
		{0x4000000, "CLONE_NEWUTS"}, {0x8000000, "CLONE_NEWIPC"},
		{0x10000000, "CLONE_NEWUSER"}, {0x20000000, "CLONE_NEWPID"},
		{0x40000000, "CLONE_NEWNET"}, {0x80000000, "CLONE_IO"},
	};
	unsigned long long named = v & ~0xffULL;
	int sig = (int)(v & 0xff);

	if (named)
		FLAGS(named, fl, "");
	if (sig)
		out("%s%s", named ? "|" : "", signal_name(sig));
	if (!named && !sig)
		out("0");
}

/* ************************************************************************** */
/*                          IDENTIFIANT CANONIQUE                             */
/* ************************************************************************** */

// Numéro 32 bit -> numéro 64 bit équivalent, pour partager les décodeurs
// -1 si pas d'équivalent (syscall propre au 32 bit: décodage par défaut)
static long canonical_number(long num, int is_64)
{
	static const short map32[][2] = {
		{3, 0}, {4, 1}, {5, 2}, {6, 3}, {197, 5}, {19, 8}, {192, 9},
		{125, 10}, {91, 11}, {45, 12}, {120, 56}, {305, 267}, {122, 63}, {42, 22}, {331, 293}, {307, 269}, {439, 439}, {174, 13}, {175, 14}, {54, 16},
		{180, 17}, {181, 18}, {33, 21}, {163, 25}, {41, 32}, {63, 33},
		{162, 35}, {359, 41}, {362, 42}, {361, 49}, {11, 59}, {1, 60},
		{114, 61}, {37, 62}, {55, 72}, {221, 72}, {183, 79}, {85, 89},
		{99, 137}, {191, 97}, {229, 191}, {230, 192}, {232, 194}, {233, 195},
		{205, 115}, {240, 202}, {422, 202}, {220, 217}, {258, 218}, {267, 230},
		{407, 230}, {252, 231}, {270, 234}, {295, 257}, {300, 262},
		{311, 273}, {330, 292}, {340, 302}, {355, 318}, {383, 332},
		{386, 334},
	};

	if (is_64)
		return num;
	for (size_t i = 0; i < ARRAY_LEN(map32); i++)
		if (map32[i][0] == num)
			return map32[i][1];
	return -1;
}

// Syscalls dont un argument est un buffer/struct rempli par le kernel:
// on l'affiche à la sortie, comme strace (read(3, "\177ELF"..., 832))
static int is_deferred(long id)
{
	return id == 0 || id == 5 || id == 13 || id == 14 || id == 16 || id == 17
		|| id == 56 || id == 61 || id == 63 || id == 79 || id == 89 || id == 97
		|| id == 194 || id == 195 || id == 267 || id == 22 || id == 293
		|| id == 217 || id == 262 || id == 302 || id == 318 || id == 332;
}

/* ************************************************************************** */
/*                              ARGUMENTS                                     */
/* ************************************************************************** */

static void print_syscall_args(t_syscall_info *info, pid_t pid)
{
	unsigned long long *a = info->args;
	int is_64 = info->is_64bit;
	long id = canonical_number(info->number, is_64);

	switch (id) {
		case 0:   // read(fd, buf, count): buf affiché à la sortie
		case 5:   // fstat(fd, statbuf)
		case 17:  // pread64(fd, buf, count, offset)
			print_fd(a[0]);
			out(", ");
			return;

		case 1:   // write(fd, buf, count)
		case 18:  // pwrite64(fd, buf, count, offset)
			print_fd(a[0]);
			out(", ");
			print_buffer(pid, a[1], a[2], 0);
			out(", %llu", a[2]);
			if (id == 18)
				out(", %lld", is_64 ? (long long)a[3] : (long long)(a[3] | (a[4] << 32)));
			return;

		case 2:   // open(path, flags, mode)
			print_path(pid, a[0]);
			out(", ");
			print_open_flags(a[1]);
			if (a[1] & 0x40)
				out(", %#llo", a[2]);
			return;

		case 3:   // close(fd)
		case 32:  // dup(fd)
			print_fd(a[0]);
			return;

		case 33:  // dup2(old, new)
			out("%d, %d", (int)a[0], (int)a[1]);
			return;

		case 292: // dup3(old, new, flags)
			out("%d, %d, %s", (int)a[0], (int)a[1], (a[2] & 0x80000) ? "O_CLOEXEC" : "0");
			return;

		case 8: { // lseek(fd, offset, whence)
			static const t_flag whence[] = {
				{0, "SEEK_SET"}, {1, "SEEK_CUR"}, {2, "SEEK_END"},
				{3, "SEEK_DATA"}, {4, "SEEK_HOLE"},
			};
			print_fd(a[0]);
			out(", %lld, ", is_64 ? (long long)a[1] : (long long)(int)a[1]);
			print_enum((long long)a[2], whence, ARRAY_LEN(whence));
			return;
		}

		case 9: { // mmap / mmap2(addr, len, prot, flags, fd, offset)
			// mmap2 (32 bit) reçoit l'offset en pages de 4096, strace l'affiche en octets
			unsigned long long offset = is_64 ? a[5] : a[5] * 4096ULL;

			print_ptr(a[0]);
			out(", %llu, ", a[1]);
			print_prot(a[2]);
			out(", ");
			print_mmap_flags(a[3]);
			out(", %d, ", (int)a[4]);
			if (offset)
				out("%#llx", offset);
			else
				out("0");
			return;
		}

		case 10:  // mprotect(addr, len, prot)
			out("%#llx, %llu, ", a[0], a[1]);
			print_prot(a[2]);
			return;

		case 11:  // munmap(addr, len)
			out("%#llx, %llu", a[0], a[1]);
			return;

		case 12:  // brk(addr)
			print_ptr(a[0]);
			return;

		case 13:  // rt_sigaction(sig, act, oldact, sigsetsize): oldact à la sortie
			out("%s, ", signal_name((int)a[0]));
			print_sigaction(pid, a[1], is_64);
			out(", ");
			return;

		case 14: { // rt_sigprocmask(how, set, oldset, sigsetsize): oldset à la sortie
			static const t_flag how[] = {
				{0, "SIG_BLOCK"}, {1, "SIG_UNBLOCK"}, {2, "SIG_SETMASK"},
			};
			if (a[0] <= 2)
				print_enum((long long)a[0], how, ARRAY_LEN(how));
			else
				out("%#llx /* SIG_??? */", a[0]);
			out(", ");
			print_sigset(pid, a[1], a[3]);
			out(", ");
			return;
		}

		case 16:  // ioctl(fd, request, arg): arg à la sortie (rempli par le kernel)
			print_fd(a[0]);
			out(", ");
			print_ioctl_request((unsigned int)a[1]);
			out(", ");
			return;

		case 56:  // clone: parent_tid, child_tidptr et tls à la sortie
			out("child_stack=");
			print_ptr(a[1]);
			out(", flags=");
			print_clone_flags(a[0]);
			return;

		case 21:  // access(path, mode)
			print_path(pid, a[0]);
			out(", ");
			print_access_mode(a[1]);
			return;

		case 269: // faccessat(dirfd, path, mode)
		case 439: { // faccessat2(dirfd, path, mode, flags)
			// AT_EACCESS vaut 0x200 comme AT_REMOVEDIR: le sens dépend du syscall
			static const t_flag fl[] = {
				{0x100, "AT_SYMLINK_NOFOLLOW"}, {0x200, "AT_EACCESS"},
				{0x1000, "AT_EMPTY_PATH"},
			};
			print_dirfd(a[0]);
			out(", ");
			print_path(pid, a[1]);
			out(", ");
			print_access_mode(a[2]);
			if (id == 439) {
				out(", ");
				FLAGS(a[3], fl, "0");
			}
			return;
		}

		case 22:  // pipe(fds): le kernel remplit fds, affiché à la sortie
		case 293: // pipe2(fds, flags)
			return;

		case 35:  // nanosleep(req, rem)
			print_ptr(a[0]);
			out(", ");
			print_ptr(a[1]);
			return;

		case 41: { // socket(domain, type, protocol)
			static const t_flag types[] = {
				{1, "SOCK_STREAM"}, {2, "SOCK_DGRAM"}, {3, "SOCK_RAW"},
				{4, "SOCK_RDM"}, {5, "SOCK_SEQPACKET"}, {10, "SOCK_PACKET"},
			};
			static const t_flag fl[] = {{0x80000, "SOCK_CLOEXEC"}, {0x800, "SOCK_NONBLOCK"}};

			print_enum((long long)a[0], g_af, ARRAY_LEN(g_af));
			out(", ");
			print_enum((long long)(a[1] & 0xf), types, ARRAY_LEN(types));
			if (a[1] & ~0xfULL) {
				out("|");
				FLAGS(a[1] & ~0xfULL, fl, "");
			}
			out(", %d", (int)a[2]);
			return;
		}

		case 42:  // connect(fd, addr, len)
		case 49:  // bind(fd, addr, len)
			print_fd(a[0]);
			out(", ");
			print_sockaddr(pid, a[1], a[2]);
			out(", %llu", a[2]);
			return;

		case 59:  // execve(path, argv, envp)
			print_path(pid, a[0]);
			out(", ");
			print_argv(pid, a[1], is_64);
			out(", ");
			print_envp(pid, a[2], is_64);
			return;

		case 60:  // exit(status)
		case 231: // exit_group(status)
			out("%d", (int)a[0]);
			return;

		case 61:  // wait4(pid, status, options, rusage): status à la sortie
			out("%d, ", (int)a[0]);
			return;

		case 115: // getgroups(size, list)
			out("%d, ", (int)a[0]);
			print_ptr(a[1]);
			return;

		case 221: { // fadvise64(fd, offset, len, advice)
			static const t_flag adv[] = {
				{0, "POSIX_FADV_NORMAL"}, {1, "POSIX_FADV_RANDOM"},
				{2, "POSIX_FADV_SEQUENTIAL"}, {3, "POSIX_FADV_WILLNEED"},
				{4, "POSIX_FADV_DONTNEED"}, {5, "POSIX_FADV_NOREUSE"},
			};
			print_fd(a[0]);
			out(", %lld, %lld, ", (long long)a[1], (long long)a[2]);
			print_enum((long long)a[3], adv, ARRAY_LEN(adv));
			return;
		}

		case 62:  // kill(pid, sig)
			out("%d, %s", (int)a[0], signal_name((int)a[1]));
			return;

		case 72: { // fcntl(fd, cmd, arg)
			static const t_flag cmd[] = {
				{0, "F_DUPFD"}, {1, "F_GETFD"}, {2, "F_SETFD"}, {3, "F_GETFL"},
				{4, "F_SETFL"}, {1030, "F_DUPFD_CLOEXEC"},
			};
			print_fd(a[0]);
			out(", ");
			print_enum((long long)a[1], cmd, ARRAY_LEN(cmd));
			if (a[1] == 2)
				out(", %s", a[2] ? "FD_CLOEXEC" : "0");
			else if (a[1] == 4) {
				out(", ");
				print_open_flags(a[2]);
			} else if (a[1] == 0 || a[1] == 1030)
				out(", %d", (int)a[2]);
			return;
		}

		case 79:  // getcwd(buf, size): buf à la sortie
			return;

		case 89:  // readlink(path, buf, size): buf à la sortie
			print_path(pid, a[0]);
			out(", ");
			return;

		case 267: // readlinkat(dirfd, path, buf, size): buf à la sortie
			print_dirfd(a[0]);
			out(", ");
			print_path(pid, a[1]);
			out(", ");
			return;

		case 63:  // uname(buf): rempli par le kernel, affiché à la sortie
			return;

		case 137: // statfs(path, buf)
			print_path(pid, a[0]);
			out(", ");
			print_ptr(a[1]);
			return;

		case 158: { // arch_prctl(code, addr)
			static const t_flag codes[] = {
				{0x1001, "ARCH_SET_GS"}, {0x1002, "ARCH_SET_FS"},
				{0x1003, "ARCH_GET_FS"}, {0x1004, "ARCH_GET_GS"},
				{0x1011, "ARCH_GET_CPUID"}, {0x1012, "ARCH_SET_CPUID"},
			};
			int found = 0;

			for (size_t i = 0; i < ARRAY_LEN(codes); i++) {
				if (codes[i].val == a[0]) {
					out("%s", codes[i].name);
					found = 1;
				}
			}
			if (!found)
				out("%#llx /* ARCH_??? */", a[0]);
			out(", %#llx", a[1]);
			return;
		}

		case 191: // getxattr(path, name, value, size)
		case 192: // lgetxattr
			print_path(pid, a[0]);
			out(", ");
			print_cstring(pid, a[1], MAX_STRLEN);
			out(", ");
			print_ptr(a[2]);
			out(", %llu", a[3]);
			return;

		case 194: // listxattr(path, list, size): list à la sortie
		case 195: // llistxattr
			print_path(pid, a[0]);
			out(", ");
			return;

		case 97:  // getrlimit / ugetrlimit(resource, rlim): rlim à la sortie
			print_rlimit_resource(a[0]);
			out(", ");
			return;

		case 202: { // futex(uaddr, op, val, timeout, uaddr2, val3)
			static const char *ops[] = {
				"FUTEX_WAIT", "FUTEX_WAKE", "FUTEX_FD", "FUTEX_REQUEUE",
				"FUTEX_CMP_REQUEUE", "FUTEX_WAKE_OP", "FUTEX_LOCK_PI",
				"FUTEX_UNLOCK_PI", "FUTEX_TRYLOCK_PI", "FUTEX_WAIT_BITSET",
				"FUTEX_WAKE_BITSET", "FUTEX_WAIT_REQUEUE_PI", "FUTEX_CMP_REQUEUE_PI",
				"FUTEX_LOCK_PI2",
			};
			unsigned int cmd = a[1] & 0x7f;

			out("%#llx, ", a[0]);
			if (cmd < ARRAY_LEN(ops))
				out("%s%s", ops[cmd], (a[1] & 0x80) ? "_PRIVATE" : "");
			else
				out("%#llx", a[1] & ~0x180ULL);
			if (a[1] & 0x100)
				out("|FUTEX_CLOCK_REALTIME");
			out(", %d", (int)a[2]);
			if (cmd == 0 || cmd == 9) {        // WAIT, WAIT_BITSET: timeout
				out(", ");
				print_ptr(a[3]);
				if (cmd == 9) {
					if ((unsigned int)a[5] == 0xffffffff)
						out(", FUTEX_BITSET_MATCH_ANY");
					else
						out(", %#x", (unsigned int)a[5]);
				}
			} else if (cmd != 1 && cmd != 10) { // autres: tous les arguments
				for (int i = 3; i < 6; i++) {
					out(", ");
					print_default_arg(a[i], is_64);
				}
			}
			return;
		}

		case 217: // getdents64(fd, dirp, count): nombre d'entrées à la sortie
			print_fd(a[0]);
			out(", ");
			return;

		case 218: // set_tid_address(tidptr)
			out("%#llx", a[0]);
			return;

		case 230: { // clock_nanosleep(clockid, flags, req, rem)
			static const t_flag clocks[] = {
				{0, "CLOCK_REALTIME"}, {1, "CLOCK_MONOTONIC"},
				{2, "CLOCK_PROCESS_CPUTIME_ID"}, {3, "CLOCK_THREAD_CPUTIME_ID"},
				{7, "CLOCK_BOOTTIME"},
			};
			print_enum((long long)a[0], clocks, ARRAY_LEN(clocks));
			out(", %s, ", a[1] ? "TIMER_ABSTIME" : "0");
			print_ptr(a[2]);
			out(", ");
			print_ptr(a[3]);
			return;
		}

		case 234: // tgkill(tgid, tid, sig)
			out("%d, %d, %s", (int)a[0], (int)a[1], signal_name((int)a[2]));
			return;

		case 257: // openat(dirfd, path, flags, mode)
			print_dirfd(a[0]);
			out(", ");
			print_path(pid, a[1]);
			out(", ");
			print_open_flags(a[2]);
			if (a[2] & 0x40)
				out(", %#llo", a[3]);
			return;

		case 262: // newfstatat(dirfd, path, statbuf, flags): statbuf à la sortie
			print_dirfd(a[0]);
			out(", ");
			print_path(pid, a[1]);
			out(", ");
			return;

		case 273: // set_robust_list(head, len)
			out("%#llx, %llu", a[0], a[1]);
			return;

		case 302: // prlimit64(pid, resource, new_limit, old_limit): old_limit à la sortie
			out("%d, ", (int)a[0]);
			print_rlimit_resource(a[1]);
			out(", ");
			print_rlimit(pid, a[2], 8, "RLIM64_INFINITY");
			out(", ");
			return;

		case 318: // getrandom(buf, len, flags): buf à la sortie
			return;

		case 332: // statx(dirfd, path, flags, mask, statxbuf): statxbuf à la sortie
			print_dirfd(a[0]);
			out(", ");
			print_path(pid, a[1]);
			out(", ");
			// Mode de synchro par défaut: strace l'affiche explicitement
			if (!(a[2] & 0x6000)) {
				out("AT_STATX_SYNC_AS_STAT");
				if (a[2])
					out("|");
			}
			if (a[2])
				FLAGS(a[2], g_at_flags, "0");
			out(", ");
			print_statx_mask(a[3]);
			out(", ");
			return;

		case 334: // rseq(rseq, len, flags, sig)
			out("%#llx, %#llx, %d, %#llx", a[0], a[1], (int)a[2], a[3]);
			return;
	}

	// Affichage par défaut
	for (int i = 0; i < info->arg_count; i++) {
		if (i > 0)
			out(", ");
		print_default_arg(a[i], is_64);
	}
}

// Fin des arguments différés, une fois que le kernel a rempli les buffers
static void print_deferred_args(t_syscall_info *info, pid_t pid)
{
	unsigned long long *a = info->args;
	int is_64 = info->is_64bit;
	long long ret = info->ret_val;
	int failed = ret < 0 && ret >= -4095;
	long id = canonical_number(info->number, is_64);

	switch (id) {
		case 0:   // read
		case 17:  // pread64
			if (failed)
				out("%#llx", a[1]);
			else
				print_buffer(pid, a[1], (unsigned long long)ret, 0);
			out(", %llu", a[2]);
			if (id == 17)
				out(", %lld", is_64 ? (long long)a[3] : (long long)(a[3] | (a[4] << 32)));
			return;

		case 5:   // fstat
			if (failed)
				print_ptr(a[1]);
			else
				print_stat(pid, a[1], is_64);
			return;

		case 262: // newfstatat
			if (failed)
				print_ptr(a[2]);
			else
				print_stat(pid, a[2], is_64);
			out(", ");
			FLAGS(a[3], g_at_flags, "0");
			return;

		case 318: { // getrandom
			static const t_flag fl[] = {
				{1, "GRND_NONBLOCK"}, {2, "GRND_RANDOM"}, {4, "GRND_INSECURE"},
			};
			if (failed)
				out("%#llx", a[0]);
			else
				print_buffer(pid, a[0], (unsigned long long)ret, 1);
			out(", %llu, ", a[1]);
			FLAGS(a[2], fl, "0");
			return;
		}

		case 332: // statx
			if (failed)
				print_ptr(a[4]);
			else
				print_statx(pid, a[4]);
			return;

		case 79:  // getcwd
			if (failed)
				print_ptr(a[0]);
			else
				print_cstring(pid, a[0], MAX_PATHLEN);
			out(", %llu", a[1]);
			return;

		case 61: { // wait4: statut décodé comme strace
			static const t_flag opts[] = {
				{1, "WNOHANG"}, {2, "WUNTRACED"}, {8, "WCONTINUED"},
				{0x20000000, "__WNOTHREAD"}, {0x40000000, "__WALL"},
				{0x80000000, "__WCLONE"},
			};
			int st;

			if (failed || ret == 0 || !a[1] || read_mem(pid, a[1], &st, sizeof(st)) != sizeof(st))
				print_ptr(a[1]);
			else if (WIFEXITED(st))
				out("[{WIFEXITED(s) && WEXITSTATUS(s) == %d}]", WEXITSTATUS(st));
			else if (WIFSIGNALED(st))
				out("[{WIFSIGNALED(s) && WTERMSIG(s) == %s%s}]", signal_name(WTERMSIG(st)),
					WCOREDUMP(st) ? " && WCOREDUMP(s)" : "");
			else if (WIFSTOPPED(st))
				out("[{WIFSTOPPED(s) && WSTOPSIG(s) == %s}]", signal_name(WSTOPSIG(st)));
			else
				out("[%#x]", st);
			out(", ");
			FLAGS(a[2] & 0xffffffff, opts, "0");
			out(", ");
			print_ptr(a[3]);
			return;
		}

		case 97:  // getrlimit / ugetrlimit
			if (failed)
				print_ptr(a[1]);
			else
				print_rlimit(pid, a[1], is_64 ? 8 : 4, "RLIM_INFINITY");
			return;

		case 302: // prlimit64
			if (failed)
				print_ptr(a[3]);
			else
				print_rlimit(pid, a[3], 8, "RLIM64_INFINITY");
			return;

		case 13:  // rt_sigaction: oldact rempli par le kernel
			if (failed)
				print_ptr(a[2]);
			else
				print_sigaction(pid, a[2], is_64);
			out(", %llu", a[3]);
			return;

		case 14:  // rt_sigprocmask: oldset rempli par le kernel
			if (failed)
				print_ptr(a[2]);
			else
				print_sigset(pid, a[2], a[3]);
			out(", %llu", a[3]);
			return;

		case 16:  // ioctl
			print_ioctl_arg(pid, (unsigned int)a[1], a[2], failed);
			return;

		case 56: { // clone(flags, stack, parent_tid, child_tid, tls), i386: tls avant child_tid
			unsigned long long ctid = is_64 ? a[3] : a[4];
			unsigned long long tls = is_64 ? a[4] : a[3];

			// parent_tid: le kernel y écrit le tid de l'enfant (ou le pidfd)
			if (a[0] & (0x100000 | 0x1000)) {
				out(", parent_tid=");
				if (failed)
					print_ptr(a[2]);
				else
					print_int_ptr(pid, a[2]);
			}
			if (a[0] & (0x1000000 | 0x200000)) {
				out(", child_tidptr=");
				print_ptr(ctid);
			}
			if (a[0] & 0x80000)
				out(", tls=%#llx", tls);
			return;
		}

		case 63: { // uname: struct utsname = 6 chaînes de 65 octets, strace en montre 2
			char uts[2][65];

			if (failed || read_mem(pid, a[0], uts, sizeof(uts)) != (ssize_t)sizeof(uts)) {
				print_ptr(a[0]);
				return;
			}
			uts[0][64] = '\0';
			uts[1][64] = '\0';
			out("{sysname=\"%s\", nodename=\"%s\", ...}", uts[0], uts[1]);
			return;
		}

		case 89:  // readlink: buf non terminé par '\0', ret = longueur écrite
		case 267: { // readlinkat
			unsigned long long buf = id == 89 ? a[1] : a[2];
			unsigned long long size = id == 89 ? a[2] : a[3];

			if (failed)
				print_ptr(buf);
			else
				print_buffer(pid, buf, (unsigned long long)ret, 0);
			out(", %llu", size);
			return;
		}

		case 22:  // pipe
		case 293: { // pipe2
			static const t_flag fl[] = {
				{0x800, "O_NONBLOCK"}, {0x80000, "O_CLOEXEC"}, {0x4000, "O_DIRECT"},
			};
			int fds[2];

			if (failed || read_mem(pid, a[0], fds, sizeof(fds)) != (ssize_t)sizeof(fds))
				print_ptr(a[0]);
			else
				out("[%d, %d]", fds[0], fds[1]);
			if (id == 293) {
				out(", ");
				FLAGS(a[1], fl, "0");
			}
			return;
		}

		case 194: // listxattr
		case 195: // llistxattr
			if (failed)
				print_ptr(a[1]);
			else
				print_buffer(pid, a[1], (unsigned long long)ret, 0);
			out(", %llu", a[2]);
			return;

		case 217: { // getdents64
			int n = failed ? -1 : count_dirents(pid, a[1], ret);

			if (n >= 0)
				out("%#llx /* %d entr%s */", a[1], n, n == 1 ? "y" : "ies");
			else
				out("%#llx", a[1]);
			out(", %llu", a[2]);
			return;
		}
	}
}

void print_syscall_enter(t_syscall_info *info, pid_t pid)
{
	g_col = 0;
	if (info->name == NULL) {
		out("syscall_%ld(", info->number);
	} else {
		out("%s(", info->name);
	}

	print_syscall_args(info, pid);
	g_line_open = 1;
}

/* ************************************************************************** */
/*                             VALEUR DE RETOUR                               */
/* ************************************************************************** */

#define E(x) [x] = #x

// Nom symbolique de l'errno (strerror ne donne que la description)
static const char *errno_name(int err)
{
	static const char *names[] = {
		E(EPERM), E(ENOENT), E(ESRCH), E(EINTR), E(EIO), E(ENXIO), E(E2BIG),
		E(ENOEXEC), E(EBADF), E(ECHILD), E(EAGAIN), E(ENOMEM), E(EACCES),
		E(EFAULT), E(ENOTBLK), E(EBUSY), E(EEXIST), E(EXDEV), E(ENODEV),
		E(ENOTDIR), E(EISDIR), E(EINVAL), E(ENFILE), E(EMFILE), E(ENOTTY),
		E(ETXTBSY), E(EFBIG), E(ENOSPC), E(ESPIPE), E(EROFS), E(EMLINK),
		E(EPIPE), E(EDOM), E(ERANGE), E(EDEADLK), E(ENAMETOOLONG), E(ENOLCK),
		E(ENOSYS), E(ENOTEMPTY), E(ELOOP), E(ENOMSG), E(EIDRM), E(ECHRNG),
		E(EL2NSYNC), E(EL3HLT), E(EL3RST), E(ELNRNG), E(EUNATCH), E(ENOCSI),
		E(EL2HLT), E(EBADE), E(EBADR), E(EXFULL), E(ENOANO), E(EBADRQC),
		E(EBADSLT), E(EBFONT), E(ENOSTR), E(ENODATA), E(ETIME), E(ENOSR),
		E(ENONET), E(ENOPKG), E(EREMOTE), E(ENOLINK), E(EADV), E(ESRMNT),
		E(ECOMM), E(EPROTO), E(EMULTIHOP), E(EDOTDOT), E(EBADMSG), E(EOVERFLOW),
		E(ENOTUNIQ), E(EBADFD), E(EREMCHG), E(ELIBACC), E(ELIBBAD), E(ELIBSCN),
		E(ELIBMAX), E(ELIBEXEC), E(EILSEQ), E(ERESTART), E(ESTRPIPE), E(EUSERS),
		E(ENOTSOCK), E(EDESTADDRREQ), E(EMSGSIZE), E(EPROTOTYPE), E(ENOPROTOOPT),
		E(EPROTONOSUPPORT), E(ESOCKTNOSUPPORT), E(EOPNOTSUPP), E(EPFNOSUPPORT),
		E(EAFNOSUPPORT), E(EADDRINUSE), E(EADDRNOTAVAIL), E(ENETDOWN),
		E(ENETUNREACH), E(ENETRESET), E(ECONNABORTED), E(ECONNRESET), E(ENOBUFS),
		E(EISCONN), E(ENOTCONN), E(ESHUTDOWN), E(ETOOMANYREFS), E(ETIMEDOUT),
		E(ECONNREFUSED), E(EHOSTDOWN), E(EHOSTUNREACH), E(EALREADY),
		E(EINPROGRESS), E(ESTALE), E(EUCLEAN), E(ENOTNAM), E(ENAVAIL), E(EISNAM),
		E(EREMOTEIO), E(EDQUOT), E(ENOMEDIUM), E(EMEDIUMTYPE), E(ECANCELED),
		E(ENOKEY), E(EKEYEXPIRED), E(EKEYREVOKED), E(EKEYREJECTED),
		E(EOWNERDEAD), E(ENOTRECOVERABLE), E(ERFKILL), E(EHWPOISON),
	};

	if (err > 0 && err < (int)ARRAY_LEN(names))
		return names[err];
	return NULL;
}

#undef E

// ") " puis espaces jusqu'à la colonne 40, puis "= " (même algo que strace)
static void print_ret_separator(void)
{
	out(") ");
	if (g_col < RET_COLUMN)
		out("%*s", RET_COLUMN - g_col, "");
	out("= ");
}

// Syscall sans retour (exit_group, process tué en plein syscall)
void print_syscall_unfinished(void)
{
	print_ret_separator();
	out("?\n");
	g_line_open = 0;
}

void print_syscall_exit(t_syscall_info *info, pid_t pid)
{
	long long ret = info->ret_val;
	long id = canonical_number(info->number, info->is_64bit);

	if (is_deferred(id))
		print_deferred_args(info, pid);
	print_ret_separator();
	g_line_open = 0;  // le "\n" final suit dans tous les cas

	if (ret < 0 && ret >= -4095) {
		int err = (int)-ret;
		const char *name = errno_name(err);

		// Codes internes au kernel (syscall interrompu par un signal), jamais vus par le programme
		static const char *restart[][2] = {
			{"ERESTARTSYS", "To be restarted if SA_RESTART is set"},
			{"ERESTARTNOINTR", "To be restarted"},
			{"ERESTARTNOHAND", "To be restarted if no handler"},
			{"ENOIOCTLCMD", "No ioctl command"},
			{"ERESTART_RESTARTBLOCK", "Interrupted by signal"},
		};
		if (err >= 512 && err <= 516)
			out("? %s (%s)\n", restart[err - 512][0], restart[err - 512][1]);
		else if (name)
			out("-1 %s (%s)\n", name, strerror(err));
		else
			out("-1 ERRNO_%d (%s)\n", err, strerror(err));
		return;
	}

	// fcntl F_GETFD / F_GETFL: le retour est un jeu de flags, décodé comme strace
	if (id == 72 && info->args[1] == 1 && ret != 0) {
		out("%#llx (flags %s)\n", ret, ret == 1 ? "FD_CLOEXEC" : "?");
		return;
	}
	if (id == 72 && info->args[1] == 3) {
		out("%#llx (flags ", ret);
		print_open_flags((unsigned long long)ret);
		out(")\n");
		return;
	}

	// Adresses en hexa (brk, mmap, mremap, shmat), tout le reste en décimal
	if (id == 9 || id == 12 || id == 25 || id == 30) {
		if (info->is_64bit)
			out("%#llx\n", (unsigned long long)ret);
		else
			out("%#x\n", (unsigned int)ret);
	} else {
		out("%lld\n", ret);
	}
}
