// pipe/pipe2 (fd rendus par le kernel, affichés à la sortie) et faccessat/faccessat2
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

int main(void)
{
	int p[2];

	pipe(p);
	pipe2(p, O_CLOEXEC);
	pipe2(p, O_CLOEXEC | O_NONBLOCK);
	syscall(SYS_pipe2, 1, 0);  // pointeur invalide: EFAULT, adresse brute
	syscall(SYS_faccessat2, AT_FDCWD, "/etc/passwd", R_OK, AT_EACCESS);
	syscall(SYS_faccessat2, AT_FDCWD, "/nope", X_OK, 0);
	syscall(SYS_faccessat2, 3, "x", F_OK, AT_SYMLINK_NOFOLLOW | AT_EACCESS);
	syscall(SYS_faccessat, AT_FDCWD, "/etc", W_OK | R_OK);
	return 0;
}
