#include "ft_strace.h"

// Construit "dir/cmd". Entrée vide du PATH = dossier courant (comme execvp et strace)
static char *join_path(const char *dir, size_t dir_len, const char *cmd)
{
	char cwd[4096];
	char *full_path;
	size_t len;

	if (dir_len == 0) {
		if (!getcwd(cwd, sizeof(cwd)))
			return NULL;
		dir = cwd;
		dir_len = strlen(cwd);
	}
	len = dir_len + strlen(cmd) + 2;
	full_path = malloc(len);
	if (!full_path)
		return NULL;
	snprintf(full_path, len, "%.*s/%s", (int)dir_len, dir, cmd);
	return full_path;
}

char *find_in_path(const char *cmd)
{
	const char *dir;
	const char *end;
	char *full_path;
	struct stat st;

	if (!cmd[0])
		return NULL;
	dir = getenv("PATH");
	if (!dir)
		return NULL;

	// Découpage manuel: strtok sauterait les entrées vides ("::" ou ":" en bord)
	while (1) {
		end = strchr(dir, ':');
		if (!end)
			end = dir + strlen(dir);

		full_path = join_path(dir, (size_t)(end - dir), cmd);
		// Un dossier est aussi "exécutable" (X_OK): on exige un fichier régulier
		if (full_path && access(full_path, X_OK) == 0 && stat(full_path, &st) == 0
			&& S_ISREG(st.st_mode))
			return full_path;
		free(full_path);

		if (*end == '\0')
			break;
		dir = end + 1;
	}
	return NULL;
}
