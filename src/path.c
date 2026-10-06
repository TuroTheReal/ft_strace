#include "ft_strace.h"

char *find_in_path(const char *cmd)
{
	char *path_env;
	char *path_copy;
	char *dir;
	char *full_path;
	size_t len;
	struct stat st;

	if (!cmd[0])
		return NULL;
	path_env = getenv("PATH");
	if (!path_env)
		return NULL;

	path_copy = strdup(path_env);
	if (!path_copy)
		return NULL;

	dir = strtok(path_copy, ":");
	while (dir) {
		len = strlen(dir) + strlen(cmd) + 2;
		full_path = malloc(len);
		if (!full_path) {
			free(path_copy);
			return NULL;
		}

		snprintf(full_path, len, "%s/%s", dir, cmd);

		// Un dossier est aussi "exécutable" (X_OK): on exige un fichier régulier
		if (access(full_path, X_OK) == 0 && stat(full_path, &st) == 0
			&& S_ISREG(st.st_mode)) {
			free(path_copy);
			return full_path;
		}

		free(full_path);
		dir = strtok(NULL, ":");
	}

	free(path_copy);
	return NULL;
}