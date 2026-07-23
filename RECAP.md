# ft_strace — récap express

## À quoi ça sert
Recoder `strace` : on lance une commande, et le programme affiche en direct **tous les
syscalls** qu'elle fait (avec arguments et valeur de retour) + **les signaux** qu'elle reçoit.
C'est un outil d'observation/debug bas niveau.

## Pourquoi
Comprendre `ptrace`, l'interface syscall (registres, numéros, ABI), les conventions
**x86_64 / i386**, la gestion des **signaux**, et la relation tracer / tracee.

## Comment ça marche (le flux)
1. **main.c** : lit l'option `-c`, puis appelle `start_trace`.
2. **start_trace** (tracer.c) :
   - résout la commande via `$PATH` si pas de `/` (path.c) ;
   - `fork()` : l'enfant se bloque sur un `read()` de pipe (il attend) ;
   - le parent s'attache avec **PTRACE_SEIZE** (pas `TRACEME`, interdit), synchronise avec
     **PTRACE_INTERRUPT** / **PTRACE_LISTEN**, débloque le pipe → l'enfant fait `execve`.
3. **trace_loop** (tracer.c) : la boucle
   - **PTRACE_SYSCALL** → avance jusqu'au prochain arrêt (entrée OU sortie de syscall) ;
   - **PTRACE_GETREGSET** → lit les registres ; la *taille renvoyée* dit **64 ou 32 bits** ;
   - **entrée** : décode numéro + args (syscall_info.c, syscall_args.c, tables syscalls_64/32.c)
     et affiche (print.c) ;
   - **sortie** : affiche la valeur de retour, ou `-1 ERRNO (message)` en cas d'erreur ;
   - **signal reçu** → l'affiche (`--- SIGxxx ---`) et le relaie au process ;
   - **fin** : `+++ exited with N +++` ou `+++ killed by SIGxxx +++` ;
   - **`-c`** : au lieu d'afficher chaque ligne, agrège les stats (stats.c) et imprime un
     tableau récap à la fin (façon `strace -c`).

## Les outils (et pourquoi)
| Outil | Rôle |
|---|---|
| `PTRACE_SEIZE` / `INTERRUPT` / `LISTEN` | attacher et synchroniser sans `TRACEME` |
| `PTRACE_SYSCALL` | avancer syscall par syscall |
| `PTRACE_GETREGSET` | lire les registres + détecter l'archi (taille du regset) |
| `PTRACE_GETSIGINFO` | détails du signal reçu |
| `PTRACE_SETOPTIONS` (via SEIZE) | `TRACESYSGOOD` (marque les syscall-stops), `EXITKILL` |
| `/proc/PID/mem` | lire les chaînes du process tracé (car `PEEKDATA` interdit) |
| `waitpid` + macros `WIF*` | savoir pourquoi le process s'est arrêté |

## Pièges / caveats
- **Liste ptrace fermée (sujet).** Interdits : `TRACEME`, `ATTACH`, `CONT`, `PEEK*`, `POKE*`,
  `GETREGS`/`SETREGS`, `SINGLESTEP`. D'où le montage `SEIZE` + `/proc/PID/mem`.
- **32 ET 64 bits obligatoires.** Détection par la **taille du regset** (216 vs 68 octets),
  struct i386 dédiée, extension de signe du retour sur 32 bits, message `runs in 32 bit mode`.
  (Repère : `cs = 0x23` → 32 bits, `cs = 0x33` → 64 bits.)
- **Signaux = le point sensible du sujet.** Il faut les **afficher** ET les **relayer**.
  Ne PAS réinjecter un signal d'arrêt (`SIGSTOP`…) sinon boucle. **Un seul `PTRACE_SYSCALL`
  par tour**, sinon erreur `ESRCH` qui coupe le trace.
- **Sortie sur stdout** ici (le vrai strace écrit sur stderr) : toléré par le sujet
  (*« display close, not exact »*), mais penser au `fflush(stdout)` pour l'ordre en pipe.
- **Démarrage un peu racy** (`usleep` + skip des 2 syscalls du pipe) : simple mais dépend
  du timing.
- **Bonus (`-c`, PATH) notés uniquement si le mandatory est PARFAIT.**

## Tester
```sh
make re      # voir d'eventuels warnings -Werror
./test.sh    # suite complete : ptrace autorises, 64/32 bits, signaux, -c, PATH, no-crash
```
