#!/bin/bash
# ============================================================================
# test.sh - Tests simples pour ft_strace (a lancer SUR UNE MACHINE LINUX)
# ----------------------------------------------------------------------------
# Verifie les points de correction du sujet :
#   0. compilation
#   1. seules les options ptrace AUTORISEES sont utilisees
#   2. trace 64 bits
#   3. trace 32 bits
#   4. affichage des signaux (le point cle du sujet)
#   5. bonus -c
#   6. bonus PATH
#   7. pas de crash sur entree invalide
# Comparaison optionnelle avec le vrai strace en fin de script.
#
# Usage : depuis la racine du repo -> ./test.sh
# ============================================================================

set -u  # erreur si on utilise une variable non definie

# Couleurs
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

FT=./ft_strace     # binaire a tester
PASS=0; FAIL=0     # compteurs de resultats

# Helpers d'affichage
ok()    { echo -e "  ${GREEN}[OK]${NC} $1";   PASS=$((PASS+1)); return 0; }
ko()    { echo -e "  ${RED}[KO]${NC} $1";     FAIL=$((FAIL+1)); return 0; }
skip()  { echo -e "  ${YELLOW}[SKIP]${NC} $1"; }
title() { echo -e "\n${YELLOW}== $1 ==${NC}"; }

# Nettoyage des fichiers temporaires en sortie
cleanup() { rm -f /tmp/ft_hello32 /tmp/ft_hello32.c /tmp/ft_sig.out; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 0. Pre-requis
# ---------------------------------------------------------------------------
if [ "$(uname -s)" != "Linux" ]; then
	echo -e "${RED}Ce script doit tourner sur Linux (ptrace requis).${NC}"; exit 1
fi

title "0. Compilation"
if make re >/dev/null 2>&1 && [ -x "$FT" ]; then
	ok "make re produit ./ft_strace"
else
	ko "make re a echoue"; exit 1
fi

# ---------------------------------------------------------------------------
# 1. Conformite sujet : AUCUNE option ptrace hors de la liste autorisee
#    Autorisees : SYSCALL, GETREGSET, SETOPTIONS, GETSIGINFO, SEIZE,
#                 INTERRUPT, LISTEN
#    Interdits typiques : TRACEME, ATTACH, CONT, PEEK*, POKE*, GETREGS
#                 (seul GETREGSET est permis), SETREGS, SINGLESTEP, KILL
# ---------------------------------------------------------------------------
title "1. Options ptrace (conformite sujet)"
INTERDITS='PTRACE_TRACEME|PTRACE_ATTACH|PTRACE_CONT|PTRACE_PEEKTEXT|PTRACE_PEEKDATA|PTRACE_PEEKUSER|PTRACE_POKETEXT|PTRACE_POKEDATA|PTRACE_POKEUSER|PTRACE_GETREGS\b|PTRACE_SETREGS|PTRACE_SINGLESTEP|PTRACE_KILL'
if grep -rEn "$INTERDITS" src/ >/dev/null 2>&1; then
	ko "option ptrace INTERDITE trouvee :"
	grep -rEn "$INTERDITS" src/ | sed 's/^/       /'
else
	ok "aucune option ptrace interdite dans src/"
fi
echo "     options utilisees :"
grep -rhoE 'PTRACE_[A-Z_]+' src/ | grep -v '^PTRACE_O_' | sort -u | sed 's/^/       /'

# ---------------------------------------------------------------------------
# 2. Trace 64 bits : execve visible, ligne de sortie presente, pas d'erreur
# ---------------------------------------------------------------------------
title "2. Trace 64 bits"
OUT=$($FT /bin/echo bonjour 2>&1)
echo "$OUT" | grep -q "execve"                && ok "execve present"          || ko "execve absent"
echo "$OUT" | grep -q "+++ exited with 0 +++" && ok "'+++ exited with 0 +++'" || ko "ligne de sortie absente"
echo "$OUT" | grep -q "ptrace SEIZE"          && skip "SEIZE refuse -> verifie /proc/sys/kernel/yama/ptrace_scope"

# ---------------------------------------------------------------------------
# 3. Trace 32 bits : on compile un mini binaire -m32 si le toolchain existe
# ---------------------------------------------------------------------------
title "3. Trace 32 bits"
printf '#include <unistd.h>\nint main(void){write(1,"hi\\n",3);return 0;}\n' > /tmp/ft_hello32.c
if gcc -m32 -o /tmp/ft_hello32 /tmp/ft_hello32.c 2>/dev/null; then
	OUT=$($FT /tmp/ft_hello32 2>&1)
	echo "$OUT" | grep -q "32 bit mode" && ok "message '32 bit mode' affiche"     || ko "message 32 bits absent"
	echo "$OUT" | grep -q "+++ exited"  && ok "trace 32 bits complete (exit)"     || ko "trace 32 bits incomplete"
else
	skip "gcc -m32 indisponible (installe gcc-multilib / libc6-dev-i386)"
fi

# ---------------------------------------------------------------------------
# 4. Signaux (LE point cle du sujet)
#    On trace un sleep, on envoie SIGTERM au process trace : ft_strace doit
#    afficher '--- SIGTERM ---' puis '+++ killed by SIGTERM +++', SANS
#    couper le trace sur une erreur ptrace (regression du double-resume).
# ---------------------------------------------------------------------------
title "4. Signaux"
$FT /bin/sleep 30 >/tmp/ft_sig.out 2>&1 &
FTPID=$!
sleep 1
CHILD=$(pgrep -P "$FTPID" 2>/dev/null | head -n1)   # le process trace (sleep)
if [ -n "$CHILD" ]; then
	kill -TERM "$CHILD" 2>/dev/null
	wait "$FTPID" 2>/dev/null
	grep -q -- "--- SIGTERM"        /tmp/ft_sig.out && ok "'--- SIGTERM ---' affiche"        || ko "signal non affiche"
	grep -q "killed by SIGTERM"     /tmp/ft_sig.out && ok "'+++ killed by SIGTERM +++'"      || ko "mort par signal non affichee"
	grep -q "ptrace SYSCALL"        /tmp/ft_sig.out && ko "erreur 'ptrace SYSCALL' (regression du double-resume)" || ok "aucune erreur ptrace (bug corrige)"
else
	ko "process trace introuvable (pgrep)"
	kill -KILL "$FTPID" 2>/dev/null
fi

# ---------------------------------------------------------------------------
# 5. Bonus -c : tableau de stats avec colonnes + ligne total
# ---------------------------------------------------------------------------
title "5. Bonus -c"
OUT=$($FT -c /bin/echo test 2>&1)
if echo "$OUT" | grep -q "syscall" && echo "$OUT" | grep -q "total"; then
	ok "tableau -c present (colonnes + total)"
else
	ko "sortie -c invalide"
fi

# ---------------------------------------------------------------------------
# 6. Bonus PATH : commande sans '/' resolue via $PATH
# ---------------------------------------------------------------------------
title "6. Bonus PATH"
OUT=$($FT ls /tmp 2>&1)
echo "$OUT" | grep -q "execve" && ok "'ls' resolu via PATH" || ko "PATH non gere"

# ---------------------------------------------------------------------------
# 7. Gestion d'erreur : pas de crash (segfault=139, abort=134)
# ---------------------------------------------------------------------------
title "7. Gestion d'erreur (pas de crash)"
$FT /binaire_inexistant >/dev/null 2>&1; RC=$?
{ [ $RC -ne 139 ] && [ $RC -ne 134 ]; } && ok "binaire introuvable gere (rc=$RC)" || ko "crash (rc=$RC)"
$FT >/dev/null 2>&1; RC=$?
[ $RC -ne 0 ] && ok "sans argument : usage + code != 0 (rc=$RC)" || ko "sans argument mal gere"

# ---------------------------------------------------------------------------
# Comparaison visuelle avec le vrai strace (optionnel, jamais appele par ft_strace)
# ---------------------------------------------------------------------------
title "Comparaison avec strace (optionnel)"
if command -v strace >/dev/null 2>&1; then
	echo "  --- ft_strace /bin/true (3 dernieres lignes) ---"
	$FT /bin/true 2>&1 | tail -n3 | sed 's/^/     /'
	echo "  --- strace /bin/true (3 dernieres lignes) ---"
	strace /bin/true 2>&1 | tail -n3 | sed 's/^/     /'
else
	skip "strace non installe"
fi

# ---------------------------------------------------------------------------
# Bilan
# ---------------------------------------------------------------------------
echo -e "\n${YELLOW}== Bilan ==${NC}  ${GREEN}${PASS} OK${NC} / ${RED}${FAIL} KO${NC}"
[ "$FAIL" -eq 0 ]
