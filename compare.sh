#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Commande par défaut ou argument
CMD="${@:-/bin/echo test}"

# Capturer les sorties
FT_OUT=$(./ft_strace $CMD 2>&1 | head -15)
REAL_OUT=$(strace $CMD 2>&1 | head -15)

# Affichage côte à côte
echo -e "${GREEN}FT_STRACE${NC} │ ${YELLOW}STRACE (original)${NC}"
echo "──────────────────────────────────────────────────────│──────────────────────────────────────────────────────"

# save -> fichiers tmp
echo "$FT_OUT" > /tmp/ft.txt
echo "$REAL_OUT" > /tmp/real.txt

# ligne par ligne + it
paste <(cat /tmp/ft.txt | nl -w2 -s': ') <(cat /tmp/real.txt | nl -w2 -s': ') | \
    awk -F'\t' '{printf "%-54s │ %s\n", $1, $2}'

# Cleanup
rm -f /tmp/ft.txt /tmp/real.txt
