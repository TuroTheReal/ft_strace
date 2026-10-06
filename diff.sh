#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

compare_test() {
    local name="$1"
    shift
    local cmd="$@"

    echo -e "\n${BLUE}━━━ TEST: $name ━━━${NC}"
    echo -e "${YELLOW}Commande: $cmd${NC}\n"

    echo -e "${GREEN}[FT_STRACE]${NC}"
    ./ft_strace $cmd 2>&1 | head -8

    echo -e "\n${BLUE}[STRACE]${NC}"
    strace $cmd 2>&1 | head -8

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Si argument fourni, tester uniquement cette commande
if [ $# -gt 0 ]; then
    compare_test "Custom" "$@"
    exit 0
fi

# Sinon, tests auto
# 64-bit
compare_test "Binaire 64-bit" /bin/echo "Hello 42"

# Commande avec arg
compare_test "Commande avec args" /bin/ls -l /tmp

# 32-bit
if [ -f "./test_32" ]; then
    compare_test "Test binaire 32-bit" ./test_32
fi

# redirection
compare_test "Cat fichier" /bin/cat /etc/hostname

# rapide
compare_test "True (exit rapide)" /bin/true

# PWD
compare_test "PWD" /bin/pwd

echo -e "\n${GREEN}✓ Tests terminés${NC}"
