#!/bin/bash

# Script de comparaison multiple ft_strace vs strace
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Fonction de comparaison
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

# Sinon, tests automatiques
# Test 1: Binaire simple 64-bit
compare_test "Binaire 64-bit simple" /bin/echo "Hello 42"

# Test 2: Commande avec arguments
compare_test "Commande avec args" /bin/ls -l /tmp

# Test 3: Binaire 64-bit (test compilé)
if [ -f "./test64" ]; then
    compare_test "Test binaire 64-bit" ./test64
fi

# Test 4: Binaire 32-bit (test compilé)
if [ -f "./test32" ]; then
    compare_test "Test binaire 32-bit" ./test32
fi

# Test 5: Commande avec redirection
compare_test "Cat fichier" /bin/cat /etc/hostname

# Test 6: Commande rapide
compare_test "True (exit rapide)" /bin/true

# Test 7: PWD
compare_test "PWD" /bin/pwd

# Test 8: Programme inexistant (erreur)
compare_test "Programme inexistant" /nonexistent

echo -e "\n${GREEN}✓ Tests terminés${NC}"
