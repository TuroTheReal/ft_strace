#******************************************************************************
# MAIN *
#******************************************************************************
NAME = ft_strace

#******************************************************************************
# FILES, DIR, OBJECTS, HEADER & DEPENDENCIES *
#******************************************************************************
SRC_FOLD = src/
HEADER_FOLD = header/
OBJ_DEP_DIR = obj_n_dep/

HEADER_SRC = ft_strace
C_SRC = main stats print syscall_info syscalls_32 syscalls_64 syscall_args tracer path signals

HEADER_FLS = $(addsuffix .h, $(HEADER_SRC))
HEADER = $(addprefix $(HEADER_FOLD), $(HEADER_FLS))

C_FLS = $(addsuffix .c, $(C_SRC))
SRC = $(addprefix $(SRC_FOLD), $(C_FLS))
OBJ = $(addprefix $(OBJ_DEP_DIR), $(SRC:.c=.o))
DEP = $(OBJ:.o=.d)

OBJF = .cache_exists

#******************************************************************************
# INSTRUCTIONS *
#******************************************************************************
CC = cc -g3
FLAGS = -Wall -Wextra -Werror -I$(HEADER_FOLD)
RM = rm -rf

#******************************************************************************
# COMPILATION *
#******************************************************************************
all: $(NAME)
	@echo "$(ROSE)COMPILATION FINISHED, $(NAME) IS CREATED!$(RESET)"

$(NAME): $(OBJ)
	@$(CC) $(FLAGS) $(OBJ) -o $(NAME)

$(OBJ_DEP_DIR)%.o: %.c $(HEADER) | $(OBJF)
	@$(CC) $(FLAGS) -MMD -MP -c $< -o $@
	@echo "$(BLEU)Compiling $< to $@.$(RESET)"

$(OBJF):
	@mkdir -p $(OBJ_DEP_DIR)$(SRC_FOLD)

clean:
	@$(RM) $(OBJ_DEP_DIR)
	@echo "$(VIOLET)Suppressing objects & dependencies files of $(NAME).$(RESET)"

fclean: clean tclean
	@$(RM) $(NAME)
	@echo "$(VERT)Suppressing archives $(NAME).$(RESET)"

re: fclean all

#******************************************************************************
# TESTS: chaque tests/*.c compilé en 64 bit (_64) et en 32 bit (_32) *
# Autre dossier: make test TEST_DIR=chemin/ *
#******************************************************************************
TEST_DIR ?= tests/
TEST_SRC = $(wildcard $(TEST_DIR)*.c)
TEST_BIN = $(TEST_SRC:.c=_64) $(TEST_SRC:.c=_32)
# -w: les sources de test ne sont pas les nôtres, pas de -Werror dessus
TEST_FLAGS = -g -w -pthread

test: $(NAME) $(TEST_BIN)
	@if [ -z "$(TEST_SRC)" ]; then \
		echo "$(VIOLET)Aucun .c dans $(TEST_DIR): y copier les sources de test.$(RESET)"; \
	else \
		echo "$(ROSE)TESTS COMPILÉS: ./$(NAME) $(TEST_DIR)<nom>_64 ou _32$(RESET)"; \
	fi

# Un test qui ne compile pas n'arrête pas les autres (ex: 32 bit sans gcc-multilib)
$(TEST_DIR)%_64: $(TEST_DIR)%.c
	@$(CC) $(TEST_FLAGS) $< -o $@ \
		&& echo "$(BLEU)Compiling $< to $@.$(RESET)" \
		|| echo "$(VIOLET)KO 64 bit: $<$(RESET)"

$(TEST_DIR)%_32: $(TEST_DIR)%.c
	@$(CC) -m32 $(TEST_FLAGS) $< -o $@ \
		&& echo "$(BLEU)Compiling $< to $@ (32 bit).$(RESET)" \
		|| echo "$(VIOLET)KO 32 bit: $< (gcc-multilib installé ?)$(RESET)"

tclean:
	@$(RM) $(TEST_BIN)

-include $(DEP)

.PHONY: re fclean clean all test tclean

#******************************************************************************
# COLORS *
#******************************************************************************
RESET = \033[0m
ROSE = \033[1;38;5;225m
VIOLET = \033[1;38;5;55m
VERT = \033[1;38;5;85m
BLEU = \033[1;34m
