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
C_SRC = main stats print syscall_info syscalls_32 syscalls_64 syscall_args tracer path

HEADER_FLS = $(addsuffix .h, $(HEADER_SRC))
HEADER = $(addprefix $(HEADER_FOLD), $(HEADER_FLS))

C_FLS = $(addsuffix .c, $(C_SRC))
SRC = $(addprefix $(SRC_FOLD), $(C_FLS))
OBJ = $(addprefix $(OBJ_DEP_DIR), $(SRC:.c=.o))
DEP = $(addprefix $(OBJ_DEP_DIR), $(OBJ:.o=.d))

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

fclean: clean
	@$(RM) $(NAME) $(NAME_BONUS)
	@echo "$(VERT)Suppressing archives $(NAME).$(RESET)"

re: fclean all

-include $(DEP)
-include $(DEP_BONUS)

.PHONY: re fclean clean all

#******************************************************************************
# COLORS *
#******************************************************************************
RESET = \033[0m
ROSE = \033[1;38;5;225m
VIOLET = \033[1;38;5;55m
VERT = \033[1;38;5;85m
BLEU = \033[1;34m
