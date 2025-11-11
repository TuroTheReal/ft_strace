#include "ft_strace.h"

void get_syscall_info(t_tracer *tracer, t_syscall_info *info)
{
	if (tracer->is_64bit) {
		// *** MODE 64-BIT ***
		// En x86_64, les registres pour les syscalls sont :
		// - rax : numéro du syscall
		// - rdi : 1er argument
		// - rsi : 2ème argument
		// - rdx : 3ème argument
		// - r10 : 4ème argument (attention, pas rcx !)
		// - r8  : 5ème argument
		// - r9  : 6ème argument

		info->number = tracer->regs.orig_rax;  // orig_rax contient le numéro
		info->args[0] = tracer->regs.rdi;
		info->args[1] = tracer->regs.rsi;
		info->args[2] = tracer->regs.rdx;
		info->args[3] = tracer->regs.r10;
		info->args[4] = tracer->regs.r8;
		info->args[5] = tracer->regs.r9;

		// Récupérer le nom du syscall depuis la table
		info->name = get_syscall_name_64(info->number);
	} else {
		// *** MODE 32-BIT ***
		// En i386, les registres pour les syscalls sont :
		// - eax : numéro du syscall
		// - ebx : 1er argument
		// - ecx : 2ème argument
		// - edx : 3ème argument
		// - esi : 4ème argument
		// - edi : 5ème argument
		// - ebp : 6ème argument

		info->number = tracer->regs.orig_rax & 0xFFFFFFFF;  // Masque 32-bit
		info->args[0] = tracer->regs.rbx & 0xFFFFFFFF;
		info->args[1] = tracer->regs.rcx & 0xFFFFFFFF;
		info->args[2] = tracer->regs.rdx & 0xFFFFFFFF;
		info->args[3] = tracer->regs.rsi & 0xFFFFFFFF;
		info->args[4] = tracer->regs.rdi & 0xFFFFFFFF;
		info->args[5] = tracer->regs.rbp & 0xFFFFFFFF;

		// Récupérer le nom du syscall depuis la table
		info->name = get_syscall_name_32(info->number);
	}
}


void get_syscall_retval(t_tracer *tracer, t_syscall_info *info)
{
	if (tracer->is_64bit) {
		// En 64-bit, la valeur de retour est dans rax
		info->ret_val = tracer->regs.rax;
	} else {
		// En 32-bit, la valeur de retour est dans eax
		info->ret_val = tracer->regs.rax & 0xFFFFFFFF;

		// Gestion des valeurs signées en 32-bit
		if (info->ret_val & 0x80000000) {
			// Si le bit de signe est à 1, c'est négatif
			// On étend le signe sur 64 bits
			info->ret_val |= 0xFFFFFFFF00000000;
		}
	}
}