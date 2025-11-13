#include "ft_strace.h"

void get_syscall_info(t_tracer *tracer, t_syscall_info *info)
{
	if (tracer->is_64bit) {
		// 64-bit: registres standard
		info->number = tracer->regs.orig_rax;
		info->args[0] = tracer->regs.rdi;
		info->args[1] = tracer->regs.rsi;
		info->args[2] = tracer->regs.rdx;
		info->args[3] = tracer->regs.r10;
		info->args[4] = tracer->regs.r8;
		info->args[5] = tracer->regs.r9;
		info->name = get_syscall_name_64(info->number);
	} else {
		// 32-bit: convention différente
		// Les registres 32-bit utilisent ebx, ecx, edx, esi, edi, ebp
		// qui sont stockés dans les 32 bits bas de leurs équivalents 64-bit
		info->number = tracer->regs.orig_rax & 0xFFFFFFFF;
		info->args[0] = tracer->regs.rbx & 0xFFFFFFFF;
		info->args[1] = tracer->regs.rcx & 0xFFFFFFFF;
		info->args[2] = tracer->regs.rdx & 0xFFFFFFFF;
		info->args[3] = tracer->regs.rsi & 0xFFFFFFFF;
		info->args[4] = tracer->regs.rdi & 0xFFFFFFFF;
		info->args[5] = tracer->regs.rbp & 0xFFFFFFFF;
		info->name = get_syscall_name_32(info->number);
	}

	// Obtenir le nombre d'arguments pour ce syscall
	info->arg_count = get_syscall_arg_count(info->number, tracer->is_64bit);
}

void get_syscall_retval(t_tracer *tracer, t_syscall_info *info)
{
	if (tracer->is_64bit) {
		// 64-bit: valeur de retour signée
		info->ret_val = (long long)tracer->regs.rax;
	} else {
		// 32-bit: IMPORTANT - traiter comme un int signé 32-bit
		// puis étendre en 64-bit signé
		int ret32 = (int)(tracer->regs.rax & 0xFFFFFFFF);
		info->ret_val = (long long)ret32;
	}
}