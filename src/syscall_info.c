#include "ft_strace.h"

void get_syscall_info(t_tracer *tracer, t_syscall_info *info)
{
	if (tracer->is_64bit) {
		// 64-bit: registres standard
		info->number = tracer->regs.regs_64.orig_rax;
		info->args[0] = tracer->regs.regs_64.rdi;
		info->args[1] = tracer->regs.regs_64.rsi;
		info->args[2] = tracer->regs.regs_64.rdx;
		info->args[3] = tracer->regs.regs_64.r10;
		info->args[4] = tracer->regs.regs_64.r8;
		info->args[5] = tracer->regs.regs_64.r9;
		info->name = get_syscall_name_64(info->number);
	} else {
		// 32-bit: registres i386
		info->number = tracer->regs.regs_32.orig_eax;
		info->args[0] = tracer->regs.regs_32.ebx;
		info->args[1] = tracer->regs.regs_32.ecx;
		info->args[2] = tracer->regs.regs_32.edx;
		info->args[3] = tracer->regs.regs_32.esi;
		info->args[4] = tracer->regs.regs_32.edi;
		info->args[5] = tracer->regs.regs_32.ebp;
		info->name = get_syscall_name_32(info->number);
	}

	// Obtenir le nombre d'arguments pour ce syscall
	info->arg_count = get_syscall_arg_count(info->number, tracer->is_64bit);
}

void get_syscall_retval(t_tracer *tracer, t_syscall_info *info)
{
	if (tracer->is_64bit) {
		// 64-bit: valeur de retour signée
		info->ret_val = (long long)tracer->regs.regs_64.rax;
	} else {
		// 32-bit: IMPORTANT - traiter comme un int signé 32-bit
		// puis étendre en 64-bit signé
		int ret32 = (int)tracer->regs.regs_32.eax;
		info->ret_val = (long long)ret32;
	}
}