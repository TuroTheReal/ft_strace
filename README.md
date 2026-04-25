# FT_STRACE

## Table of Contents

* [About](#about)
* [Installation](#installation)
* [Usage](#usage)
* [Key Concepts Learned](#key-concepts-learned)
* [Skills Developed](#skills-developed)
* [Project Overview](#project-overview)
* [Features Implemented](#features-implemented)
* [Program Architecture](#program-architecture)
* [Testing](#testing)
* [42 School Standards](#42-school-standards)
* [Related Articles](#-related-articles)
* [Contact](#contact)

## About

This repository contains my implementation of the **ft_strace** project at 42 School.
ft_strace is a recreation of the powerful **strace** system call tracer, one of the most essential debugging and diagnostic tools used by system programmers and security researchers since 1991.
Built entirely in **C**, this program intercepts and records system calls made by a process using **ptrace** (process trace), providing deep visibility into program behavior, system interactions, and low-level operations.

The project demonstrates mastery of process control, Linux kernel interfaces, and system-level debugging while implementing the core functionality of the original strace utility.

## Installation

### Prerequisites

* **C Compiler** (gcc/clang)
* **Make** utility
* **UNIX/Linux environment** (ptrace API)
* **64-bit Linux system** (for proper syscall number mappings)

### Compilation

```bash
# Clone the repository
git clone https://github.com/TuroTheReal/ft_strace.git
cd ft_strace

# Compile the program
make

# Clean object files
make clean

# Clean everything
make fclean

# Recompile
make re
```

## Usage

### Basic Usage

```bash
# Trace a simple command
./ft_strace ls -la

# Trace with arguments
./ft_strace /bin/echo "Hello World"

# Trace with full path
./ft_strace /usr/bin/python3 script.py
```

### Example Output

```bash
$ ./ft_strace /bin/ls
execve("/bin/ls", ["/bin/ls"], 0x7ffdb2e3e0a8 /* 62 vars */) = 0
brk(NULL)                               = 0x55f8c9a3d000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=119854, ...}) = 0
mmap(NULL, 119854, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f8e5c3a0000
close(3)                                = 0
...
write(1, "Makefile  README.md  header  src"..., 41) = 41
close(1)                                = 0
close(2)                                = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

## Key Concepts Learned

### Process Control and Debugging

* **ptrace System Call**: Mastering Linux's process tracing mechanism for debugging and monitoring
* **Process State Management**: Understanding PTRACE_TRACEME, PTRACE_SYSCALL, PTRACE_GETREGS
* **Signal Handling**: Intercepting and analyzing signals sent to traced processes
* **Parent-Child Process Coordination**: Managing tracer/tracee relationship with fork()

### System Call Interface

* **Syscall Number Mapping**: Converting syscall numbers to human-readable names across architectures
* **Register Extraction**: Reading system call arguments from CPU registers (rdi, rsi, rdx, r10, r8, r9)
* **Return Value Analysis**: Interpreting syscall return values and error codes (errno)
* **Architecture-Specific Knowledge**: Understanding x86_64 and i386 syscall calling conventions

### Low-Level C Programming

* **Binary Data Structures**: Working with user_regs_struct and ptrace register access
* **Memory Layout**: Understanding process memory, stack, heap, and register organization
* **Pointer Manipulation**: Reading traced process memory with PTRACE_PEEKDATA
* **String Handling**: Reconstructing strings and data from remote process memory

### Operating System Internals

* **Kernel-User Space Boundary**: Understanding syscall mechanism and context switches
* **Process Lifecycle**: Tracking execve, fork, clone, exit, and process state transitions
* **File Descriptor Management**: Monitoring open, close, read, write, dup operations
* **Signal Delivery**: Observing signal generation, delivery, and handler invocation

## Skills Developed

* **System Programming Expertise**: Professional-level understanding of Unix/Linux internals
* **Debugging Tool Development**: Building diagnostic tools for system-level troubleshooting
* **Reverse Engineering Fundamentals**: Analyzing program behavior without source code access
* **Low-Level Process Monitoring**: Implementing sophisticated process tracing mechanisms
* **Security Analysis Skills**: Understanding techniques used in malware analysis and forensics
* **Cross-Architecture Compatibility**: Writing portable code for x86_64 and i386 Linux architectures
* **Performance Debugging**: Identifying bottlenecks through syscall analysis

## Project Overview

ft_strace implements the core functionality of the strace utility, enabling developers and system administrators to diagnose program behavior, debug issues, analyze security vulnerabilities, and understand system-level interactions.
The program uses ptrace to intercept every system call made by a target process, decodes the syscall number and arguments, and displays them in human-readable format.

### Core Components

**Process Tracer Engine** (`src/tracer.c`): Uses ptrace(PTRACE_SYSCALL) to stop the traced process before and after each system call, capturing entry and exit points for complete syscall lifecycle monitoring.

**Syscall Decoders** (`src/syscalls_64.c`, `src/syscalls_32.c`): Maintains comprehensive syscall number-to-name mappings for both x86_64 and i386 architectures, translating raw syscall numbers into readable names like "read", "write", "open", etc.

**Syscall Info Handler** (`src/syscall_info.c`, `src/syscall_args.c`): Extracts syscall arguments from CPU registers using PTRACE_GETREGS, reads values following the appropriate calling convention, and dispatches to the correct architecture table.

**Argument Formatter** (`src/print.c`): Implements intelligent formatting for different argument types including integers, pointers, file descriptors, flags (O_RDONLY|O_CLOEXEC), structures, and arrays.

**Path Resolver** (`src/path.c`): Resolves command names to full executable paths by searching PATH, enabling usage of `./ft_strace ls` without typing the full `/bin/ls` path.

**Statistics Module** (`src/stats.c`): Collects and displays per-syscall statistics such as call counts and timing information when requested.

**Main Driver** (`src/main.c`): Parses command-line arguments, sets up the fork/ptrace workflow, coordinates the tracer and tracee, and handles final cleanup.

## Features Implemented

### Core strace Functionality

* **System Call Interception**: Trace every syscall made by target process
* **Argument Display**: Show syscall arguments in readable format
* **Return Value Tracking**: Display syscall return values and error codes
* **Process Lifecycle**: Track from execve through exit_group

### Output Formatting

* **Syscall Name Resolution**: Convert syscall numbers to names (x86_64 and i386 tables)
* **Argument Type Detection**: Format integers, pointers, strings appropriately
* **Flag Decoding**: Display symbolic flag names (O_RDONLY, MAP_PRIVATE)
* **Structure Display**: Show struct stat, timeval, etc. in readable format
* **String Truncation**: Limit long strings with ellipsis (...)

### Error Handling

* **errno Mapping**: Convert error numbers to symbolic names (ENOENT, EACCES)
* **Error Message Display**: Show descriptive error strings
* **Invalid Syscall Detection**: Handle unknown syscall numbers
* **Signal Differentiation**: Distinguish signals from syscall events

### Process Management

* **Fork Detection**: Handle traced process creating child processes
* **Exec Tracking**: Monitor program execution and replacement
* **Exit Status**: Display process exit code and termination reason
* **Signal Delivery**: Report signals received by traced process

### Advanced Features

* **Dual Architecture Support**: Separate syscall tables for x86_64 (`syscalls_64.c`) and i386 (`syscalls_32.c`)
* **File Descriptor Tracking**: Monitor fd creation and usage patterns
* **Memory Operation Analysis**: Track mmap, brk, munmap operations
* **Network Syscall Monitoring**: Display socket, bind, connect, send, recv calls

## Program Architecture

### Project Structure

```
ft_strace/
├── Makefile
├── README.md
├── en.subject.pdf
├── compare.sh                  # Script to compare output with real strace
├── diff.sh                     # Script to diff behaviors
├── test_32.c                   # 32-bit test source
├── test_32                     # Compiled 32-bit test binary
├── header/
│   └── ft_strace.h
└── src/
    ├── main.c                  # Entry point and fork/ptrace orchestration
    ├── tracer.c                # Core ptrace loop and syscall stop handling
    ├── syscall_info.c          # Syscall info dispatch
    ├── syscall_args.c          # Register → argument extraction
    ├── syscalls_64.c           # x86_64 syscall table
    ├── syscalls_32.c           # i386 syscall table
    ├── print.c                 # Argument / return value formatting
    ├── path.c                  # PATH resolution for command names
    └── stats.c                 # Per-syscall statistics
```

### ptrace Workflow

The program follows a strict ptrace workflow: fork process, child calls PTRACE_TRACEME and execve, parent waits for child, uses PTRACE_SYSCALL to single-step through syscalls, stopping at entry and exit.

### Syscall Table Architecture

Maintains two static syscall tables, one for x86_64 (`syscalls_64.c`) and one for i386 (`syscalls_32.c`), supporting common syscalls (read, write, open, close, etc.) up to modern ones.

### Register Reading Strategy

Uses PTRACE_GETREGS to read entire register set, extracts syscall number from orig_rax (or orig_eax on i386) register, reads arguments from standard argument registers, captures return value from rax/eax.

### String Reconstruction

Implements word-by-word memory reading using PTRACE_PEEKDATA (8 bytes per call on 64-bit), assembles characters into strings, handles null terminators and invalid memory gracefully, truncates at reasonable length (32-64 chars).

### State Machine Design

Tracks whether process is at syscall entry or exit using alternating flag, handles PTRACE_EVENT signals specially, manages process state transitions (running, stopped, exited, signaled).

## Testing

### Basic Command Tests

```bash
# Test simple commands
./ft_strace /bin/ls
./ft_strace /bin/pwd
./ft_strace /bin/echo "test"

# Test with arguments
./ft_strace /usr/bin/wc -l /etc/passwd
./ft_strace /usr/bin/grep "root" /etc/passwd
```

### File Operation Tests

```bash
# Test file I/O
./ft_strace /bin/cat test.txt
./ft_strace /usr/bin/head -n 5 file.txt

# Test file creation
./ft_strace /usr/bin/touch newfile.txt
```

### 32-bit Binary Tests

```bash
# Compile the provided 32-bit test binary
gcc -m32 -o test_32 test_32.c

# Trace the 32-bit binary (exercises the i386 syscall table)
./ft_strace ./test_32
```

### Network Operation Tests

```bash
# Test network syscalls
./ft_strace /usr/bin/curl -s http://example.com
./ft_strace /usr/bin/wget http://example.com
./ft_strace /usr/bin/nc -l 8080
```

### Error Condition Tests

```bash
# Test error handling
./ft_strace /bin/cat nonexistent.txt
./ft_strace /usr/bin/ls /root  # Permission denied

# Test invalid commands
./ft_strace /nonexistent/command
```

### Comparison with Original strace

```bash
# Use the provided comparison scripts
./compare.sh <command>
./diff.sh <command>

# Manual side-by-side comparison
strace ls 2>&1 | head -20
./ft_strace ls 2>&1 | head -20
```

### Edge Cases

```bash
# Test with shell built-ins (should fail gracefully)
./ft_strace cd /tmp

# Test with scripts
./ft_strace ./script.sh

# Test long-running process with Ctrl+C
./ft_strace sleep 100  # Press Ctrl+C
```

## 42 School Standards

### Project Standards

* ✅ No memory leaks (validated with valgrind)
* ✅ ptrace-based syscall interception
* ✅ Accurate syscall name and argument display
* ✅ Proper error handling and errno mapping
* ✅ Support for common syscalls (read, write, open, etc.)
* ✅ Norm compliance (42 coding standards)

### Technical Requirements

* ✅ Fork and ptrace process control
* ✅ Register reading with PTRACE_GETREGS
* ✅ Syscall entry/exit detection
* ✅ Argument extraction from registers
* ✅ Return value and error code display
* ✅ Process exit status tracking

### System Programming Requirements

* ✅ Understanding of ptrace API
* ✅ Knowledge of x86_64 and i386 syscall conventions
* ✅ Process state management
* ✅ Signal handling during tracing
* ✅ Memory reading from remote process
* ✅ Proper cleanup of traced processes

### Output Requirements

* ✅ Syscall name resolution
* ✅ Human-readable argument formatting
* ✅ Error message display (errno translation)
* ✅ Process exit information
* ✅ Compatible output format with original strace

## 📝 Related Articles

Blog posts documenting the learning process and context behind this project:

- 📝 [42 Piscine and Common Core: What I Learned](https://arthur-portfolio.com/en/blog/42-piscine-and-core-curriculum) — Reflections on 42 School's selection process and 2-year curriculum

---

## Contact

* **GitHub**: [@TuroTheReal](https://github.com/TuroTheReal)
* **Email**: [arthurbernard.dev@gmail.com](mailto:arthurbernard.dev@gmail.com)
* **LinkedIn**: [Arthur Bernard](https://www.linkedin.com/in/arthurbernard92/)

---

[![Made with C](https://img.shields.io/badge/Made%20with-C-blue.svg)](https://img.shields.io/badge/Made%20with-C-blue.svg)
[![System Call Tracing](https://img.shields.io/badge/Tool-strace-green.svg)](https://img.shields.io/badge/Tool-strace-green.svg)
[![ptrace API](https://img.shields.io/badge/API-ptrace-red.svg)](https://img.shields.io/badge/API-ptrace-red.svg)
