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
* **Architecture-Specific Knowledge**: Understanding x86_64 syscall calling conventions

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
* **Cross-Architecture Compatibility**: Writing portable code for different Linux architectures
* **Performance Debugging**: Identifying bottlenecks through syscall analysis

## Project Overview

ft_strace implements the core functionality of the strace utility, enabling developers and system administrators to diagnose program behavior, debug issues, analyze security vulnerabilities, and understand system-level interactions.
The program uses ptrace to intercept every system call made by a target process, decodes the syscall number and arguments, and displays them in human-readable format.

### Core Components

**Process Tracer Engine**: Uses ptrace(PTRACE_SYSCALL) to stop the traced process before and after each system call, capturing entry and exit points for complete syscall lifecycle monitoring.

**Syscall Decoder**: Maintains comprehensive syscall number-to-name mappings for x86_64 architecture, translating raw syscall numbers (0-548+) into readable names like "read", "write", "open", etc.

**Register Reader**: Extracts syscall arguments from CPU registers using PTRACE_GETREGS, reading values from rax (syscall number), rdi, rsi, rdx, r10, r8, r9 (arguments), following x86_64 calling conventions.

**Argument Formatter**: Implements intelligent formatting for different argument types including integers, pointers, file descriptors, flags (O_RDONLY|O_CLOEXEC), structures, and arrays.

**String Extractor**: Reads string arguments from traced process memory using PTRACE_PEEKDATA, reconstructing character-by-character for display with proper escaping and truncation.

**Return Value Analyzer**: Interprets syscall return values, identifies errors using errno, and displays human-readable error messages (ENOENT, EACCES, EINVAL, etc.).

**Signal Handler**: Detects signals delivered to traced process (SIGSEGV, SIGINT, SIGTERM), distinguishing between signals and syscall stops for accurate tracing.

## Features Implemented

### Core strace Functionality

* **System Call Interception**: Trace every syscall made by target process
* **Argument Display**: Show syscall arguments in readable format
* **Return Value Tracking**: Display syscall return values and error codes
* **Process Lifecycle**: Track from execve through exit_group

### Output Formatting

* **Syscall Name Resolution**: Convert syscall numbers to names
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

* **Multi-threaded Process Support**: Basic handling of threaded applications
* **File Descriptor Tracking**: Monitor fd creation and usage patterns
* **Memory Operation Analysis**: Track mmap, brk, munmap operations
* **Network Syscall Monitoring**: Display socket, bind, connect, send, recv calls

## Program Architecture

### ptrace Workflow

The program follows a strict ptrace workflow: fork process, child calls PTRACE_TRACEME and execve, parent waits for child, uses PTRACE_SYSCALL to single-step through syscalls, stopping at entry and exit.

### Syscall Table Architecture

Maintains static syscall tables mapping x86_64 syscall numbers to names, supports common syscalls (read=0, write=1, open=2, close=3, etc.) up to modern syscalls (450+).

### Register Reading Strategy

Uses PTRACE_GETREGS to read entire register set, extracts syscall number from orig_rax register, reads arguments from standard argument registers (rdi through r9), captures return value from rax.

### String Reconstruction

Implements word-by-word memory reading using PTRACE_PEEKDATA (8 bytes per call), assembles characters into strings, handles null terminators and invalid memory gracefully, truncates at reasonable length (32-64 chars).

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
# Compare outputs side by side
strace ls 2>&1 | head -20
./ft_strace ls 2>&1 | head -20

# Verify syscall counts
strace -c ls
./ft_strace ls  # Manual verification
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
* ✅ Knowledge of x86_64 syscall conventions
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

## Contact

* **GitHub**: [@TuroTheReal](https://github.com/TuroTheReal)
* **Email**: [arthurbernard.dev@gmail.com](mailto:arthurbernard.dev@gmail.com)
* **LinkedIn**: [Arthur Bernard](https://www.linkedin.com/in/arthurbernard92/)

---

[![Made with C](https://img.shields.io/badge/Made%20with-C-blue.svg)](https://img.shields.io/badge/Made%20with-C-blue.svg)
[![System Call Tracing](https://img.shields.io/badge/Tool-strace-green.svg)](https://img.shields.io/badge/Tool-strace-green.svg)
[![ptrace API](https://img.shields.io/badge/API-ptrace-red.svg)](https://img.shields.io/badge/API-ptrace-red.svg)
