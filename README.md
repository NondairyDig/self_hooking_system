# Linux Kernel Function Hooking System

## Note
Might encounter problems if hooking more then one function due to concurrent execution, this might lead into two functions executing code that was changed. can make a template trampoline function for each hook to avoid crashes or implement a simple "trampoline lock" to avoid executing if not available(Can also make a trampoline pool for multiple executions as the number of cores or multiprocessing threads etc..);

## Overview
The Linux Kernel Function Hooking System is a tool designed to intercept and redirect kernel-level function calls. It's used for monitoring or altering the behavior of kernel functions. This system serves as an alternative to other kernel function interception methods like ftrace/kprobes and syscall table modification.

## Purpose
The main purpose of this system is to provide a flexible and straightforward interface for hooking into kernel functions. This can be particularly useful for:
- Debugging the kernel by monitoring function calls and parameters.
- Enhancing security by checking parameters or call frequency.
- Extending or modifying kernel functionality without altering source code.

## Features
- **Function Hooking**: Intercept and redirect calls to kernel functions to user-defined hook functions.
- **Trampoline Function**: Execute the original function code after the interception to ensure normal operation.
- **Support for Multiple Return Types**: Use a union type to handle various function return types.

## Usage
To hook a kernel function using this system, follow these steps:

1. Define a `self_hook` struct instance for the function you intend to hook.
2. Resolve the address of the target kernel function using `resolve_hook_address`.
3. Set your hook function by assigning it to the `hook_func` field of the `self_hook` struct.
4. Install the hook using `self_hook_function`.
5. Calls to the original function will now be redirected to your hook function.
6. (Optional) Within your hook function, use `trampoline` to execute the original function if necessary.
7. Uninstall the hook with `self_unhook_function` when done.

## Example
There's a simple example of how to use this system to hook the `__x64_sys_kill` function in the Linux kernel.


## Limitations
The current implementation only supports x86_64 architecture.
The system may not work with all kernel functions due to potential restrictions or optimizations.
