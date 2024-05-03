# Linux Kernel Function Hooking System

This system provides a mechanism for hooking functions in the Linux kernel. It allows you to intercept calls to a target function and redirect them to a hook function. This can be useful for monitoring or modifying the behavior of the kernel.
An alternative to ftrace/kprobes or modifying the syscall table.

## Features

- **Function Hooking**: Intercept calls to a target function and redirect them to a hook function.
- **Trampoline Function**: Call the original function from within the hook function.
- **Support for Multiple Return Types**: Handle functions that return different types using a union.

## Usage

The system is based on a `self_hook` struct, which contains the following fields:

- `target`: A pointer to the target function to be hooked.
- `hook_func`: A pointer to the hook function.
- `original_instructions`: An array to store the original instructions of the target function.

To use the system, you need to:

1. Define a `self_hook` struct for the target function.
2. Use the `install_hook` function to install the hook.
3. Call the target function. The system will automatically redirect the call to the hook function.
4. Use `trampoline()` to call the original function from within a hook function.
5. Use the `uninstall_hook` function to uninstall the hook when you're done.
