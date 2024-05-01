#include <linux/types.h>

/*

Use trampoline with the original instructions and jmp to the rest of the original function.
- original function first few instructions are replaced with a jmp to the hook function
- hook function executed
- if the original function is needed, then the trampoline will be called; the trampoline contains the original instructions with a jmp to the rest of the original function
- when unhooking, the trampoline will be released and the original instructions will return.


*/
struct self_hook
{
    void *target;
    void *hook_func;

    unsigned char * trampoline;
	unsigned char original_instructions[10];
};


static void disable_page_protection(void) {
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if (!(value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}


static void enable_page_protection(void) {
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if ((value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}


static int self_hook_function(struct self_hook *hook){
	// Assume 'target_function' is the address of the function you want to hook
	// 'hook_function' is the address of your hook function

	// Save the original first few bytes of 'target_function'
	// so you can execute them later in your 'hook_function'

	// Write a jump instruction at the beginning of 'target_function'
	// to redirect execution to 'hook_function'
	void **target_function = (void *)(hook->original); // Replace with the actual address
	void *hook_function = hook->function;     		// Your hook function

	unsigned char jmp_instruction[] = {
	    0x48, 0xB8,                             // mov rax, <address>
	    (unsigned char)(uintptr_t)hook_function, // Address of 'hook_function', split into bytes
	    (unsigned char)((uintptr_t)hook_function >> 8),
	    (unsigned char)((uintptr_t)hook_function >> 16),
	    (unsigned char)((uintptr_t)hook_function >> 24),
	    (unsigned char)((uintptr_t)hook_function >> 32),
	    (unsigned char)((uintptr_t)hook_function >> 40),
	    (unsigned char)((uintptr_t)hook_function >> 48),
	    (unsigned char)((uintptr_t)hook_function >> 56),
	    0xFF, 0xE0                    // jmp rax
	};


	// Save the original instructions
    memcpy(hook->original_instructions, hook->target, 5);

    // Create the trampoline function
    trampoline = kmalloc(8, GFP_KERNEL);
    memcpy(trampoline, original_instructions, 5);
    ((unsigned char *)trampoline)[5] = 0xE9; // JMP opcode
    int relative_address = (int)target_function_ptr - (int)trampoline - 5;
    memcpy(&((unsigned char *)trampoline)[6], &relative_address, 4);

    // Replace the first instruction of the target function with a jump to the hook function
    unsigned char jmp_instruction[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    relative_address = (int)hook_function_ptr - (int)target_function_ptr - 5;
    memcpy(&jmp_instruction[1], &relative_address, 4);
    memcpy(target_function_ptr, jmp_instruction, 5);


	// Disable write protection on the page containing 'target_function'
	// and replace the first few bytes with 'jmp_instruction'
	return 1;
}

static int self_unhook_function(struct ftrace_hook *hook){

}


static void my_hook_function(struct hook *hook) {
    // Perform your custom actions here
	


    // Call the original function
    asm volatile (
        "push %rax\n"
        "mov $original_instructions, %rax\n"
        "call *%rax\n"
        "pop %rax\n"
    );
}

void generate_trampoline(struct ftrace_hook *hook){
}