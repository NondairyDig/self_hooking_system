#include <linux/kprobes.h> // to resolve kernel symbols
#include <linux/version.h>


typedef unsigned long (*kallsyms_lookup_name_t)(const char *); // the kallsyms_lookup_name function prototype pointer

struct self_hook
{
    void *target;
    void *hook_func;

	unsigned char original_instructions[5];
    unsigned char hook_instructions[5];
};

typedef union { // A generic return type to handle return values of various functions.
    int i;
    long l;
    float f;
    double d;
    long double ld;
    void* p;
} ret_t;

typedef ret_t (*func_ptr_t)(void*);

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

    disable_page_protection();
	// Save the original instructions
    memcpy(hook->original_instructions, hook->target, 5);

    // Replace the first instruction of the target function with a jump to the hook function
    unsigned char jmp_instruction[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    unsigned long relative_address = (unsigned long)hook->hook_func - (unsigned long)hook->target - 5;
    memcpy(&jmp_instruction[1], &relative_address, 4);
    memcpy(hook->target, jmp_instruction, 5);
    memcpy(hook->hook_instructions, jmp_instruction, 5);

    enable_page_protection();

	return 1;
}


static int self_unhook_function(struct self_hook *hook){

    disable_page_protection();

    memcpy(hook->target, hook->original_instructions, 5);

    enable_page_protection();
    return 1;
}


static int resolve_hook_address(struct self_hook *hook, const char *symbol)
{
    static struct kprobe kp = {
    	.symbol_name = "kallsyms_lookup_name" // Ready the kbrobe to probe the kallsyms_lookup_name function
    };

    #if LINUX_VERSION_CODE > KERNEL_VERSION(5, 8, 0)
        kallsyms_lookup_name_t kallsyms_lookup_name_new;
		register_kprobe(&kp);
        kallsyms_lookup_name_new = (kallsyms_lookup_name_t)kp.addr; // Get address of function
        hook->target = (unsigned long *)kallsyms_lookup_name_new(symbol); // Get starting point of syscall table in memory
        unregister_kprobe(&kp);
    #elif LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
        hook->target = (unsigned long*)kallsyms_lookup_name(symbol); // Find symbol link with kallsyms_lookup_name
    #else
        hook->target = NULL;
#endif

	if (!hook->target)
	{
        pr_err("target function not found\n");
		return -ENOENT;
	}

	return 1;
}

// can't allocate executable memory!! :(.
static ret_t trampoline(struct self_hook *hook, void* args) {
    ret_t returnValue;

    // Call the rest of the original function and get the return value
    asm volatile (
        "call *%1\n"
        "mov %%rax, %0\n"
        : "=r" (returnValue.ld)  // Store the return value as the largest value possible
        : "r" (hook->target + sizeof(hook->original_instructions))
        : "%rax"
    );

    return returnValue;
}


static ret_t trampoline_option_1(struct self_hook *hook, void* args) {
    ret_t returnValue;
    disable_page_protection();
    memcpy(hook->target, hook->original_instructions, 5);
    enable_page_protection();
    // Call the rest of the original function and get the return value
    // Define a function pointer type that matches the signature of the function you're hooking
    

    // Cast hook->target to the function pointer type
    func_ptr_t func_ptr = (func_ptr_t)hook->target;

    // Call the function through the function pointer and store the return value
    returnValue = func_ptr(args);

    disable_page_protection();
    memcpy(hook->target, hook->hook_instructions, 5);
    enable_page_protection();
    return returnValue;
}

// Executable function.... == Replaceable....
static ret_t trampoline_option_2(struct self_hook *hook, void* args) {
    asm volatile (
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
        "nop\n"
    );
}