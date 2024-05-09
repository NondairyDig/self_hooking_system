#include <linux/module.h> // core header for loading lkms into the kernel
#include <linux/kernel.h> // types, macros, functions for kernel

#include "hooking.h"


MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("self_mod");
MODULE_AUTHOR("NondairyDig");
MODULE_VERSION("1.1");


struct self_hook hook;

static int hook_kill(struct pt_regs *regs){
    int sig = regs->si;


    if(sig != 1){
        ret_t ret;
        ret = trampoline_option_1(&hook, regs);
        return ret.i;
    }
    pr_info("Blocked kill 1\n");
    return 0;
}


static int __init mod_init(void){
    resolve_hook_address(&hook, "__x64_sys_kill");
    hook.hook_func = hook_kill;
    self_hook_function(&hook);
    return 0;
}


static void __exit mod_exit(void){
    self_unhook_function(&hook);
}


module_init(mod_init);
module_exit(mod_exit);