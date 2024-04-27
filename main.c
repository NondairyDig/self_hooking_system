#include <linux/module.h> // core header for loading lkms into the kernel
#include <linux/kernel.h> // types, macros, functions for kernel

#include "logger.h"


MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("self_mod");
MODULE_AUTHOR("NondairyDig");
MODULE_VERSION("1.0");


static int __init mod_init(void){
    
    return 0;
}


static void __exit mod_exit(void){
    cleanup();
}


module_init(mod_init);
module_exit(mod_exit);