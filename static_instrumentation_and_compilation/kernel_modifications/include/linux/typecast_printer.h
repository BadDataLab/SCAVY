#ifndef __TYPECAST_PRINTER__
#define __TYPECAST_PRINTER__ 

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>

void __attribute__((__noinline__)) print_typecast_instruction (char * function_name, void* alloc_pointer, char * original_type, char * new_type);
void __attribute__((__noinline__)) decide_to_enable_logging (int current_pid, int current_cpu);
void __attribute__((__noinline__)) print_kmalloc_stuff (int size, int flags);
void __attribute__((__noinline__)) print_syscall_stuff (unsigned long number);

#endif