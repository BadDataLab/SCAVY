#include "corrupter_def.h"
#include <linux/uaccess.h> 
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/cred.h>
#include <linux/sched.h> // for current task_struct
#include <linux/module.h>
#include <linux/typecast_printer.h>
#include <linux/slab.h>
// #include <trace/events/typecast_printer_event.h>

// breakpoint stuff
#include <linux/kallsyms.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/string.h>  // for strcmp()
#include <linux/list.h> // for the linked list of breakpoint handlers

/***************************************************************************************************************************************/

unsigned long anti_optimization_symbol = 0;

unsigned long long allocated_addresses[10000] = {0};
unsigned short is_allocated[10000] = {0};
int latest_address = 0;
int tracking_enabled = 0;

/***************************************************************************************************************************************/
static inline void* instrumentable_print_typecast (char * function_name, void* alloc_pointer, char * original_type, char * new_type) {
	return (void *) ((unsigned long) function_name ^ (unsigned long)alloc_pointer);
}

void __attribute__((__noinline__)) __attribute__ ((optnone)) print_typecast_instruction (char * function_name, void* alloc_pointer,
char * original_type, char * new_type) {
	anti_optimization_symbol ^= (unsigned long) instrumentable_print_typecast(function_name,alloc_pointer,original_type,new_type);
}

EXPORT_SYMBOL(anti_optimization_symbol);
EXPORT_SYMBOL_GPL(print_typecast_instruction);

/***************************************************************************************************************************************/

void remove_address(void * address) {
	int i = 0;
	if (tracking_enabled == 0) { return; }
	if (strcmp(current->comm,"syz-executor") != 0) {return;} 
	for (i = 0;i < latest_address; i++) {
		if (is_allocated[i] == 0) {
			continue;
		}
		if (allocated_addresses[i] == (unsigned long long) address) {
			is_allocated[i] = 0;
		}
	}
}

void add_address(void * address) {
	if (tracking_enabled == 0) { return; }
	if (strcmp(current->comm,"syz-executor") != 0) {return;} 
	allocated_addresses[latest_address] = (unsigned long long) address;
	is_allocated[latest_address] = 1;	
	latest_address++;
}

void clear_allocations(void) {
	int i;
	for (i = 0; i < latest_address; i++) {
		is_allocated[i] = 0;
	}
	latest_address = 0;
}

EXPORT_SYMBOL_GPL(remove_address);
EXPORT_SYMBOL_GPL(add_address);
EXPORT_SYMBOL_GPL(clear_allocations);

/***************************************************** NEW CODE HERE FOR CORRUPTER *****************************************************/

struct perf_event **read_event = 0, **write_event = 0;
struct perf_event_attr *read_attr = 0, *write_attr = 0;
int set_up = 0, read_happened = 0;

static void unregister_breakpoint(void) {
	set_up = 0;
	if (read_event) {unregister_wide_hw_breakpoint(read_event); read_event = 0;}
	if (write_event) {unregister_wide_hw_breakpoint(write_event); write_event = 0;}
	if(read_attr){kfree(read_attr); read_attr = 0;};
	if(write_attr){kfree(write_attr); write_attr = 0;};
}

static void hbp_read_write_handler(struct perf_event *bp,
			       struct perf_sample_data *data,
			       struct pt_regs *regs) {
	if (bp->attr.bp_type == HW_BREAKPOINT_W) {
		if (read_happened == 0) {
			PDEBUG("{WRITE} detected from `0x%px`, breakpoint removed!\n",(void*)regs->ip);
			// unregister_breakpoint();
			// dump_stack();
			return;
		}
		PDEBUG("{WRITE} detected from `0x%px`!\n",(void*)regs->ip);
	} else if (bp->attr.bp_type == HW_BREAKPOINT_RW) {
		PDEBUG("{READ} detected from `0x%px`\n",(void*)regs->ip);
		// dump_stack();
		read_happened = 1;
	} else{
		PDEBUG("{UNKNOWN} operation (type: %d) made by `0x%px`\n",bp->attr.bp_type,(void*)regs->ip);
	}
}


static long  corrupter_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	struct corrupter_args args;
	struct perf_event_attr attr;
	struct perf_event** sample_hbp;
	struct perf_event_attr* tmp;
	// unsigned int current_iterator = current_event_ptr;

	preempt_disable();

	if (copy_from_user(&args, (struct corrupter_args *)arg, sizeof(args))) {
		preempt_enable();
		PDEBUG("copy_from_user of the parameters failed!\n");
		return -EFAULT;
	}
	
	switch (cmd) {
		int i, found_it = 0;
		case CORRUPT_ADDRESS:
			if (set_up) {
				PDEBUG("Breakpoint exists!\n");
				preempt_enable();
				return -EFAULT;
			}
			if (args.size > 8 || args.size < 1) {
				PDEBUG("Size not supported!\n");
				preempt_enable();
				return -EFAULT;
			}
			
			// for (i = 0;i < latest_address; i++) {
			// 	if (is_allocated[i] == 0) {
			// 		continue;
			// 	}
			// 	if (allocated_addresses[i] == args.address) {
			// 		found_it = 1;
			// 	}
			// }
			// if (found_it == 0) {
			// 	PDEBUG("Address `0x%px` not allocated!\n",(void*) args.address);
			// 	return -EINVAL;
			// }

			/////////////// New trial: Don't corrupt the memory, just set breakpoint ///////////////
			if (args.only_trace_accesses == 0) {
				if (copy_from_user((void *)(args.address+args.offset), args.data, args.size)) {
					preempt_enable();
					PDEBUG("copy_from_user of the corruption failed!\n");
					return -EFAULT;
				}
			}
			////////////////////////////////////////////////////////////////////////////////////////
			
			///////////// NEW TRIAL: Look around the memory to corrupt with a similar value
			// unsigned long long struct_size;
			// copy_from_user(&struct_size, args.data, 8);
			// unsigned long long addr_to_corr = args.address+args.offset;
			// unsigned long long page_head = (args.address >> 3) << 3;
			// for (int idx = 0; idx < PAGE_SIZE/struct_size; idx++) {
			// 	unsigned long long current_addr = page_head+args.offset+(struct_size*idx);
			// 	if (current_addr != addr_to_corr) {
			// 		if (!(*((short *)current_addr) == 0xfc || *((short *)current_addr) == 0xfb)) {
			// 			memcpy(addr_to_corr, current_addr, args.size);
			// 		}
			// 	}
			// }
			
			read_happened = 0;
			hw_breakpoint_init(&attr);
			attr.bp_addr = args.address + args.offset; //kallsyms_lookup_name(ksym_name);
			attr.bp_len = args.size;
			attr.bp_type = HW_BREAKPOINT_W;
			sample_hbp = register_wide_hw_breakpoint(&attr, hbp_read_write_handler, NULL);
			// sample_hbp = register_wide_hw_breakpoint(&attr, hbp_read_write_handler, NULL);
			if (IS_ERR((void __force *)sample_hbp)) {
				PDEBUG("Breakpoint (write) registration failed! (too many up already?) {error: %d}\n",IS_ERR((void __force *)sample_hbp));
				unregister_breakpoint();
				preempt_enable();
				return -EFAULT;
			}
			write_event = sample_hbp;
			write_attr = kmalloc(sizeof(attr),GFP_KERNEL);
			memcpy(write_attr,&attr,sizeof(attr));


			hw_breakpoint_init(&attr);
			attr.bp_addr = args.address + args.offset; //kallsyms_lookup_name(ksym_name);
			attr.bp_len = args.size;
			attr.bp_type = HW_BREAKPOINT_RW;
			sample_hbp = register_wide_hw_breakpoint(&attr, hbp_read_write_handler, NULL);
			if (IS_ERR((void __force *)sample_hbp)) {
				unregister_breakpoint();
				PDEBUG("Breakpoint (read) registration failed! (too many up already?) {error: %d}\n",IS_ERR((void __force *)sample_hbp));
				preempt_enable();
				return -EFAULT;
			}
			read_event = sample_hbp;
			read_attr = kmalloc(sizeof(attr),GFP_KERNEL);;
			memcpy(read_attr,&attr,sizeof(attr));
			PDEBUG("HW Breakpoints installed in address `0x%px`\n",(void*)(args.address + args.offset));
			set_up = 1;

			preempt_enable();
			return 0;

		case UNTRACE_CORRUPTION:
			if (read_attr == 0 || args.address+args.offset != read_attr->bp_addr) {
				PDEBUG("Invalid address to untrace! (current address: %px)\n",(void*) read_attr->bp_addr);
				preempt_enable();
				return -ENOKEY;
			}
			unregister_breakpoint();
			PDEBUG("HW Breakpoints removed!\n");
			preempt_enable();
			return 0;
		
		case READ_KERNEL_MEMORY:
			PDEBUG("Reading kernel memory at address `0x%px` and size `%d` -> result = 0x%px\n",
				(void*)(args.address + args.offset),args.size,(void*)*((unsigned long long*)(args.address + args.offset)));
			return copy_to_user(args.data, (void *)(args.address+args.offset), args.size);
		case ENABLE_TRACKING:
			tracking_enabled = 1;
			preempt_enable();
			return 0;

		case DISABLE_TRACKING:
			tracking_enabled = 0;
			preempt_enable();
			return 0;

		case CLEAR_ALLOCATIONS:
			clear_allocations();
			preempt_enable();
			return 0;
	}
	preempt_enable();
	return -EINVAL;
}


static struct file_operations corrupter_module_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = corrupter_ioctl,
	.compat_ioctl = corrupter_ioctl,
};

static struct miscdevice corrupter_module_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "corrupter_module",
	.fops = &corrupter_module_fops,
};

static int __init corrupter_module_init(void) {
	int ret;

	ret = misc_register(&corrupter_module_misc);
	if (unlikely(ret)) {
		printk(KERN_ERR "corrupter_module: failed to register misc device.\n");
		return ret;
	}

	printk(KERN_INFO "corrupter_module: initialized\n");
	
	return 0;
}


static void __exit corrupter_module_exit(void) {
	misc_deregister(&corrupter_module_misc);
	printk(KERN_INFO "corrupter_module: unloaded\n");
}

module_init(corrupter_module_init);
module_exit(corrupter_module_exit);

MODULE_LICENSE("GPL");
