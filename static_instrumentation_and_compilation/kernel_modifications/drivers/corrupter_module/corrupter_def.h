#ifndef __TCAST_TRACER_H__
#define __TCAST_TRACER_H__

// #include <linux/assoc_array.h>
#define PDEBUG(format, args...) printk(KERN_DEBUG "[CORRUPTER]: " format, ##args)
#define PCRIT(format, args...) printk(KERN_CRIT "[CORRUPTER]: " format, ##args)

struct corrupter_args {
        unsigned long long address;
        unsigned long long offset;
        void * data;
        unsigned int size;
        unsigned int only_trace_accesses;
};

void add_address(void * address);
void remove_address(void * address);
void clear_allocations(void);

#define CORRUPT_ADDRESS         1
#define UNTRACE_CORRUPTION      5
#define ENABLE_TRACKING         8
#define DISABLE_TRACKING        16
#define CLEAR_ALLOCATIONS       32
#define READ_KERNEL_MEMORY      64

// #define SET_PARAMETERS          4
// #define PRINT_PARAMETERS        5

#endif
