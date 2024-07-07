# Setting up

Copy these 2 folders and merge with your kernel source code. Then modify `drivers/Makefile` and `drivers/Kconfig` with `obj-$(CONFIG_CORRUPTER_MODULE)  += corrupter_module/`  and `source "drivers/corrupter_module/Kconfig"` respectively.

# Gotchas

If during compilation you get an error like `error: memset changed binding to STB_GLOBAL`, it's because DWARF2 only supports one section per compilation unit. To fix that you need to add `KBUILD_CFLAGS += -gdwarf-4` to the Makefile.
