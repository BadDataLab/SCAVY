# how to use

1. Read the script (`clang-emit-bc-and-instrument.sh`) and modify the paths in there to the location of your llvm pass and the `python-c-instrumenter.py`
2. Compile the kernel with this script as follows: `make -j6 CC=<path to this folder>/clang-emit-bc-and-instrument.sh`


**NOTE:** Make sure you enable all the flags that Syzkaller wants and that you insert `CONFIG_CORRUPTER_MODULE=y`. Also make sure you enable `KProbe` and debug info.
