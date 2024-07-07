import sys,os
import re

def is_problematic_input_file(input_file):
    if input_file.find("tracer_module") >= 0 or input_file.find("playground") >= 0 :
        return True
    #### This code is used to instrument only ./kernel files
    # if input_file.find("/linux-clang-compilable/kernel/") > 0: ## fix this to work in any kernel
    #     # if input_file.find("/",input_file.find("kernel/")+8) >= 0:   # only instrument the c files in kernel not in its subdirectories
    #     #     return True
    #     # else:
    #     return False
    # return True
    #### end of code 
    if (    (input_file.find("empty") >= 0) or
            (input_file.find("arch/") >= 0) or
            (input_file.find("init/") >= 0) or
            (input_file.find("boot/") >= 0) or
            #(input_file.find("certs/") >= 0) or
            (input_file.find("samples/") >= 0) or
            #(input_file.find("net/bpfilter/") >= 0) or
	        (input_file.find("corrupter_module") >= 0) or
            #(input_file.find("scripts/") >= 0) or
            #(input_file.find("include/config/") >= 0) or
            #(input_file.find("kernel/events") >= 0) or
            #(input_file.find("kernel/panic") >= 0) or
            (input_file.find("trace") >= 0)):
            #(input_file.find("signal") >= 0) or
            #(input_file.find("select") >= 0)):
            #(input_file.find("irq") >= 0) or
            #(input_file.find("interrupt") >= 0) or
            #(input_file.find("kernel/bpf") >= 0)):
        return True
    return False

# Getting input file from cmd line. Assumes that all kernel compilation contain the file in the end
args = (' '.join(sys.argv[1:])).split()
input_file = args[-1]
input_file = os.path.join(args[0],args[-1])

if ((input_file[input_file.rfind(".")+1:] not in ["c","c++","cpp"]) or is_problematic_input_file(input_file)):
    exit(1)
try:
    with open(input_file,"r") as fin:
        infile_data = fin.read()
except:
    exit(1)
exit(0)
