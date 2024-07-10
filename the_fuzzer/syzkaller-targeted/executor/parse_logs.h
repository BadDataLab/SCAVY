// for the kprobe parser
#include <fstream>
#include <unordered_map>
#include <sys/wait.h>
#include <unistd.h>
#include <iostream>
// for the driver interactions
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stddef.h>
#include <unistd.h>

struct corrupter_args {
	unsigned long long address;
	unsigned long long offset;
	void * data;
	unsigned int size;
};

struct allocated_obj {
	unsigned long long address;
	std::string type;
};

struct corruption {
	struct allocated_obj* obj;
	int offset;
	void * data;
	unsigned int data_length;
	bool is_active;
};

unsigned long long order_of_allocation = 0;
unsigned long long addr_alloc_order[1000]; // at most we track 1000 allocations
std::unordered_map<unsigned long long, allocated_obj*> allocated_addr_mapping;

namespace kprobe {
	static int kprobe_register_pid(int pid){ // observation: these 2 functions below don't filter kprobe stuff :(
		char command[60];
		snprintf(command,60,"echo %d >> /sys/kernel/debug/tracing/set_ftrace_pid",pid);
		return system(command);
	}

	static int kprobe_remove_pid(int pid) {
		char command[150];
		snprintf(command,150,"echo \"`cat /sys/kernel/debug/tracing/set_ftrace_pid | grep %d --invert-match`\" > /sys/kernel/debug/tracing/set_ftrace_pid",pid);
		return system(command);
	}

	static int clear_traces() {
		int ret = system("echo > /sys/kernel/debug/tracing/trace");
		while (ret > 0){ 	
			sleep(1);
			ret = system("echo > /sys/kernel/debug/tracing/trace");
		}
		return ret;
	}

	static int start_tracing() {
		return system("echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable");
	}

	static int stop_tracing() {
		return system("echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable");
	}
	static int probe_kfrees() {
		int ret = system("echo \'p:pkfree kfree $arg1\' >> /sys/kernel/debug/tracing/kprobe_events");
		while (ret > 0) { 
			sleep(1);
			ret = system("echo \'p:pkfree kfree $arg1\' >> /sys/kernel/debug/tracing/kprobe_events");
		}
		return ret;
	}
	static int probe_kmallocs() {
		int ret = system("echo \'r:pkmallocret __kmalloc $retval\' >> /sys/kernel/debug/tracing/kprobe_events");
		while (ret > 0){ 
			sleep(1);
			ret = system("echo \'r:pkmallocret __kmalloc $retval\' >> /sys/kernel/debug/tracing/kprobe_events");
		}

		ret = system("echo \'r:pkmallocret2 kmem_cache_alloc $retval\' >> /sys/kernel/debug/tracing/kprobe_events");
		while (ret > 0){ 
			sleep(1);
			ret = system("echo \'r:pkmallocret2 kmem_cache_alloc $retval\' >> /sys/kernel/debug/tracing/kprobe_events");
		}
		return ret;
	}
	static int set_probes() {
		int ret;
		ret = system("echo \'p:ptcast print_typecast_instruction addr=$arg2 before=+0($arg3):string after=+0($arg4):string\' > /sys/kernel/debug/tracing/kprobe_events");
		while (ret > 0){ 	
			sleep(1);
			ret = system("echo \'p:ptcast print_typecast_instruction addr=$arg2 before=+0($arg3):string after=+0($arg4):string\' > /sys/kernel/debug/tracing/kprobe_events");
		}
		ret = probe_kmallocs();
		ret = probe_kfrees();
		return ret;
	}

	static int clear_probes() {
		int ret = system("echo > /sys/kernel/debug/tracing/kprobe_events");
		while (ret > 0){ 
			ret = system("echo > /sys/kernel/debug/tracing/kprobe_events");
			sleep(1);
		}
		return ret;
	}
}

static void setup_kprobe_tracer() {
	int ret = 0;
	ret = kprobe::clear_probes();
	if (ret > 0) {
		printf("[!] clear probes error\n");
		exit(6);
	}
	ret = kprobe::set_probes();
	if (ret > 0) {
		printf("[!] set probes error\n");
		exit(6);
	}
	ret = kprobe::clear_traces();
	if (ret > 0) {
		printf("[!] clear traces error\n");
		exit(6);
	}
	ret = kprobe::start_tracing();
	if (ret > 0) {
		printf("[!] start tracing error\n");
		exit(6);
	}
}

static void* parse_kprobe_logs(void * kprobe_line_filter) {
	std::fstream kprobe_pipe;
	kprobe_pipe.open("/sys/kernel/debug/tracing/trace_pipe",std::fstream::in);

	for( std::string line; getline( kprobe_pipe, line ); ) {
		if (line.length() < 10)
			continue;
		if (line.find((char*)kprobe_line_filter) == std::string::npos) {
			continue;
		}
		// printf("LINE: %s\n",line.c_str());
		if ((line.find("pkmallocret:") != std::string::npos) || 
			(line.find("pkmallocret2:") != std::string::npos)) {
			
			int start = line.find("arg1=") + 5;
			int end = line.find(" ",start);
			if (end < 0) end = line.length();
			std::string alloc_addr = line.substr(start,end);
			unsigned long long address = strtoull(alloc_addr.c_str(),NULL,16);
			allocated_obj* new_allocation = new allocated_obj{address,""};
		
			allocated_addr_mapping.insert({address,new_allocation});
			addr_alloc_order[order_of_allocation] = address;
			order_of_allocation++;
		} else if (line.find("ptcast:") != std::string::npos) {
			int start = line.find("addr=") + 5;
			int end = line.find(" ",start);
			std::string tcast_addr_str = line.substr(start,end-start);
			unsigned long long tcast_addr = strtoull(tcast_addr_str.c_str(),NULL,16);

			std::unordered_map<unsigned long long,allocated_obj*>::const_iterator iter;
			iter = allocated_addr_mapping.find(tcast_addr);

			if (iter != allocated_addr_mapping.end()) {
				allocated_obj* to_edit = iter->second;

				int start = line.find("before=\"") + 9;
				int end = line.find("\"",start);
				std::string tcast_before = line.substr(start,end-start);

				start = line.find("after=\"",end+1) + 7;
				end = line.find("\"",start);
				std::string tcast_after = line.substr(start,end-start);

				int before_struct = tcast_before.find("struct.");
				int after_struct = tcast_after.find("struct.");
				if (before_struct < 0 && after_struct < 0){
					continue;
				}
				if ((before_struct >= 0) && (after_struct > 0)) {
					to_edit->type = tcast_before;
				} else if (before_struct >= 0) {
					to_edit->type = tcast_before;
				} else if (after_struct >= 0) {
					to_edit->type = tcast_after;
				}
				// std::cout << "Got typecast for address `"<< (void*)to_edit->address << "` (" << tcast_addr_str;
				// std::cout << ") parsed(1: `"<< tcast_before <<"` ||| 2: `" << tcast_after << "`)\n";
			}
		} else if (line.find("pkfree") != std::string::npos) {
			int start = line.find("arg1=") + 5;
			int end = line.find(" ",start);
			if (__glibc_likely( end < 0) ) end = line.length();
			std::string addr_string = line.substr(start,end);
			unsigned long long freed_address = strtoull(addr_string.c_str(),NULL,16);
			free(allocated_addr_mapping[freed_address]);
			allocated_addr_mapping.erase(freed_address);
		}

	}
	return NULL;
}

static void start_parse_kprobe_logs(char * filter_string) {
	pthread_t th;
	for (int i = 0; i < 100; i++) {
		if (pthread_create(&th, NULL, parse_kprobe_logs, (void*)filter_string) == 0) {
			return;
		}
		if (errno == EAGAIN) {
			sleep(1);
			continue;
		}
		break;
	}
	fprintf(stderr, "[-] Failed to start Kprobe parser thread!\n");
}


//////// This code is to define the globals and the functions needed for the multithreaded kprobe parsing
int pipe_parser_to_exec[2],pipe_exec_to_parser[2];
int pipes_initialized = 0;


void close_pipes() {
	if (pipes_initialized == 0) return;
	close(pipe_parser_to_exec[0]);
	close(pipe_parser_to_exec[1]);

	close(pipe_exec_to_parser[0]);
	close(pipe_exec_to_parser[1]);
	pipes_initialized = 0;
}

int corrupt_address(struct corruption* corruption) {
	int corrupterfd = open("/dev/corrupter_module", O_RDONLY);
	if (corrupterfd == -1) {
		return -1;
	}

	struct corrupter_args args;
	args.address = corruption->obj->address;
	args.offset = corruption->offset;
	args.data = corruption->data;
	args.size = corruption->data_length;

	int toreturn = ioctl(corrupterfd, 1, &args);
	close(corrupterfd);
	
	if (toreturn == 0) {
		corruption->is_active = true;
	}
	return toreturn;
}

int untrace_address(struct corruption* corruption) {
	int corrupterfd = open("/dev/corrupter_module", O_RDONLY);
	if (corrupterfd == -1 || !corruption->is_active) {
		return -1;
	}

	struct corrupter_args args;
	args.address = corruption->obj->address;
	args.offset = corruption->offset;
	args.data = 0;
	args.size = 0;

	int toreturn = ioctl(corrupterfd, 5, &args);
	close(corrupterfd);

	if (toreturn == 0) {
		corruption->is_active = false;
	}
	return toreturn;
}

int init_pipes() {
	close_pipes();
	if (pipe(pipe_parser_to_exec) == -1) {
  		printf("[!] pipe failed!\n");
		exit(2);
	}
	if (pipe(pipe_exec_to_parser) == -1) {
		printf("[!] pipe 2 failed!\n");
		exit(2);
	}
	pipes_initialized = 1;
}

int setup_executor_with_pipes() {
	close(pipe_parser_to_exec[1]);
	close(pipe_exec_to_parser[0]);

	char RW = 'B';

	// wait for parent to tell us kprobe is ready
	read(pipe_parser_to_exec[0],&RW,sizeof(char));
	printf("[+] Started the syscalls!\n");
}

int start_parser_thread_and_corrupt(char* to_corrupt, int order, int offset, void * data, unsigned int data_length) {
	init_pipes();

	int pid = fork();
	if (pid < 0) {
		printf("[!] fork() failed!");
		exit(1);
	}
	if (pid > 0) {
		close(pipe_parser_to_exec[0]);
		close(pipe_exec_to_parser[1]);
		// creating the filter string
		std::string filter = "-" + std::to_string(pid) + " "; 

		printf("[+] Started the parser for pid: %d!\n",pid);
		
		// here we start the parser
		// kprobe::kprobe_register_pid(pid);
		setup_kprobe_tracer();
		// start_parse_kprobe_logs((char*)filter.c_str());

		char toWrite = 'A';

		// notify the child we are ready
		write(pipe_parser_to_exec[1],&toWrite,sizeof(char));

		// wait for child to tell us to do the corruption
		read(pipe_exec_to_parser[0],&toWrite,sizeof(char));

		// kprobe::kprobe_remove_pid(pid);
		kprobe::stop_tracing();
		kprobe::clear_probes();
		sleep(1); // 1 second is enough for the parser to parse stuff
		kprobe::probe_kfrees();
		kprobe::clear_traces();
		kprobe::start_tracing();
		
		// print objects still left allocated
		// for ( auto it = allocated_addr_mapping.begin(); it != allocated_addr_mapping.end(); ++it ) {
		// 	printf("\t%s -> %p\n",it->second->type.c_str(),it->second->address);
		// }

		// Find the address that we want to corrupt
		int current_order = 0;
		allocated_obj* found_addr = NULL, *current_addr;
		for (int i = 0; i < order_of_allocation; i++) {
			if (allocated_addr_mapping.find(addr_alloc_order[i]) == allocated_addr_mapping.end()) continue;
			current_addr = allocated_addr_mapping[addr_alloc_order[i]];

			if (strcmp(current_addr->type.c_str(),to_corrupt) == 0) {
				if (order == current_order) {
					found_addr = current_addr;
				} else {
					current_order++;
				}
			}
		}
		struct corruption* corr = NULL;
		if (found_addr != NULL) {
			corr = new corruption{found_addr,offset,data,data_length};
			if (corrupt_address(corr) == 0) {
				printf("[+] Corruption succeeded!\n");
			} else {
				printf("[-] Corruption failed!\n");
				free(corr);
			}
		} else {
			printf("[!] Object to corrupt not found!\n");
		}
		

		// sleep(1); 
		write(pipe_parser_to_exec[1],&toWrite,sizeof(char)); // notify the child that the corruption is done

		int status = 0;
		if (waitpid(-1, &status, WUNTRACED) == pid) {
			printf("[+] Ended the parser! -- %d objects still allocated\n",allocated_addr_mapping.size());
			if (corr != NULL) {
				untrace_address(corr);
				free(corr);
			}
			kprobe::stop_tracing();
			kprobe::clear_probes();
			kprobe::clear_traces();
			// printf("[.] Parser indicates %d objects are allocated\n", allocated_addr_mapping.size());
			// for ( auto it = allocated_addr_mapping.begin(); it != allocated_addr_mapping.end(); ++it ) {
			// 	printf("\t%s -> %p\n",it->second->type.c_str(),it->second->address);
			// }
			exit(0);
		} else {
			fprintf(stderr, "[-] Smth went wrong!!! We cry now :'(\n");
			exit(1);
		}
	}
	if (pid == 0) {
		setup_executor_with_pipes();
	}
}

void stop_execution_and_wait_corrupter() {
	char RW = 'B';
	write(pipe_exec_to_parser[1],&RW,sizeof(char));
	read(pipe_parser_to_exec[0],&RW,sizeof(char));
	printf("[?] Corruption should be done or failed!\n");
}
