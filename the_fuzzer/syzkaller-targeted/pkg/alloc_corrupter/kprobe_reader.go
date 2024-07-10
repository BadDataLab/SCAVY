package alloc_corrupter

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

var IgnoreKfrees = false

var allocated_addr_mapping = make(map[uint64]string)
var allocated_addr_mapping_string = make(map[string][]uint64)
var order uint64 = 0
var allocated_addr_order = make(map[uint64]uint64)
var lock = sync.RWMutex{}

// total tracking is used ot save and see all allocations made at runtime and see how many of each object are being allocated
var totalTrackingLock = sync.RWMutex{}
var Total_alloc_tracking_mode = false                            // this tells our functions to keep storing all the allocations they see
var all_allocated_addr_mapping = make(map[uint64]map[string]int) // only use this mapping for collecting all kernel objects
var all_allocated_addr_mapping_allocated = make(map[uint64]bool) // only use this mapping for collecting only the allocated kernel objects

/**************** Kprobe internal util functions ****************/
func no_fail_command_executor(cmd string, maxfails int) int {
	err := exec.Command("bash", "-c", cmd).Run()
	current_fails := 0
	for err != nil && current_fails < maxfails {
		log.Logf(0, "[?][kprobe_reader.go] Waiting for Kprobe device to become responsive...")
		time.Sleep(50 * time.Millisecond)
		err = exec.Command(cmd).Run()
		fmt.Printf("[!][kprobe_reader.go]err: %v\n", err)
		current_fails += 1
	}
	if current_fails == maxfails {
		return -1
	}
	return 0
}

func Clear_traces(tries int) int {
	return no_fail_command_executor("echo > /sys/kernel/debug/tracing/trace", tries)
}

func Start_tracing(tries int) int {
	log.Logf(0, "[+][kprobe_reader.go] ============== TRACING ENABLED ============== \n")
	return no_fail_command_executor("echo 1 > /sys/kernel/debug/tracing/events/kprobes/enable", tries)
}

func Stop_tracing(tries int) int {
	log.Logf(0, "[-][kprobe_reader.go] ============== TRACING DISABLED ============== \n")
	return no_fail_command_executor("echo 0 > /sys/kernel/debug/tracing/events/kprobes/enable", tries)
}

func set_probes() int {
	ret := no_fail_command_executor(
		"echo 'p:ptcast print_typecast_instruction addr=$arg2 before=+0($arg3):string after=+0($arg4):string' > /sys/kernel/debug/tracing/kprobe_events", 50)
	if ret == -1 {
		log.Fatalf("[!][kprobe_reader.go] Couldn't set up the Kprobe points!")
		return -1
	}

	ret = no_fail_command_executor("echo 'r:pkmallocret __kmalloc $retval' >> /sys/kernel/debug/tracing/kprobe_events", 50)
	if ret == -1 {
		log.Fatalf("[!][kprobe_reader.go] Couldn't set up the Kprobe points!")
		return -1
	}

	ret = no_fail_command_executor("echo 'r:pkmallocret2 kmem_cache_alloc $retval' >> /sys/kernel/debug/tracing/kprobe_events", 50)
	if ret == -1 {
		log.Fatalf("[!][kprobe_reader.go] Couldn't set up the Kprobe points!")
		return -1
	}
	// Comment out the next 5 lines to disable kfree
	if !Total_alloc_tracking_mode {
		ret = no_fail_command_executor("echo 'p:pkfree kfree $arg1' >> /sys/kernel/debug/tracing/kprobe_events", 50)
		if ret == -1 {
			log.Fatalf("[!][kprobe_reader.go] Couldn't set up the Kprobe points!")
			return -1
		}
	}
	return 0
}

func clear_probes() {
	no_fail_command_executor("echo > /sys/kernel/debug/tracing/kprobe_events", 10)
}

/**************** End of Kprobe util functions ****************/

func InitializeKprobe() {
	log.Logf(0, "[.] Clearing probes...")
	clear_probes()
	log.Logf(0, "[+][kprobe_reader.go] Probes cleared!")
	log.Logf(0, "[.] Setting new probes!")
	set_probes()
	log.Logf(0, "[+][kprobe_reader.go] New probes set!")
	// log.Logf(0, "[.] Enabling tracing...")  // tracking is now enabled by the syz-executor (not this)
	// start_tracing(10)
	log.Logf(0, "[+][kprobe_reader.go] Kprobe almost READY (executor must enable tracing)!")
}

func ThreadedKprobeReader() {
	file, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	log.Logf(0, "[+][kprobe_reader.go] Started reading Kprobe pipe!")
	// since there is no EOF we will be stuck in this loop forever :) YAY
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 10 { // done because sometimes we get scuffed lines
			continue
		}
		if !strings.Contains(line, "syz-executor") {
			continue
		}
		// log.Logf(0, "[.] Parsing line: `%v`", line)

		if strings.Contains(line, "pkmallocret") {
			start := strings.Index(line, "arg1=") + 5

			address, err := strconv.ParseUint(line[start+2:], 16, 64)
			if err != nil {
				log.Fatalf("Error parsing `%v` (err: %v)", line[start+2:], err)
			}

			if !Total_alloc_tracking_mode {
				KprobeLock()
				allocated_addr_mapping[address] = ""
				KprobeUnlock()
			} else {
				_, found := allocated_addr_mapping[address]
				TotalTrackingVariablesLock()
				if !found {
					all_allocated_addr_mapping[address] = make(map[string]int)
				}
				all_allocated_addr_mapping_allocated[address] = true
				TotalTrackingVariablesUnlock()
				KprobeLock()
				allocated_addr_order[address] = order
				order += 1
				KprobeUnlock()
				// log.Logf(0, "[.] Mapping has already %d allocations", len(all_allocated_addr_mapping))
			}
		} else if strings.Contains(line, "ptcast:") {
			start := strings.Index(line, "addr=") + 5
			end := start + strings.Index(line[start:], " ")

			tcast_addr, _ := strconv.ParseUint(line[start+2:end], 16, 64)

			KprobeLock()
			_, found := allocated_addr_mapping[tcast_addr]
			KprobeUnlock()

			if found {
				start := strings.Index(line, "before=") + 7
				end := start + strings.Index(line[start:], " ")
				tcast_before := line[start+1 : end-1] //strings.Replace(line[start:end], "\"", "", -1)

				start = strings.Index(line, "after=") + 6
				tcast_after := line[start+1 : len(line)-1] //strings.Replace(line[start:], "\"", "", -1)

				before_struct := strings.Contains(tcast_before, "struct.")
				after_struct := strings.Contains(tcast_after, "struct.")

				if !(before_struct || after_struct) {
					continue
				}
				if Total_alloc_tracking_mode {
					TotalTrackingVariablesLock()
					if all_allocated_addr_mapping_allocated[tcast_addr] {
						if before_struct {
							all_allocated_addr_mapping[tcast_addr][tcast_before] = 1
						} else if after_struct {
							all_allocated_addr_mapping[tcast_addr][tcast_after] = 1
						}
						all_allocated_addr_mapping_allocated[tcast_addr] = false
					}
					TotalTrackingVariablesUnlock()
				} else {
					KprobeLock()
					if before_struct {
						allocated_addr_mapping[tcast_addr] = tcast_before
						if _, ok := allocated_addr_mapping_string[tcast_before]; ok {
							allocated_addr_mapping_string[tcast_before] = append(allocated_addr_mapping_string[tcast_before], tcast_addr)
						} else {
							allocated_addr_mapping_string[tcast_before] = make([]uint64, 1)
							allocated_addr_mapping_string[tcast_before][0] = tcast_addr
						}
					} else if after_struct {
						allocated_addr_mapping[tcast_addr] = tcast_after
						if _, ok := allocated_addr_mapping_string[tcast_after]; ok {
							allocated_addr_mapping_string[tcast_after] = append(allocated_addr_mapping_string[tcast_after], tcast_addr)
						} else {
							allocated_addr_mapping_string[tcast_after] = make([]uint64, 1)
							allocated_addr_mapping_string[tcast_after][0] = tcast_addr
						}
					}
					KprobeUnlock()
				}
			}
		} else if strings.Contains(line, "pkfree:") {
			if IgnoreKfrees {
				continue
			}
			start := strings.Index(line, "arg1=") + 5
			freed_address, _ := strconv.ParseUint(line[start+2:], 16, 64)

			if GlobalCorrupterState.IsReady && GlobalCorrupterState.TrackingCorruption &&
				GlobalCorrupterState.LatestCorruptionStats.Corruption.corruptionAddress == freed_address {
				if ok, _, _ := GlobalCorrupterState.DisableAndSaveLatestCorruption(); ok {
					log.Logf(0, "[+][kprobe_reader.go] Corruption tracking stopped due to object (%s at address %s)!",
						GlobalCorrupterState.LatestCorruptionStats.Corruption.CorruptionType,
						fmt.Sprintf("%x", GlobalCorrupterState.LatestCorruptionStats.Corruption.corruptionAddress),
					)
				} else {
					log.Logf(0, "[!!][kprobe_reader.go] Corruption tracking didn't stop properly!!! (%s at address %s)!",
						GlobalCorrupterState.LatestCorruptionStats.Corruption.CorruptionType,
						fmt.Sprintf("%x", GlobalCorrupterState.LatestCorruptionStats.Corruption.corruptionAddress),
					)
				}
			}
		}
	}
}

func ClearAllocs() {
	KprobeLock()
	TotalTrackingVariablesLock()
	allocated_addr_mapping = make(map[uint64]string)
	allocated_addr_mapping_string = make(map[string][]uint64)
	all_allocated_addr_mapping = make(map[uint64]map[string]int)
	all_allocated_addr_mapping_allocated = make(map[uint64]bool)
	order = 0
	allocated_addr_order = make(map[uint64]uint64)

	GlobalCorrupterState.DisableAndSaveLatestCorruption()

	TotalTrackingVariablesUnlock()
	KprobeUnlock()
}

func KprobeLock() {
	lock.Lock()
}

func KprobeUnlock() {
	lock.Unlock()
}

func TotalTrackingVariablesLock() {
	totalTrackingLock.Lock()
}

func TotalTrackingVariablesUnlock() {
	totalTrackingLock.Unlock()
}

func KprobeGetTotalMap() map[uint64]map[string]int {
	return all_allocated_addr_mapping
}

func KprobeGetMap() map[uint64]string {
	return allocated_addr_mapping
}

func KprobeGetTypeAddrMap() map[string][]uint64 {
	return allocated_addr_mapping_string
}

func KprobeGetAddrOrderMapping() map[uint64]uint64 {
	return allocated_addr_order
}

func ClearAllocsAndStopTracing() {
	Stop_tracing(10)
	for {
		ClearAllocs()
		time.Sleep(5 * time.Millisecond)
		KprobeLock()
		if len(KprobeGetMap()) == 0 {
			KprobeUnlock()
			return
		}
		KprobeUnlock()
	}
}
