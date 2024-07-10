package alloc_corrupter

import (
	"bufio"
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/google/syzkaller/pkg/log"
)

// THIS IS THE MEAT OF THIS WHOLE FILE (3 variables to track corruption)
var GlobalCorrupterState = CorrupterState{IsReady: false, fd: nil, LatestCorruptionStats: nil, TrackingCorruption: false, TrackingModeOnly: true}

type CorrupterState struct {
	IsReady               bool
	fd                    *os.File
	TotalCorrStats        *TotalCorruptionStats
	TrackingCorruption    bool
	LatestCorruptionStats *CorruptionStats
	TrackerLock           sync.RWMutex

	TrackingModeOnly bool // in this mode the corrupter will not corrupt but only track memory accesses
}

type Corruption struct {
	corruptionActive  bool   // is the corruption active or not (not exported)
	corruptionAddress uint64 // the address of existing corruption

	CorruptionSize   uint8
	CorruptionOffset uint16 // offset from start of the memory address
	CorruptionType   string // object type that will be corrupted
	CorruptionOrder  uint32 // which object of that type is it based of its allocation order (starts from 0)
	CorruptionData   []byte // data we used to corrupt (for now we dont care and fill with random data)
}

type CoverMap map[uint32]struct{} // had to redeclare coverage because fucking GO doesnt allow cycle import

type CorruptionStats struct {
	Corruption *Corruption

	NumHits   uint64            // total number of times our corruption was read
	ReadAddrs map[uint64]uint32 // addresses that read our corruption and how many times we hit those instruction addresses
	Coverage  CoverMap          //coverage of the kernel code after the corruption
}

type TotalCorruptionStats struct {
	TotalNumHits uint64
	// TotalReadAddrs map[uint64]uint32 // I dont think this information is significant to the fuzzer in any way

	CorruptionsStats []CorruptionStats
}

// COPIED FROM cover.go, because can't fucking import it. GOSHIT will cry about cycle imports
func (cov *CoverMap) MergeDiff(raw []uint32) []uint32 {
	//log.Logf(3, "func (cov *CoverMap) MergeDiff(raw []uint32) []uint32 CALLED!")
	c := *cov
	if c == nil {
		c = make(CoverMap)
		*cov = c
	}
	n := 0
	for _, pc := range raw {
		if _, ok := c[pc]; ok {
			continue
		}
		c[pc] = struct{}{}
		raw[n] = pc
		n++
	}
	return raw[:n]
}

func (cov *CoverMap) Merge(raw []uint32) {
	//log.Logf(3, "func (cov *CoverMap) Merge(raw []uint32) CALLED!")
	c := *cov
	if c == nil {
		c = make(CoverMap)
		*cov = c
	}
	for _, pc := range raw {
		c[pc] = struct{}{}
	}
}

/*********************** CorruptionStats and TotalCorruptionStats functions ***************************/

func (cstats *CorruptionStats) Merge(cstats2 *CorruptionStats) bool {
	//log.Logf(3, "func (cstats *CorruptionStats) Merge(cstats2 *CorruptionStats) bool CALLED!")
	if cstats.Corruption == nil {
		log.Fatalf("[corruption_tracker.go][!] This was not supposed to happen!")
		return false // WHY DID THIS EVEN HAPPEN?
	}
	newCorruptionIsLarger := false
	cstats.Corruption.corruptionActive = cstats.Corruption.corruptionActive || cstats2.Corruption.corruptionActive
	if cstats2.Corruption.corruptionActive {
		cstats.Corruption.corruptionAddress = cstats2.Corruption.corruptionAddress
	}
	if cstats.ReadAddrs == nil {
		cstats.ReadAddrs = make(map[uint64]uint32)
		log.Logf(0, "[!][corruption_tracker.go][corruption_tracker.go] corruption-tracker Merge(): cstats was not supposed to be nil!\n")
		cstats.ReadAddrs = cstats2.ReadAddrs
		return true
	}
	for k := range cstats2.ReadAddrs {
		if _, ok := cstats.ReadAddrs[k]; ok {
			if cstats2.ReadAddrs[k] > cstats.ReadAddrs[k] {
				cstats.ReadAddrs[k] = cstats2.ReadAddrs[k]
				newCorruptionIsLarger = true
			}
		} else {
			cstats.ReadAddrs[k] = cstats2.ReadAddrs[k]
			newCorruptionIsLarger = true
		}
	}
	keys := make([]uint32, 0, len(cstats2.Coverage))
	for k := range cstats2.Coverage {
		keys = append(keys, k)
	}
	if diff := cstats.Coverage.MergeDiff(keys); len(diff) > 0 {
		newCorruptionIsLarger = true
	}
	if cstats2.NumHits > cstats.NumHits {
		cstats.NumHits = cstats2.NumHits
		newCorruptionIsLarger = true
	}
	return newCorruptionIsLarger
}

func (cstats *CorruptionStats) Invalidate() {
	//log.Logf(3, "func (cstats *CorruptionStats) Invalidate() CALLED!")
	cstats.Corruption.corruptionActive = false
	cstats.Corruption.corruptionAddress = 0
}

// insert new corruption and return index where that new corruption is
// or just return -1 on error
func (tcs *TotalCorruptionStats) InsertCorruptionStats(cs *CorruptionStats) (int, bool) {
	//log.Logf(3, "func (tcs *TotalCorruptionStats) InsertCorruptionStats(cs *CorruptionStats) int CALLED!")
	if cs == nil || cs.Corruption == nil {
		return -1, false
	}
	c, idx := tcs.FindCorruptionStats(cs.Corruption.CorruptionType, cs.Corruption.CorruptionOffset, cs.Corruption.CorruptionSize)
	if c != nil {
		oldHits := c.NumHits
		is_larger := c.Merge(cs)
		tcs.TotalNumHits += (c.NumHits - oldHits)
		return idx, is_larger
	}
	tcs.TotalNumHits += cs.NumHits
	tcs.CorruptionsStats = append(tcs.CorruptionsStats, *cs)
	return len(tcs.CorruptionsStats) - 1, true
}

// finds a corruption type
func (tcs *TotalCorruptionStats) FindCorruptionStats(CorruptionType string, CorruptionOffset uint16, CorruptionSize uint8) (*CorruptionStats, int) {
	//log.Logf(3, "func (tcs *TotalCorruptionStats) FindCorruptionStats(CorruptionType string, CorruptionOffset uint16, CorruptionSize uint8) *CorruptionStats CALLED!")
	if tcs == nil {
		tcs = &TotalCorruptionStats{
			TotalNumHits:     0,
			CorruptionsStats: make([]CorruptionStats, 0, 10),
		}
	}

	if len(tcs.CorruptionsStats) == 0 {
		return nil, -1
	}
	for idx, c := range tcs.CorruptionsStats {
		if c.Corruption == nil {
			log.Logf(3, "[!][corruption_tracker.go] TotalCorruptionStats.FindCorruptionStats() error: Corruption is nil, but it's never supposed to be!")
			// log.Logf(0, "[?][corruption_tracker.go] Here is how tcs looks like! %v", tcs)
			return nil, -1
		}
		// they are the same corruption with just different data maybe (for now we dont care about the data)
		if (c.Corruption.CorruptionType == CorruptionType) &&
			(c.Corruption.CorruptionOffset == CorruptionOffset) &&
			(c.Corruption.CorruptionSize == CorruptionSize) {
			return &c, idx
		}
	}
	return nil, -1
}

/*********************** CorrupterState functions ***************************/

func (corrupter *CorrupterState) TrackNewCorruption(corr *Corruption) *CorruptionStats {
	//log.Logf(3, "func (corrupter *CorrupterState) TrackNewCorruption(corr *Corruption) *CorruptionStats CALLED!")
	if corrupter.TrackingCorruption { // module already has set the hardware breakpoints, can't track more corruptions
		return nil
	}

	KprobeLock()
	defer KprobeUnlock()
	if !corrupter.IsReady {
		log.Fatalf("[corruption_tracker.go][?] WARNING: Uninitialized corrupter!\n")
		return nil
	}

	typeAdds := KprobeGetTypeAddrMap()
	orderMap := KprobeGetAddrOrderMapping()

	if _, ok := typeAdds[corr.CorruptionType]; !ok {
		log.Logf(3, "[!][corruption_tracker.go] Not finding the object type `%v`.\n", corr.CorruptionType)
		return nil
	}

	for _, addr := range typeAdds[corr.CorruptionType] {
		if orderMap[addr] == uint64(corr.CorruptionOrder) {
			toreturn := CorruptionStats{
				Corruption: corr,

				NumHits:   0,
				ReadAddrs: make(map[uint64]uint32),
				Coverage:  make(CoverMap),
			}
			corr.corruptionAddress = addr
			corr.corruptionActive = true

			// corrupting address `addr` at the given offset and some random data
			if corrupter.trackExistingCorruption(&toreturn) {
				log.Logf(0, "[+][corruption_tracker.go] Successfully corrupted program at (corruption: %v)", corr)
				return &toreturn
			} else {
				return nil
			}
		}
	}
	log.Fatalf("[corruption_tracker.go][!] TrackNewCorruption() order didn't match!\n")
	return nil
}

// Never call this function without calling KprobeLock()
func (corrupter *CorrupterState) trackExistingCorruption(cstats *CorruptionStats) bool {
	//log.Logf(3, "func (corrupter *CorrupterState) TrackExistingCorruption(cstats *CorruptionStats) bool CALLED!")
	if corrupter.TrackingCorruption { // module already has set the hardware breakpoints, can't track more corruptions
		return false
	}

	if !corrupter.IsReady {
		log.Fatalf("[corruption_tracker.go][!] Uninitialized corrupter!\n")
		return false
	}

	if cstats == nil {
		return false
	}

	if !cstats.Corruption.corruptionActive {
		log.Fatalf("[corruption_tracker.go][!] Invalid corruption!\n")
		return false
	}

	if !corrupter.CorruptRaw(cstats.Corruption.corruptionAddress, cstats.Corruption.CorruptionOffset,
		cstats.Corruption.CorruptionSize, cstats.Corruption.CorruptionData) {
		return false
	}
	corrupter.TrackerLock.Lock()
	corrupter.LatestCorruptionStats = cstats
	corrupter.TrackingCorruption = true
	cstats.Corruption.corruptionActive = true
	// allActiveCorruptions[cstats.Corruption.corruptionAddress] = cstats    // ---- This is done if we have multiple corruptions ----
	corrupter.RegisterCorruptionStats(cstats) // merge with all the knowledge we have already before we crash
	corrupter.TrackerLock.Unlock()

	return true
}

func (corrupter *CorrupterState) CorruptRaw(address uint64, offset uint16, size uint8, data []byte) bool {
	//log.Logf(3, "func (corrupter *CorrupterState) CorruptRaw(address uint64, offset uint16, size uint8, data []byte) bool CALLED!")
	if corrupter.TrackingCorruption {
		return true
	}
	// this struct definition shall never exist outside of this function because we dont
	// want to have other locations mess with our very well tested driver (Kappa)
	type corrupter_args struct {
		address             uint64
		offset              uint64
		data                uintptr
		size                uint32
		only_trace_accesses uint32
	}
	var only_trace_accesses uint32 = 0
	if corrupter.TrackingModeOnly {
		only_trace_accesses = 1
	}
	args := corrupter_args{address: address, offset: uint64(offset), data: uintptr(unsafe.Pointer(&data)), size: uint32(size), only_trace_accesses: only_trace_accesses}

	log.Logf(3, "[+][corruption_tracker.go] CORRUPTER: Corrupting address `%s` with data `%v`\n", fmt.Sprintf("%x", address), data)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(corrupter.fd.Fd()), 1, uintptr(unsafe.Pointer(&args))); errno != 0 {
		log.Logf(3, "[corruption_tracker.go][!] Error in performing the memory corruption: %v\n", errno)
		return false
	}
	return true
}

func (corrupter *CorrupterState) InitializeWithStats(tcs *TotalCorruptionStats) (bool, error) {
	//log.Logf(3, "func (corrupter *CorrupterState) InitializeWithStats(tcs *TotalCorruptionStats) (bool, error) CALLED!")
	if corrupter.IsReady {
		return true, nil
	}
	if corrupter.fd == nil {
		fd, err := os.Open("/dev/corrupter_module")
		if err != nil {
			log.Fatalf("[corruption_tracker.go][!] %v\n", err)
			return false, err
		}
		corrupter.fd = fd
	}
	if tcs == nil {
		corrupter.TotalCorrStats = &TotalCorruptionStats{
			TotalNumHits:     0,
			CorruptionsStats: make([]CorruptionStats, 0, 10),
		}
	} else {
		corrupter.TotalCorrStats = tcs
		for _, c := range corrupter.TotalCorrStats.CorruptionsStats {
			if c.ReadAddrs == nil {
				c.ReadAddrs = make(map[uint64]uint32)
			}
			if c.Coverage == nil {
				c.Coverage = make(CoverMap)
			}
		}
	}
	corrupter.IsReady = true

	go corrupter.ThreadedDmesgParser()

	return true, nil
}

func (corrupter *CorrupterState) Initialize(filename string) (bool, error) {
	//log.Logf(3, "func (corrupter *CorrupterState) Initialize(filename string) (bool, error) CALLED!")
	if corrupter.IsReady {
		return true, nil
	}
	if corrupter.fd == nil {
		fd, err := os.Open("/dev/corrupter_module")
		if err != nil {
			log.Fatalf("[corruption_tracker.go][!] %v\n", err)
			return false, err
		}
		corrupter.fd = fd
	}

	err := corrupter.LoadCorruptionStats(filename)
	if err != nil {
		log.Fatalf("[corruption_tracker.go][!] %v\n", err)
		return false, err
	}
	go corrupter.ThreadedDmesgParser()

	corrupter.IsReady = true

	return true, nil
}

func (corrupter *CorrupterState) LoadCorruptionStats(filename string) error {
	//log.Logf(3, "func (corrupter *CorrupterState) LoadCorruptionStats(filename string) error CALLED!")
	fi, err := os.Open(filename)
	if err != nil {
		corrupter.TotalCorrStats = &TotalCorruptionStats{
			TotalNumHits:     0,
			CorruptionsStats: make([]CorruptionStats, 0, 10),
		}
		log.Logf(0, "[.][corruption_tracker.go] Corruption statistics file not found! Starting fresh!")
		corrupter.StoreCorruptionStats(filename)
		return nil
	}
	defer fi.Close()

	fz, err := gzip.NewReader(fi)
	if err != nil {
		return err
	}
	defer fz.Close()

	decoder := gob.NewDecoder(fz)
	err = decoder.Decode(corrupter.TotalCorrStats)
	if err != nil {
		return err
	}
	return nil
}

func (corrupter *CorrupterState) StoreCorruptionStats(filename string) error {
	//log.Logf(3, "func (corrupter *CorrupterState) StoreCorruptionStats(filename string) error CALLED!")
	fi, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer fi.Close()

	fz := gzip.NewWriter(fi)
	defer fz.Close()

	encoder := gob.NewEncoder(fz)
	err = encoder.Encode(corrupter.TotalCorrStats)
	if err != nil {
		return err
	}

	return nil
}

// wrapper to be called from CorrupterState because why not
func (corrupter *CorrupterState) RegisterCorruptionStats(cstats *CorruptionStats) (int, bool) {
	//log.Logf(3, "func (corrupter *CorrupterState) RegisterCorruptionStats(cstats *CorruptionStats) int CALLED!")
	return corrupter.TotalCorrStats.InsertCorruptionStats(cstats)
}

func (corrupter *CorrupterState) DisableAndSaveLatestCorruption() (bool, int, bool) {
	//log.Logf(3, "func (corrupter *CorrupterState) DisableAndSaveLatestCorruption() bool CALLED!")
	if !corrupter.TrackingCorruption || corrupter.LatestCorruptionStats == nil {
		return false, -1, false
	}
	corrupter.TrackingCorruption = false
	toreturn, toreturn2, toreturn3 := corrupter.DisableAndSaveCorruption(corrupter.LatestCorruptionStats)
	corrupter.LatestCorruptionStats = nil
	return toreturn, toreturn2, toreturn3
}

func (corrupter *CorrupterState) DisableAndSaveCorruption(cstats *CorruptionStats) (bool, int, bool) {
	//log.Logf(3, "func (corrupter *CorrupterState) DisableAndSaveCorruption(cstats *CorruptionStats) bool CALLED!")
	if cstats == nil || cstats.Corruption == nil || !cstats.Corruption.corruptionActive || cstats.Corruption.corruptionAddress == 0 {
		return false, -1, false
	}
	// this struct definition shall never exist outside of this function because we dont
	// want to have other locations mess with our very well tested driver (Kappa)
	type corrupter_args struct {
		address             uint64
		offset              uint64
		data                uintptr
		size                uint32
		only_trace_accesses uint32
	}

	args := corrupter_args{
		address: cstats.Corruption.corruptionAddress,
		offset:  uint64(cstats.Corruption.CorruptionOffset),
		data:    uintptr(unsafe.Pointer(&cstats.Corruption.CorruptionData)),
		size:    0,
	}
	corrupter.TrackerLock.Lock()
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(corrupter.fd.Fd()), 5, uintptr(unsafe.Pointer(&args))); errno != 0 {
		log.Fatalf("[corruption_tracker.go][!] Error in disabling hardware breakpoint tracing for address `%v`: %v\nw", cstats.Corruption.corruptionAddress, errno)
		corrupter.TrackerLock.Unlock()
		return false, -1, false
	}

	total_corr_idx, is_larger := corrupter.RegisterCorruptionStats(cstats)
	corrupter.TrackingCorruption = false
	cstats.Invalidate()
	corrupter.TrackerLock.Unlock()
	return true, total_corr_idx, is_larger
}

func (corrupter *CorrupterState) ThreadedDmesgParser() {
	//log.Logf(3, "func (corrupter *CorrupterState) ThreadedDmesgParser() CALLED!")
	fd, err := os.Open("/dev/kmsg")
	if err != nil {
		log.Fatal(err)
	}
	defer fd.Close()

	log.Logf(0, "[+][corruption_tracker.go] Started dmesg-based corrupter parser!")
	// since there is no EOF we will be stuck in this loop forever :) YAY
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 10 {
			continue
		}
		if !strings.Contains(line, "[CORRUPTER]") {
			continue
		}
		if !corrupter.TrackingCorruption { // might be 1 line after write that's buffered but with the same IP
			continue
		}
		if strings.Contains(line, "{READ}") || strings.Contains(line, "{WRITE}") {
			startidx := strings.Index(line, "`") + 1
			endidx := strings.LastIndex(line, "`")
			read_addr, _ := strconv.ParseUint(line[startidx+2:endidx], 16, 64)
			corrupter.TrackerLock.Lock()
			corrupter.LatestCorruptionStats.NumHits += 1
			if _, ok := corrupter.LatestCorruptionStats.ReadAddrs[read_addr]; !ok {
				corrupter.LatestCorruptionStats.ReadAddrs[read_addr] = 0
			}
			corrupter.LatestCorruptionStats.ReadAddrs[read_addr] += 1
			corrupter.TrackerLock.Unlock()
		}
	}
}

func (corrupter *CorrupterState) EnableKmallocTracker() bool {
	//log.Logf(3, "func (corrupter *CorrupterState) EnableKmallocTracker() bool CALLED!")
	type corrupter_args struct {
		address             uint64
		offset              uint64
		data                uintptr
		size                uint32
		only_trace_accesses uint32
	}

	args := corrupter_args{address: 0, offset: uint64(0), data: uintptr(0), size: uint32(0), only_trace_accesses: 0}

	log.Logf(3, "[+][corruption_tracker.go] CORRUPTER: Enabling kmalloc tracker!\n")

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(corrupter.fd.Fd()), 8, uintptr(unsafe.Pointer(&args))); errno != 0 {
		log.Fatalf("[corruption_tracker.go][!] Error in enabling kmalloc tracker: %v\n", errno)
		return false
	}

	return true
}

func (corrupter *CorrupterState) DisableKmallocTracker() bool {
	//log.Logf(3, "func (corrupter *CorrupterState) DisableKmallocTracker() bool CALLED!")
	type corrupter_args struct {
		address             uint64
		offset              uint64
		data                uintptr
		size                uint32
		only_trace_accesses uint32
	}

	args := corrupter_args{address: 0, offset: uint64(0), data: uintptr(0), size: uint32(0), only_trace_accesses: 0}

	log.Logf(3, "[+][corruption_tracker.go] CORRUPTER: Disabling kmalloc tracker!\n")

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(corrupter.fd.Fd()), 16, uintptr(unsafe.Pointer(&args))); errno != 0 {
		log.Fatalf("[corruption_tracker.go][!] Error in disabling kmalloc tracker: %v\n", errno)
		return false
	}

	return true
}

func (corrupter *CorrupterState) ClearAllocations() bool {
	//log.Logf(3, "func (corrupter *CorrupterState) ClearAllocations() bool CALLED!")
	type corrupter_args struct {
		address             uint64
		offset              uint64
		data                uintptr
		size                uint32
		only_trace_accesses uint32
	}

	args := corrupter_args{address: 0, offset: uint64(0), data: uintptr(0), size: uint32(0), only_trace_accesses: 0}

	log.Logf(3, "[+][corruption_tracker.go] CORRUPTER: Clearing kmalloc tracker allocations!\n")

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(corrupter.fd.Fd()), 32, uintptr(unsafe.Pointer(&args))); errno != 0 {
		log.Fatalf("[corruption_tracker.go][!] Error in clearing kmalloc tracker allocations: %v\n", errno)
		return false
	}

	return true
}
