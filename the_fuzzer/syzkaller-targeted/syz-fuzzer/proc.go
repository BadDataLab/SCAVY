// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/alloc_corrupter"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	env               *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsNoCollide := *fuzzer.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				log.Logf(0, "[+][proc.go] WorkTriage received!\n\n")
				proc.triageInput(item)
			case *WorkCandidate:
				// if item.p.CorrIndex < 0 {
				// 	log.Logf(0, "[+][proc.go] WorkCandidate received!\n\n")
				proc.fuzzer.workQueue.enqueue(&WorkCorrupt{
					p:     item.p,
					flags: item.flags,
				})
				// } else {
				// 	proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				// }
			case *WorkSmash:
				log.Logf(0, "[+][proc.go] WorkSmash received!\n\n")
				proc.smashInput(item)
			case *WorkCorrupt:
				log.Logf(0, "[+][proc.go] WorkCorrupt received!\n\n")
				proc.corruptInput(item)
			default:
				log.Fatalf("[proc.go][!!] unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			log.Logf(0, "length of corpus is %v and generatePeriod is %v", len(fuzzerSnapshot.corpus), generatePeriod)
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

func (proc *Proc) corruptInput(item *WorkCorrupt) {
	type corrAndIndex struct {
		corr *alloc_corrupter.CorruptionStats
		idx  int
	}
	// skip this if corrupter not setup
	if !alloc_corrupter.GlobalCorrupterState.IsReady {
		if item.flags&ProgSmashed == 0 {
			proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
		} else if item.flags&ProgCandidate == 0 {
			proc.fuzzer.workQueue.enqueue(&WorkCandidate{item.p, item.flags})
		}
		log.Logf(0, "[proc.go][corruptInput][-] #%v: GlobalCorrupterState not ready. LEAVING...", proc.pid)
		return
	}
	p := item.p

	// first we check if the program is already corrupted...
	// then we check its corrupted code coverage
	if item.flags&ProgCorrupted == 0 || p.CorrStats == nil || p.CorrIndex == 0 {
		if len(p.Calls) == 1 {
			log.Logf(0, "[proc.go][corruptInput][-] #%v: program has too few calls. LEAVING...", proc.pid)
			return
		}
		allocation_types := proc.discoverAllocations(proc.execOpts, p, len(p.Calls)-1)
		var bestCandidate *corrAndIndex = nil
		allCandidates := make([]*corrAndIndex, 0, len(allocation_types))
		for index, allocs := range allocation_types {
			if index == 0 {
				continue
			}
			if bestCandidate != nil {
				break
			}
			for _, a := range allocs {
				if len(a) <= 1 {
					continue // we want structure names to be valid, not 1 character strings
				}
				matched_struct := ""
				for s := range proc.fuzzer.structOffsetSize {
					if strings.Contains(a, s) {
						matched_struct = s
						break
					}
				}
				if len(matched_struct) <= 0 {
					continue
				}
				for offset, size := range proc.fuzzer.structOffsetSize[matched_struct] {
					corrstats, _ := alloc_corrupter.GlobalCorrupterState.TotalCorrStats.FindCorruptionStats(a, uint16(offset), uint8(size))
					if corrstats == nil {
						bestCandidate = &corrAndIndex{
							corr: &alloc_corrupter.CorruptionStats{
								Corruption: &alloc_corrupter.Corruption{
									CorruptionSize:   uint8(size),
									CorruptionOffset: uint16(offset),
									CorruptionType:   a,
									CorruptionOrder:  0,
									CorruptionData:   make([]byte, 8),
								},
								NumHits:   0,
								Coverage:  make(alloc_corrupter.CoverMap),
								ReadAddrs: make(map[uint64]uint32),
							},
							idx: index,
						}
						break
					} else {
						allCandidates = append(allCandidates, &corrAndIndex{
							corr: corrstats,
							idx:  index,
						})
					}
				}
			}
		}
		if bestCandidate == nil && len(allCandidates) <= 0 {
			log.Logf(3, "[proc.go][corruptInput][-] #%v: program creates no objects. Skipping...", proc.pid)
			return
		}
		// if we don't have an easy best candidate we pick the one with lowest coverage
		if bestCandidate == nil {
			minhits := 99999999
			mincoverage := 99999999
			for _, c := range allCandidates {
				corr := c.corr
				hits := corr.ReadAddrs
				cov := corr.Coverage
				if len(hits) < minhits {
					minhits = len(hits)
					bestCandidate = c
				} else {
					if len(cov) < mincoverage {
						mincoverage = len(cov)
						bestCandidate = c
					}
				}
			}
		}

		log.Logf(0, "[proc.go][corruptInput][+] #%v: program %s was found at order %d and index %d\n", proc.pid, bestCandidate.corr.Corruption.CorruptionType,
			bestCandidate.corr.Corruption.CorruptionOrder, bestCandidate.idx)

		p.CorrStats = bestCandidate.corr
		p.CorrIndex = bestCandidate.idx

		// choose random data
		rand.Read(p.CorrStats.Corruption.CorruptionData)
		// binary.LittleEndian.PutUint64(p.CorrStats.Corruption.CorruptionData, uint64(0))

		// Corruption set up and ready for execution...
		log.Logf(3, "[proc.go][corruptInput][.] #%v: corrupting program at index %d (type: %s)", proc.pid, p.CorrIndex, p.CorrStats.Corruption.CorruptionType)
		_, tcsIdx := proc.executeRaw(proc.execOptsCover, item.p, 0, true, true) //proc.execute(proc.execOptsCover, item.p, item.flags, StatCorrupt) // executed

		if tcsIdx == -1 {
			log.Logf(3, "[proc.go][corruptInput][!] #%v: program could not be corrupted", proc.pid)
			p.CorrStats = nil
			p.CorrIndex = -1
			if item.flags&ProgSmashed == 0 {
				proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
			}
			return
		} else {
			// Mark as corrupted
			item.flags |= ProgCorrupted
		}
	} else {
		// 2) Program is corrupted ... we choose to recorrupt in another location or not
		choice := rand.Int31n(10)
		if choice == 0 { // 10% chance to re-corrupt
			alloc_corrupter.GlobalCorrupterState.DisableAndSaveCorruption(p.CorrStats)
			p.CorrIndex = -1
			p.CorrStats = nil
			proc.corruptInput(item)
		}
	}
}

// taken from: https://siongui.github.io/2018/03/09/go-match-common-element-in-two-array/
func arrayIntersection(a, b []uint32) (c []uint32) {
	m := make(map[uint32]bool)

	for _, item := range a {
		m[item] = true
	}

	for _, item := range b {
		if _, ok := m[item]; ok {
			c = append(c, item)
		}
	}
	return
}

// Reverting triage for now. The fault is that all the triage steps are missed (returns none)
func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	// newCorrCover := item.info.CorrCover
	if newSignal.Empty() {
		return
	}
	if item.p.CorrIndex > 0 { //&& len(newCorrCover) <= 0 {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		info, _ := proc.executeRaw(proc.execOptsCover, item.p, StatTriage, false, true)
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover, _ := getSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)
		// newCorrCover = newCorrCover.Intersection(thisCorrCover)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if item.flags&ProgMinimized == 0 {
		if item.p.CorrIndex > 0 && item.call == -1 {
			log.Fatalf("[triageInput] BAD CONDITION: CorrIndex > 0 and item.call == -1")
		}
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info, _ := proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						if p1.CorrIndex >= 0 {

						} else {
							return true
						}
					}
				}
				return false
			})
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32, []uint32) {
	// if p.CorrIndex > 0 || alloc_corrupter.Total_alloc_tracking_mode { // program has corruption
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover, inf.CorrCover
	// } else { // no corruption and not total tracking we remove coverage
	// 	return signal.FromRaw(make([]uint32, 0), 0), make([]uint32, 0)
	// }
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		// disabling the corruption
		p.CorrIndex = -1
		p.CorrStats = nil
		proc.fuzzer.workQueue.enqueue(&WorkCorrupt{
			p:     p,
			flags: 0,
		})
		//proc.execute(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info, _ := proc.executeRaw(proc.execOpts, newProg, StatSmash, false, true)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info, _ := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) (*ipc.ProgInfo, bool) {
	info, worked := proc.executeRaw(execOpts, p, stat, false, true)
	if info == nil {
		return nil, false
	}
	calls, extra := proc.fuzzer.checkNewSignal(p, info)
	if p.CorrIndex <= 0 { //  todo: check if program has corruption
		for _, callIndex := range calls {
			proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
		}
		if extra {
			proc.enqueueCallTriage(p, flags, -1, info.Extra)
		}
	} else {
		for _, callIndex := range calls {
			if callIndex <= p.CorrIndex {
				continue
			}
			proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
		}
	}
	return info, worked != -1
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) discoverAllocations(opts *ipc.ExecOpts, p *prog.Prog, maxInstruction int) map[int][]string {
	// alloc_corrupter.GlobalCorrupterState.DisableAndSaveLatestCorruption()
	start_syscall_idx := 3
	alloc_corrupter.ClearAllocs()
	if maxInstruction == -1 {
		maxInstruction = len(p.Calls)
	}

	allocations_per_call := make(map[int][]string)
	// don't disable object livelyhood detection because we need to know total allocated objects not only what's still alive
	alloc_corrupter.IgnoreKfrees = false

	// syz-executor's startup structures
	previous_alloc_types := make(map[string]struct{})

	if len(p.Calls) < start_syscall_idx+1 && maxInstruction <= start_syscall_idx+1 {
		return make(map[int][]string)
	}

	for idx := start_syscall_idx; idx < maxInstruction; idx++ {
		tmpp := &prog.Prog{
			Calls:    p.Calls[0:idx],
			Target:   p.Target,
			Comments: p.Comments,

			CorrStats: nil,
			CorrIndex: -1,
		}

		alloc_corrupter.ClearAllocs()
		proc.executeRaw(proc.execOptsNoCollide, tmpp, 0, true, false)
		allocation_map := alloc_corrupter.KprobeGetTypeAddrMap()

		for k := range allocation_map {
			if _, ok := previous_alloc_types[k]; !ok {
				allocations_per_call[idx] = append(allocations_per_call[idx], k)
				// 	previous_alloc_types[k] = struct{}{}
			}
		}
		// log.Logf(0, "[.][proc.go] Until AFTER call %d there are these allocation types still alive: %v\n", idx, allocations_per_call[idx])
	}
	// log.Fatal(nil)
	// re-enable object livelyhood detection
	alloc_corrupter.IgnoreKfrees = false
	return allocations_per_call
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat, tracking bool, allowLogging bool) (*ipc.ProgInfo, int) {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("[proc.go][!!] dedup cover is not enabled")
	}
	proc.fuzzer.checkDisabledCalls(p)

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)
	// alloc_corrupter.Stop_tracing(10)
	time.Sleep(time.Millisecond)
	if allowLogging {
		proc.logProgram(opts, p)
	}
	targetedFuzzing := proc.fuzzer.targetedFuzzing != nil
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		var output []byte
		var info *ipc.ProgInfo
		var hanged bool
		var err error
		var corruptionSucceeded bool = true

		if targetedFuzzing && alloc_corrupter.GlobalCorrupterState.IsReady {
			// alloc_corrupter.Start_tracing(10)
			if p.CorrStats != nil && p.CorrIndex > 0 {
				// must disable old corruption tracker or we won't track new corruptions
				alloc_corrupter.GlobalCorrupterState.DisableAndSaveLatestCorruption()
				//alloc_corrupter.GlobalCorrupterState.DisableKmallocTracker()
				alloc_corrupter.GlobalCorrupterState.ClearAllocations()
				alloc_corrupter.ClearAllocs()

				// inject the corruption
				returnChannel := make(chan struct{})
				pauseChannel := make(chan struct{})

				// alloc_corrupter.GlobalCorrupterState.EnableKmallocTracker()
				alloc_corrupter.GlobalCorrupterState.TrackingModeOnly = true // its always true here but just to be safe...
				go func() {
					output, info, hanged, err = proc.env.ExecWithSleep(proc.execOptsCover, p, uint64(p.CorrIndex), 1, pauseChannel)
					returnChannel <- struct{}{}
					log.Logf(3, "[+][proc.go] Successfully executed the corrupted program (pid: %d)!\n", proc.pid)
				}()

				<-pauseChannel // if pause channel has some item in it, it means that we hit the pause in executor
				p.CorrStats = alloc_corrupter.GlobalCorrupterState.TrackNewCorruption(p.CorrStats.Corruption)
				if p.CorrStats == nil {
					p.CorrIndex = -1
					corruptionSucceeded = false
					log.Logf(3, "[-][proc.go] Unable to corrupt program! Something went wrong (corruptionSucceeded: %v)...\n", corruptionSucceeded)
				}

				// finished the call
				<-returnChannel
				//alloc_corrupter.GlobalCorrupterState.DisableKmallocTracker()

				log.Logf(3, "[+][proc.go] Finished the execution of corrupted program.(corruptionSucceeded: %v)\n", corruptionSucceeded)

				// update coverage using filtered coverage
				if corruptionSucceeded {
					p.CorrStats.Coverage = make(alloc_corrupter.CoverMap)
					// This is the corruption-based $EIP filtering here! TODO: FIX THE ISSUE WITH THIS CODE BEING TOO SLOW!!!
					if _, ok := proc.fuzzer.targetedFuzzing[p.CorrStats.Corruption.CorruptionType]; ok {
						for _, call := range info.Calls {
							for _, c := range call.Signal {
								p.CorrStats.Coverage[c] = struct{}{}
							}
						}
					}
					alloc_corrupter.Stop_tracing(10)
					info.Extra.CorrCover = make([]uint32, 0, 20*len(p.CorrStats.ReadAddrs))
					for addr := range p.CorrStats.ReadAddrs {
						for i := 0; i < 20; i++ {
							info.Extra.CorrCover = append(info.Extra.CorrCover, uint32(addr+uint64(100+60*i)))
						}
					}
					maxCover := make([]uint32, len(info.Extra.CorrCover))
					maxCorrCover := make([]uint32, 0, len(maxCover))
					copy(maxCover, info.Extra.CorrCover)
					copy(maxCorrCover, maxCover)
					maxCover = append(maxCorrCover, info.Extra.Cover...)

					// stop and save tracking, add to corpus if corruption reaches deeper code
					proc.fuzzer.saveCorruptionStats(p.CorrStats) // saving the result after collecting the coverage
					ok, tcsIdx, _ := alloc_corrupter.GlobalCorrupterState.DisableAndSaveLatestCorruption()
					if !ok {
						log.Fatalf("[proc.go][!!] executeRaw: something wrong with disabling corruption!\n")
					} else {
						log.Logf(0, "[proc.go][+] executeRaw: Disable and save worked!!\n")
					}
					log.Logf(3, "[proc.go][corruptInput][+] Got %d addresses of coverage and %d addresses of corruption R/W!\n",
						len(p.CorrStats.Coverage), len(p.CorrStats.ReadAddrs))

					// ============================== reexecute now with the corruption active ==============================
					// alloc_corrupter.GlobalCorrupterState.TrackingModeOnly = false
					// go func() {
					// 	output, info, hanged, err = proc.env.ExecWithSleep(proc.execOptsCover, p, uint64(p.CorrIndex), 1, pauseChannel)
					// 	returnChannel <- struct{}{}
					// 	log.Logf(3, "[+][proc.go] Successfully executed the corrupted program (pid: %d)!\n", proc.pid)
					// }()
					// <-pauseChannel // if pause channel has some item in it, it means that we hit the pause in executor
					// p.CorrStats = alloc_corrupter.GlobalCorrupterState.TrackNewCorruption(p.CorrStats.Corruption)
					// if p.CorrStats == nil {
					// 	p.CorrIndex = -1
					// 	corruptionSucceeded = false
					// 	log.Logf(3, "[-][proc.go] Unable to corrupt program! Something went wrong (corruptionSucceeded: %v)...\n", corruptionSucceeded)
					// }
					// // finished the call
					// <-returnChannel
					// alloc_corrupter.GlobalCorrupterState.DisableKmallocTracker()
					// alloc_corrupter.GlobalCorrupterState.TrackingModeOnly = true

					// corrActiveCoverage := make([]uint32, 0, len(p.CorrStats.ReadAddrs))
					// for addr := range p.CorrStats.ReadAddrs {
					// 	corrActiveCoverage = append(corrActiveCoverage, uint32(addr))
					// }
					// randCorrActiveCoverage := make([]uint32, 0, len(p.CorrStats.ReadAddrs))
					// for addr := range p.CorrStats.ReadAddrs {
					// 	randCorrActiveCoverage = append(randCorrActiveCoverage, uint32(addr))
					// }
					// if len(randCorrActiveCoverage) != len(corrActiveCoverage) {
					// 	log.Logf(0, "WARNING: Mismatching coverages! Potential privesc!")
					// }
					info.Extra.CorrCover = maxCorrCover
					info.Extra.Cover = maxCover
					return info, tcsIdx
				} else {
					alloc_corrupter.Stop_tracing(10)
					return nil, -1
				}
			} else if tracking {
				// We are not corrupting, just tracking
				output, info, hanged, err = proc.env.ExecWithTracking(opts, p)
				alloc_corrupter.Stop_tracing(10)
			} else {
				output, info, hanged, err = proc.env.Exec(opts, p)
			}
		} else {
			output, info, hanged, err = proc.env.Exec(opts, p)
		}
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than ignoring this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				return nil, -1
			}
			if try > 10 {
				log.Fatalf("[proc.go][!!] executor %v failed %v times (corruption kmode: %v):\n%v", proc.pid, try,
					(targetedFuzzing && alloc_corrupter.GlobalCorrupterState.IsReady && p.CorrStats != nil), err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info, -1
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}
	fmt.Printf("\n\n")
	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		if p.CorrStats != nil {
			fmt.Printf("%02v:%02v:%02v executing program %v (corruption `%s+%d (%d)` at call %d):\n%s\n",
				now.Hour(), now.Minute(), now.Second(), proc.pid, p.CorrStats.Corruption.CorruptionType,
				p.CorrStats.Corruption.CorruptionOffset, p.CorrStats.Corruption.CorruptionSize, p.CorrIndex, data)
		} else {
			fmt.Printf("%02v:%02v:%02v executing program %v (no corruption):\n%s\n",
				now.Hour(), now.Minute(), now.Second(), proc.pid, data)
		}
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			if p.CorrStats != nil {
				fmt.Fprintf(buf, "syzkaller: executing program %v (corruption %s+%d at call %d):\n%s\n",
					proc.pid, p.CorrStats.Corruption.CorruptionType, p.CorrStats.Corruption.CorruptionOffset, p.CorrIndex, data)
			} else {
				fmt.Fprintf(buf, "syzkaller: executing program %v (no corruption):\n%s\n", proc.pid, data)
			}
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("[proc.go][!!] unknown output type: %v", proc.fuzzer.outputType)
	}
}
