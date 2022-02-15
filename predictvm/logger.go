// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package predictvm

import (
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"predict_acl/predictvm/fakestate"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

//// Storage represents a contract's storage.
//type Storage map[common.Hash]common.Hash
//
//// Copy duplicates the current storage.
//func (s Storage) Copy() Storage {
//	cpy := make(Storage)
//	for key, value := range s {
//		cpy[key] = value
//	}
//	return cpy
//}

// LogConfig are the configuration options for structured logger the EVM
type LogConfig struct {
	EnableMemory     bool // enable memory capture
	DisableStack     bool // disable stack capture
	DisableStorage   bool // disable storage capture
	EnableReturnData bool // enable return data capture
	Debug            bool // print output during capture end
	Limit            int  // maximum length of output, but zero means unlimited
	// Chain overrides, can be used to execute a trace using future fork rules
	Overrides *params.ChainConfig `json:"overrides,omitempty"`
}

//go:generate gencodec -type StructLog -field-override structLogMarshaling -out gen_structlog.go

// StructLog is emitted to the EVM each cycle and lists information about the current internal state
// prior to the execution of the statement.
type StructLog struct {
	Contract      common.Address              `json:"Contract"`
	Pc            uint64                      `json:"pc"`
	Op            OpCode                      `json:"op"`
	Gas           uint64                      `json:"gas"`
	GasCost       uint64                      `json:"gasCost"`
	Memory        []byte                      `json:"memory"`
	MemorySize    int                         `json:"memSize"`
	Stack         []uint256.Int               `json:"stack"`
	ReturnData    []byte                      `json:"returnData"`
	Storage       map[common.Hash]common.Hash `json:"-"`
	Depth         int                         `json:"depth"`
	RefundCounter uint64                      `json:"refund"`
	BranchDepth   int                         `json:"depth"`
	Info          string                      `json:"info"`
	Err           error                       `json:"-"`
}

// overrides for gencodec
type structLogMarshaling struct {
	Gas         math.HexOrDecimal64
	GasCost     math.HexOrDecimal64
	Memory      hexutil.Bytes
	ReturnData  hexutil.Bytes
	OpName      string `json:"opName"` // adds call to OpName() in MarshalJSON
	ErrorString string `json:"error"`  // adds call to ErrorString() in MarshalJSON
}

// OpName formats the operand name in a human-readable format.
func (s *StructLog) OpName() string {
	return s.Op.String()
}

// ErrorString formats the log's error as a string.
func (s *StructLog) ErrorString() string {
	if s.Err != nil {
		return s.Err.Error()
	}
	return ""
}

// Tracer is used to collect execution traces from an EVM transaction
// execution. CaptureState is called for each Step of the VM with the
// current VM state.
// Note that reference types are actual VM data structures; make copies
// if you need to retain them beyond the current call.
type Tracer interface {
	CaptureStart(env *EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int)
	CaptureState(env *EVM, pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error)
	CaptureEnter(typ OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int)
	CaptureExit(output []byte, gasUsed uint64, err error)
	CaptureFault(env *EVM, pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, depth int, err error)
	CaptureEnd(output []byte, gasUsed uint64, t time.Duration, err error)
}

// StructLogger is an EVM state logger and implements Tracer.
//
// StructLogger can capture state based on the given Log configuration and also keeps
// a track record of modified storage which is used in reporting snapshots of the
// contract their storage.
type StructLogger struct {
	cfg LogConfig

	storage map[common.Address]fakestate.Storage
	logs    []StructLog
	output  []byte
	err     error
}

// NewStructLogger returns a new logger
func NewStructLogger(cfg *LogConfig) *StructLogger {
	logger := &StructLogger{
		storage: make(map[common.Address]fakestate.Storage),
	}
	if cfg != nil {
		logger.cfg = *cfg
	}
	return logger
}

// Reset clears the data held by the logger.
func (l *StructLogger) Reset() {
	l.storage = make(map[common.Address]fakestate.Storage)
	l.output = make([]byte, 0)
	l.logs = l.logs[:0]
	l.err = nil
}

// CaptureStart implements the Tracer interface to initialize the tracing operation.
func (l *StructLogger) CaptureStart(env *EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
}

// CaptureState logs a new structured log message and pushes it out to the environment
//
// CaptureState also tracks SLOAD/SSTORE ops to track storage change.
func (l *StructLogger) CaptureState(env *EVM, pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error) {
	memory := scope.Memory
	stack := scope.Stack
	contract := scope.Contract
	// check if already accumulated the specified number of logs
	if l.cfg.Limit != 0 && l.cfg.Limit <= len(l.logs) {
		return
	}
	// Copy a snapshot of the current memory state to a new buffer
	var mem []byte
	if l.cfg.EnableMemory {
		mem = make([]byte, len(memory.Data()))
		copy(mem, memory.Data())
	}
	// Copy a snapshot of the current stack state to a new buffer
	var stck []uint256.Int
	if !l.cfg.DisableStack {

		//  usually top 16 items is enough
		size := 16
		stackData := stack.Data()
		if len(stackData) < size {
			size = len(stack.Data())
		}
		stck = make([]uint256.Int, size)
		for i, item := range stackData[len(stackData)-size:] {
			stck[i] = item
		}
	}
	// Copy a snapshot of the current storage to a new container
	var storage fakestate.Storage
	if !l.cfg.DisableStorage && (op == SLOAD || op == SSTORE) {
		// initialise new changed values storage container for this contract
		// if not present.
		if l.storage[contract.Address()] == nil {
			l.storage[contract.Address()] = make(fakestate.Storage)
		}
		// capture SLOAD opcodes and record the read entry in the local storage
		if op == SLOAD && stack.len() >= 1 {
			var (
				address = common.Hash(stack.data[stack.len()-1].Bytes32())
				value   = env.StateDB.GetState(contract.Address(), address)
			)
			l.storage[contract.Address()][address] = value
			storage = l.storage[contract.Address()].Copy()
		} else if op == SSTORE && stack.len() >= 2 {
			// capture SSTORE opcodes and record the written entry in the local storage.
			var (
				value   = common.Hash(stack.data[stack.len()-2].Bytes32())
				address = common.Hash(stack.data[stack.len()-1].Bytes32())
			)
			l.storage[contract.Address()][address] = value
			storage = l.storage[contract.Address()].Copy()
		}
	}
	var rdata []byte
	if l.cfg.EnableReturnData {
		rdata = make([]byte, len(rData))
		copy(rdata, rData)
	}

	info := ""
	if op == JUMP {
		info = fmt.Sprintf("dest: %s", stack.data[stack.len()-1].Hex())
	} else if op == JUMPI {
		info = fmt.Sprintf("%s, cond: %s", stack.data[stack.len()-1].Hex(), stack.data[stack.len()-2].Hex())
	}

	// create a new snapshot of the EVM.
	log := StructLog{contract.Address(), pc, op, gas, cost, mem, memory.Len(), stck, rdata, storage, depth, env.StateDB.GetRefund(), env.branchDepth, info, err}
	l.logs = append(l.logs, log)
}

// CaptureFault implements the Tracer interface to trace an execution fault
// while running an opcode.
func (l *StructLogger) CaptureFault(env *EVM, pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, depth int, err error) {
	count := len(l.logs)
	if count > 0 {
		l.logs[count-1].Err = err
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (l *StructLogger) CaptureEnd(output []byte, gasUsed uint64, t time.Duration, err error) {
	l.output = output
	l.err = err
	if l.cfg.Debug {
		fmt.Printf("0x%x\n", output)
		if err != nil {
			fmt.Printf(" error: %v\n", err)
		}
	}
}

func (l *StructLogger) CaptureEnter(typ OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
}

func (l *StructLogger) CaptureExit(output []byte, gasUsed uint64, err error) {}

// StructLogs returns the captured log entries.
func (l *StructLogger) StructLogs() []StructLog { return l.logs }

// Error returns the VM error captured by the trace.
func (l *StructLogger) Error() error { return l.err }

// Output returns the VM return value captured by the trace.
func (l *StructLogger) Output() []byte { return l.output }

func (l *StructLogger) WriteLastTrace(writer io.Writer, tag string) {
	l.WriteTrace(writer, tag, l.logs[len(l.logs)-1:])
}

// WriteTrace writes a formatted trace to the given writer
func (l *StructLogger) WriteTrace(writer io.Writer, tag string, logs []StructLog) {
	for _, log := range logs {
		tabs := ""
		if log.Depth > 0 {
			tabs = strings.Repeat("\t", log.Depth-1)
		}

		fmt.Fprintf(writer, "%v%v %-16spc=%08x depth=%v", tabs, tag, log.Op, log.Pc, log.Depth)

		if log.BranchDepth > 0 {
			fmt.Fprintf(writer, " branch=%v", log.BranchDepth)
		}

		// if stack is present, info is not necessary
		if len(log.Info) > 0 && l.cfg.DisableStack {
			fmt.Fprintf(writer, " info=%s", log.Info)
		}

		if log.Err != nil {
			fmt.Fprintf(writer, " ERROR: %v", log.Err)
		}
		fmt.Fprintln(writer)

		if !l.cfg.DisableStack {
			fmt.Fprintf(writer, "%vStack:\n", tabs)
			for i := len(log.Stack) - 1; i >= 0; i-- {
				fmt.Fprintf(writer, "\t%v%s\n", tabs, log.Stack[i].Hex())
			}
		}
		if len(log.Memory) > 0 {
			fmt.Fprintf(writer, "%vMemory:\n", tabs)
			fmt.Fprintf(writer, "\t%v%s\n", tabs, hex.Dump(log.Memory))
		}
		if len(log.Storage) > 0 {
			fmt.Fprintf(writer, "%vStorage:\n", tabs)
			for h, item := range log.Storage {
				fmt.Fprintf(writer, "\t%v%x: %x\n", tabs, h, item)
			}
		}
		if len(log.ReturnData) > 0 && (log.Op == RETURN || log.Op == REVERT || log.Op == STOP || log.Op == SELFDESTRUCT) {
			fmt.Fprintf(writer, "%vReturnData:\n", tabs)
			fmt.Fprintf(writer, "\t%v%s\n", tabs, hex.EncodeToString(log.ReturnData))
		}
		fmt.Fprintln(writer)
	}
}

// WriteLogs writes vm logs in a readable format to the given writer
func WriteLogs(writer io.Writer, logs []*types.Log) {
	for _, log := range logs {
		fmt.Fprintf(writer, "LOG%d: %x bn=%d txi=%x\n", len(log.Topics), log.Address, log.BlockNumber, log.TxIndex)

		for i, topic := range log.Topics {
			fmt.Fprintf(writer, "%08d  %x\n", i, topic)
		}

		fmt.Fprint(writer, hex.Dump(log.Data))
		fmt.Fprintln(writer)
	}
}
