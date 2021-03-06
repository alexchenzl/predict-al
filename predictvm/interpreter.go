// Copyright 2014 The go-ethereum Authors
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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/holiman/uint256"
	"hash"
	"sync/atomic"

	"predict_acl/predictvm/fakestate"
)

// RunBranchDepth Maximum depth of RunBranch stack, to avoid branch explosion
const RunBranchDepth int = 8

// Config are the configuration options for the Interpreter
type Config struct {
	Debug                   bool   // Enables debugging
	Tracer                  Tracer // Opcode logger
	NoRecursion             bool   // Disables call, callcode, delegate call and create
	NoBaseFee               bool   // Forces the EIP-1559 baseFee to 0 (needed for 0 price calls)
	EnablePreimageRecording bool   // Enables recording of SHA3/keccak preimages

	JumpTable [256]*operation // EVM instruction table, automatically populated if unset

	ExtraEips []int // Additional EIPS that are to be enabled
}

// ScopeContext contains the things that are per-call, such as stack and memory,
// but not transients like pc and gas
type ScopeContext struct {
	Memory   *Memory
	Stack    *Stack
	Contract *Contract

	// record the execution count of jumpi opcodes with fake condition values
	Jumps2 map[uint64]int
}

// keccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// EVMInterpreter represents an EVM interpreter
type EVMInterpreter struct {
	evm *EVM
	cfg Config

	hasher    keccakState // Keccak256 hasher instance shared across opcodes
	hasherBuf common.Hash // Keccak256 hasher result array shared aross opcodes

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse
}

// NewEVMInterpreter returns a new instance of the Interpreter.
func NewEVMInterpreter(evm *EVM, cfg Config) *EVMInterpreter {
	// We use the STOP instruction whether to see
	// the jump table was initialised. If it was not
	// we'll set the default jump table.
	if cfg.JumpTable[STOP] == nil {
		var jt JumpTable
		switch {
		case evm.chainRules.IsLondon:
			jt = londonInstructionSet
		case evm.chainRules.IsBerlin:
			jt = berlinInstructionSet
		case evm.chainRules.IsIstanbul:
			jt = istanbulInstructionSet
		case evm.chainRules.IsConstantinople:
			jt = constantinopleInstructionSet
		case evm.chainRules.IsByzantium:
			jt = byzantiumInstructionSet
		case evm.chainRules.IsEIP158:
			jt = spuriousDragonInstructionSet
		case evm.chainRules.IsEIP150:
			jt = tangerineWhistleInstructionSet
		case evm.chainRules.IsHomestead:
			jt = homesteadInstructionSet
		default:
			jt = frontierInstructionSet
		}
		for i, eip := range cfg.ExtraEips {
			if err := EnableEIP(eip, &jt); err != nil {
				// Disable it, so caller can check if it's activated or not
				cfg.ExtraEips = append(cfg.ExtraEips[:i], cfg.ExtraEips[i+1:]...)
				//log.Error("EIP activation failed", "eip", eip, "error", err)
			}
		}
		cfg.JumpTable = jt
	}

	return &EVMInterpreter{
		evm: evm,
		cfg: cfg,
	}
}

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// ErrExecutionReverted which means revert-and-keep-gas-left.
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {

	// Increment the call depth which is restricted to 1024
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This also makes sure that the readOnly flag isn't removed for child calls.
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}

	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway.
	in.returnData = nil

	// Don't bother with the execution if there's no code.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		mem         = NewMemory() // bound memory
		stack       = newstack()  // local stack
		jumps2      = make(map[uint64]int)
		callContext = &ScopeContext{
			Memory:   mem,
			Stack:    stack,
			Contract: contract,

			Jumps2: jumps2,
		}
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		pc = uint64(0) // program counter

	)
	// Don't move this deferrred function, it's placed before the capturestate-deferred method,
	// so that it get's executed _after_: the capturestate needs the stacks before
	// they are returned to the pools
	defer func() {
		returnStack(stack)
	}()
	contract.Input = input

	return in.runOpCodes(pc, callContext)
}

// RunBranch Clone the current call context to run one JUMPI branch
func (in *EVMInterpreter) RunBranch(pc uint64, callContext *ScopeContext) (ret []byte, err error) {
	// Increment the branch depth which is restricted to
	in.evm.branchDepth++
	defer func() { in.evm.branchDepth-- }()

	var (
		mem    = NewMemory() // bound memory
		stack  = newstack()  // local stack
		jumps2 = make(map[uint64]int)

		newCallContext = &ScopeContext{
			Memory:   mem,
			Stack:    stack,
			Contract: callContext.Contract,

			Jumps2: jumps2,
		}

		curReturnData []byte
	)

	// Clone the current stack
	stackLen := callContext.Stack.len()
	if stackLen > stack.len() {
		stack.data = make([]uint256.Int, 0, stackLen)
	}
	for i := 0; i < stackLen; i++ {
		stack.push(&callContext.Stack.data[i])
	}

	// Clone the memory
	mem.lastGasCost = callContext.Memory.lastGasCost
	mem.store = callContext.Memory.GetCopy(0, int64(callContext.Memory.Len()))

	// Clone the jumpis
	for k, v := range callContext.Jumps2 {
		jumps2[k] = v
	}

	// snapshot is not implemented yet, so clone the statedb instead
	statedb := in.evm.StateDB
	in.evm.StateDB = in.evm.StateDB.(*fakestate.FakeStateDB).Copy()

	// backup current interpreter returnData
	if in.returnData != nil {
		size := len(in.returnData)
		curReturnData = make([]byte, size)
		copy(curReturnData, in.returnData)
	}

	// backup current gas
	curGas := callContext.Contract.Gas

	defer func() {
		callContext.Contract.Gas = curGas
		if curReturnData != nil {
			copy(in.returnData, curReturnData)
		}
		in.evm.StateDB = statedb
		returnStack(stack)
	}()

	return in.runOpCodes(pc, newCallContext)
}

func (in *EVMInterpreter) runOpCodes(pc uint64, callContext *ScopeContext) (ret []byte, err error) {
	var (
		op   OpCode // current opcode
		cost uint64
		// copies used by tracer
		pcCopy  uint64 // needed for the deferred Tracer
		gasCopy uint64 // for Tracer to log gas remaining before execution
		logged  bool   // deferred Tracer should ignore already logged Steps
		res     []byte // result of the opcode execution function
	)

	if in.cfg.Debug {
		defer func() {
			if err != nil {
				if !logged {
					in.cfg.Tracer.CaptureState(in.evm, pcCopy, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
				} else {
					// Append error information to last trace log
					in.cfg.Tracer.CaptureFault(in.evm, pcCopy, op, gasCopy, cost, callContext, in.evm.depth, err)
				}
			}
		}()
	}
	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.
	for {
		in.evm.steps++
		// return error to avoid running more branches
		if in.evm.steps%1024 == 0 && atomic.LoadInt32(&in.evm.abort) != 0 {
			//fmt.Printf("%08x:%08x Abort branch %d:%d\n", in.evm.steps, pc, in.evm.depth, in.evm.branchDepth)
			return nil, ErrAbort
		}
		if in.cfg.Debug {
			// Capture pre-execution values for tracing.
			logged, pcCopy, gasCopy = false, pc, callContext.Contract.Gas
		}

		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation.
		op = callContext.Contract.GetOp(pc)
		operation := in.cfg.JumpTable[op]
		if operation == nil {
			return nil, &ErrInvalidOpCode{opcode: op}
		}
		//fmt.Printf("%08x:%08x branch %d:%d op %v\n", in.evm.steps, pc, in.evm.depth, in.evm.branchDepth, op)
		// Validate stack
		if sLen := callContext.Stack.len(); sLen < operation.minStack {
			return nil, &ErrStackUnderflow{stackLen: sLen, required: operation.minStack}
		} else if sLen > operation.maxStack {
			return nil, &ErrStackOverflow{stackLen: sLen, limit: operation.maxStack}
		}
		// If the operation is valid, enforce write restrictions
		if in.readOnly && in.evm.chainRules.IsByzantium {
			// If the interpreter is operating in readonly mode, make sure no
			// state-modifying operation is performed. The 3rd stack item
			// for a call operation is the value. Transferring value from one
			// account to the others means the state is modified and should also
			// return with an error.
			if operation.writes || (op == CALL && callContext.Stack.Back(2).Sign() != 0) {
				return nil, ErrWriteProtection
			}
		}
		// Static portion of gas
		cost = operation.constantGas // For tracing
		if !callContext.Contract.UseGas(operation.constantGas) {
			return nil, ErrOutOfGas
		}

		var memorySize uint64
		// calculate the new memory size and expand the memory to fit
		// the operation
		// Memory check needs to be done prior to evaluating the dynamic gas portion,
		// to detect calculation overflows
		if operation.memorySize != nil {
			memSize, overflow := operation.memorySize(callContext.Stack)
			if overflow {
				return nil, ErrGasUintOverflow
			}
			// memory is expanded in words of 32 bytes. Gas
			// is also calculated in words.
			if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow {
				return nil, ErrGasUintOverflow
			}
		}
		// Dynamic portion of gas
		// consume the gas and return an error if not enough gas is available.
		// cost is explicitly set so that the capture state defer method can get the proper cost
		if operation.dynamicGas != nil {
			var dynamicCost uint64
			dynamicCost, err = operation.dynamicGas(in.evm, callContext.Contract, callContext.Stack, callContext.Memory, memorySize)
			cost += dynamicCost // total cost, for debug tracing
			if err != nil || !callContext.Contract.UseGas(dynamicCost) {
				return nil, ErrOutOfGas
			}
		}
		if memorySize > 0 {
			callContext.Memory.Resize(memorySize)
		}

		if in.cfg.Debug {
			in.cfg.Tracer.CaptureState(in.evm, pc, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
			logged = true
		}

		// execute the operation
		res, err = operation.execute(&pc, in, callContext)
		// if the operation clears the return data (e.g. it has returning data)
		// set the last return to the result of the operation.
		if operation.returns {
			in.returnData = res
		}

		switch {
		case err != nil:
			return nil, err
		case operation.reverts:
			return res, ErrExecutionReverted
		case operation.halts:
			return res, nil
		case !operation.jumps:
			pc++
		}
	}
	return nil, nil
}
