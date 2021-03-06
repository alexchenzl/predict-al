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
	"bytes"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

// It means a tainted value
var UnknownValuePlaceHolder, _ = uint256.FromHex("0xFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFCFC")

func opAdd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.Add(&x, y)
	}

	return nil, nil
}

func opSub(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.Sub(&x, y)
	}
	return nil, nil
}

func opMul(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.Mul(&x, y)
	}
	return nil, nil
}

func opDiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.Div(&x, y)
	}
	return nil, nil
}

func opSdiv(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.SDiv(&x, y)
	}
	return nil, nil
}

func opMod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.Mod(&x, y)
	}
	return nil, nil
}

func opSmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.SMod(&x, y)
	}
	return nil, nil
}

func opExp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	base, exponent := scope.Stack.pop(), scope.Stack.peek()
	if base.Eq(UnknownValuePlaceHolder) {
		*exponent = *UnknownValuePlaceHolder
	} else if !exponent.Eq(UnknownValuePlaceHolder) {
		exponent.Exp(&base, exponent)
	}
	return nil, nil
}

func opSignExtend(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	back, num := scope.Stack.pop(), scope.Stack.peek()
	if back.Eq(UnknownValuePlaceHolder) {
		*num = *UnknownValuePlaceHolder
	} else if !num.Eq(UnknownValuePlaceHolder) {
		num.ExtendSign(num, &back)
	}
	return nil, nil
}

func opNot(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if !x.Eq(UnknownValuePlaceHolder) {
		x.Not(x)
	}
	return nil, nil
}

func opLt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		if x.Lt(y) {
			y.SetOne()
		} else {
			y.Clear()
		}
	}
	return nil, nil
}

func opGt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		if x.Gt(y) {
			y.SetOne()
		} else {
			y.Clear()
		}
	}
	return nil, nil
}

func opSlt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		if x.Slt(y) {
			y.SetOne()
		} else {
			y.Clear()
		}
	}
	return nil, nil
}

func opSgt(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		if x.Sgt(y) {
			y.SetOne()
		} else {
			y.Clear()
		}
	}
	return nil, nil
}

func opEq(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		if x.Eq(y) {
			y.SetOne()
		} else {
			y.Clear()
		}
	}
	return nil, nil
}

func opIszero(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if !x.Eq(UnknownValuePlaceHolder) {
		if x.IsZero() {
			x.SetOne()
		} else {
			x.Clear()
		}
	}
	return nil, nil
}

func opAnd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.And(&x, y)
	}
	return nil, nil
}

func opOr(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.Or(&x, y)
	}
	return nil, nil
}

func opXor(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y := scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) {
		*y = *UnknownValuePlaceHolder
	} else if !y.Eq(UnknownValuePlaceHolder) {
		y.Xor(&x, y)
	}
	return nil, nil
}

func opByte(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	th, val := scope.Stack.pop(), scope.Stack.peek()
	if th.Eq(UnknownValuePlaceHolder) {
		*val = *UnknownValuePlaceHolder
	} else if !val.Eq(UnknownValuePlaceHolder) {
		val.Byte(&th)
	}
	return nil, nil
}

func opAddmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) || y.Eq(UnknownValuePlaceHolder) {
		*z = *UnknownValuePlaceHolder
	} else if !z.Eq(UnknownValuePlaceHolder) {
		if z.IsZero() {
			z.Clear()
		} else {
			z.AddMod(&x, &y, z)
		}
	}
	return nil, nil
}

func opMulmod(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x, y, z := scope.Stack.pop(), scope.Stack.pop(), scope.Stack.peek()
	if x.Eq(UnknownValuePlaceHolder) || y.Eq(UnknownValuePlaceHolder) {
		*z = *UnknownValuePlaceHolder
	} else if !z.Eq(UnknownValuePlaceHolder) {
		z.MulMod(&x, &y, z)
	}
	return nil, nil
}

// opSHL implements Shift Left
// The SHL instruction (shift left) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the left by arg1 number of bits.
func opSHL(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.Eq(UnknownValuePlaceHolder) {
		*value = *UnknownValuePlaceHolder
	} else if !value.Eq(UnknownValuePlaceHolder) {
		if shift.LtUint64(256) {
			value.Lsh(value, uint(shift.Uint64()))
		} else {
			value.Clear()
		}
	}
	return nil, nil
}

// opSHR implements Logical Shift Right
// The SHR instruction (logical shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with zero fill.
func opSHR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Note, second operand is left in the stack; accumulate result into it, and no need to push it afterwards
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.Eq(UnknownValuePlaceHolder) {
		*value = *UnknownValuePlaceHolder
	} else if !value.Eq(UnknownValuePlaceHolder) {
		if shift.LtUint64(256) {
			value.Rsh(value, uint(shift.Uint64()))
		} else {
			value.Clear()
		}
	}
	return nil, nil
}

// opSAR implements Arithmetic Shift Right
// The SAR instruction (arithmetic shift right) pops 2 values from the stack, first arg1 and then arg2,
// and pushes on the stack arg2 shifted to the right by arg1 number of bits with sign extension.
func opSAR(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	shift, value := scope.Stack.pop(), scope.Stack.peek()
	if shift.Eq(UnknownValuePlaceHolder) {
		*value = *UnknownValuePlaceHolder
	} else if !value.Eq(UnknownValuePlaceHolder) {
		if shift.GtUint64(256) {
			if value.Sign() >= 0 {
				value.Clear()
			} else {
				// Max negative shift: all bits set
				value.SetAllOne()
			}
			return nil, nil
		}
		n := uint(shift.Uint64())
		value.SRsh(value, n)
	}
	return nil, nil
}

// Offset and size must not be unknown, but data may be unknown
func opSha3(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.peek()
	data := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	if interpreter.hasher == nil {
		interpreter.hasher = sha3.NewLegacyKeccak256().(keccakState)
	} else {
		interpreter.hasher.Reset()
	}
	interpreter.hasher.Write(data)
	interpreter.hasher.Read(interpreter.hasherBuf[:])

	size.SetBytes(interpreter.hasherBuf[:])
	return nil, nil
}

// Contract address must be known
func opAddress(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Address().Bytes()))
	return nil, nil
}

// The balance should be unknown in the first round, but it may be known in next rounds
func opBalance(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	if !slot.Eq(UnknownValuePlaceHolder) {
		address := common.Address(slot.Bytes20())
		balance := interpreter.evm.StateDB.GetBalance(address)
		if balance == nil {
			// balance is unknown
			*slot = *UnknownValuePlaceHolder
		} else {
			// balance is already known
			slot.SetFromBig(balance)
		}
	}
	return nil, nil
}

// Origin must be known
func opOrigin(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Origin.Bytes()))
	return nil, nil
}

// Caller must be known
func opCaller(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(scope.Contract.Caller().Bytes()))
	return nil, nil
}

// Currently suppose that all parameters of calls are known, but it seems that Value is not necessary to be known
func opCallValue(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(scope.Contract.value)
	scope.Stack.push(v)
	return nil, nil
}

// CallData must be known
func opCallDataLoad(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	x := scope.Stack.peek()
	if offset, overflow := x.Uint64WithOverflow(); !overflow {
		data := getData(scope.Contract.Input, offset, 32)
		x.SetBytes(data)
	} else {
		x.Clear()
	}
	return nil, nil
}

// CallDataSize must be known
func opCallDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(scope.Contract.Input))))
	return nil, nil
}

// CallData must be known
func opCallDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	dataOffset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		dataOffset64 = 0xffffffffffffffff
	}
	// These values are checked for overflow during gas cost calculation
	memOffset64 := memOffset.Uint64()
	length64 := length.Uint64()
	scope.Memory.Set(memOffset64, length64, getData(scope.Contract.Input, dataOffset64, length64))

	return nil, nil
}

// Though engine doesn't really execute contracts, the return data size may not be expected size, but it should be known
func opReturnDataSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(len(interpreter.returnData))))
	return nil, nil
}

// The same as opReturnDataSize
func opReturnDataCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		dataOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)

	offset64, overflow := dataOffset.Uint64WithOverflow()
	if overflow {
		return nil, ErrReturnDataOutOfBounds
	}
	// we can reuse dataOffset now (aliasing it for clarity)
	var end = dataOffset
	end.Add(&dataOffset, &length)
	end64, overflow := end.Uint64WithOverflow()
	if overflow || uint64(len(interpreter.returnData)) < end64 {
		return nil, ErrReturnDataOutOfBounds
	}
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), interpreter.returnData[offset64:end64])
	return nil, nil
}

// Address may not be literally known.
// Size is unknown in the first found even when address is literally known.
func opExtCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()
	if !slot.Eq(UnknownValuePlaceHolder) {
		size := interpreter.evm.StateDB.GetCodeSize(slot.Bytes20())

		// State is not known yet, it's different from zero code size
		if size == -1 {
			*slot = *UnknownValuePlaceHolder
		} else {
			slot.SetUint64(uint64(size))
		}
	}
	return nil, nil
}

// This state should be already known
func opCodeSize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	l := new(uint256.Int)
	l.SetUint64(uint64(len(scope.Contract.Code)))
	scope.Stack.push(l)
	return nil, nil
}

// Code of itself must be known
func opCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		memOffset  = scope.Stack.pop()
		codeOffset = scope.Stack.pop()
		length     = scope.Stack.pop()
	)
	uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
	if overflow {
		uint64CodeOffset = 0xffffffffffffffff
	}
	codeCopy := getData(scope.Contract.Code, uint64CodeOffset, length.Uint64())
	scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)

	return nil, nil
}

// ExtCodeCopy is usually used to check and analyze a contract's code. In most scenarios it could be replaced by
// ExtCodeHash now. Ref https://ethereum.stackexchange.com/questions/59779/what-is-the-purpose-of-extcodecopy
//
// Address may be unknown, but it seems that this should never happen. If address is unknown, the codeOffset
// would be unknown either.
// code obviously is unknown in the first round, code size is unknown either
//
// Now assume memOffset and codeOffset should be known when address is known. There's not any opcode to get codeOffset,
// so this value must be known during compiling stage.
//
func opExtCodeCopy(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		stack      = scope.Stack
		a          = stack.pop()
		memOffset  = stack.pop()
		codeOffset = stack.pop()
		length     = stack.pop()
	)

	if !a.Eq(UnknownValuePlaceHolder) {
		uint64CodeOffset, overflow := codeOffset.Uint64WithOverflow()
		if overflow {
			uint64CodeOffset = 0xffffffffffffffff
		}
		addr := common.Address(a.Bytes20())

		code := interpreter.evm.StateDB.GetCode(addr)
		var codeCopy []byte
		if code == nil {
			// code is unknown, length should be unknown either
			// Set memory as UnknownValuePlaceHolder, length is 32 bytes
			length = *uint256.NewInt(32)
			codeCopy = UnknownValuePlaceHolder.Bytes()
		} else {
			// If code is known, length is known
			codeCopy = getData(code, uint64CodeOffset, length.Uint64())
		}
		scope.Memory.Set(memOffset.Uint64(), length.Uint64(), codeCopy)
		return nil, nil
	} else {
		return nil, ErrExecutionReverted
	}

}

// Purpose of this opcode: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-1052.md
//
// opExtCodeHash returns the code hash of a specified account.
// There are several cases when the function is called, while we can relay everything
// to `state.GetCodeHash` function to ensure the correctness.
//   (1) Caller tries to get the code hash of a normal contract account, state
// should return the relative code hash and set it as the result.
//
//   (2) Caller tries to get the code hash of a non-existent account, state should
// return common.Hash{} and zero will be set as the result.
//
//   (3) Caller tries to get the code hash for an account without contract code,
// state should return emptyCodeHash(0xc5d246...) as the result.
//
//   (4) Caller tries to get the code hash of a precompiled account, the result
// should be zero or emptyCodeHash.
//
// It is worth noting that in order to avoid unnecessary create and clean,
// all precompile accounts on mainnet have been transferred 1 wei, so the return
// here should be emptyCodeHash.
// If the precompile account is not transferred any amount on a private or
// customized chain, the return value will be zero.
//
//   (5) Caller tries to get the code hash for an account which is marked as suicided
// in the current transaction, the code hash of this account should be returned.
//
//   (6) Caller tries to get the code hash for an account which is marked as deleted,
// this account should be regarded as a non-existent account and zero should be returned.
func opExtCodeHash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	slot := scope.Stack.peek()

	// Address may be unknown, for example, just load from another slot
	if !slot.Eq(UnknownValuePlaceHolder) {
		address := common.Address(slot.Bytes20())

		// The account is not loaded or existed
		// TODO - Need to distinguish these two cases ?
		// put an empty object into statedb as a non-exist account ?
		if !interpreter.evm.StateDB.Exist(address) {
			*slot = *UnknownValuePlaceHolder
		} else if interpreter.evm.StateDB.Empty(address) {
			slot.Clear()
		} else {
			slot.SetBytes(interpreter.evm.StateDB.GetCodeHash(address).Bytes())
		}
	}
	return nil, nil
}

func opGasprice(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.GasPrice)
	scope.Stack.push(v)
	return nil, nil
}

func opBlockhash(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	num := scope.Stack.peek()
	num64, overflow := num.Uint64WithOverflow()
	if overflow {
		num.Clear()
		return nil, nil
	}
	var upper, lower uint64
	upper = interpreter.evm.Context.BlockNumber.Uint64()
	if upper < 257 {
		lower = 0
	} else {
		lower = upper - 256
	}
	if num64 >= lower && num64 < upper {
		num.SetBytes(interpreter.evm.Context.GetHash(num64).Bytes())
	} else {
		num.Clear()
	}
	return nil, nil
}

func opCoinbase(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetBytes(interpreter.evm.Context.Coinbase.Bytes()))
	return nil, nil
}

func opTimestamp(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Time)
	scope.Stack.push(v)
	return nil, nil
}

func opNumber(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.BlockNumber)
	scope.Stack.push(v)
	return nil, nil
}

func opDifficulty(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v, _ := uint256.FromBig(interpreter.evm.Context.Difficulty)
	scope.Stack.push(v)
	return nil, nil
}

func opGasLimit(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(interpreter.evm.Context.GasLimit))
	return nil, nil
}

func opPop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.pop()
	return nil, nil
}

// Assume memory offset is always known
func opMload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	v := scope.Stack.peek()
	if v.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}

	offset := int64(v.Uint64())
	v.SetBytes(scope.Memory.GetPtr(offset, 32))
	return nil, nil
}

// Assume memory offset is always known now
// Now suppose that mStart is known, it's ok if val is fake value
func opMstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// pop value of the stack
	mStart, val := scope.Stack.pop(), scope.Stack.pop()
	if mStart.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}
	scope.Memory.Set32(mStart.Uint64(), &val)
	return nil, nil
}

// If any parameter is unknown, returns error.
// What's the typical use case of mstore8 ? It's seldom seen in disassembly code.
// The UnknownValuePlaceHolder is 32 bytes, may have issue with byte memory operation.
func opMstore8(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	off, val := scope.Stack.pop(), scope.Stack.pop()
	if off.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}

	if !val.Eq(UnknownValuePlaceHolder) {
		scope.Memory.store[off.Uint64()] = byte(val.Uint64())
		return nil, nil
	} else {
		// TODO -
		// Not sure whether it's ok to put a UnknownValuePlaceHolder, need to test and verify whether
		// it will break up the bytes
		//scope.Memory.Set32(off.Uint64(), &val)
		return nil, ErrMstore8Value
	}
}

// If loc is unknown, keep the stack value as unknown
func opSload(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	loc := scope.Stack.peek()
	if !loc.Eq(UnknownValuePlaceHolder) {
		hash := common.Hash(loc.Bytes32())
		val := interpreter.evm.StateDB.GetState(scope.Contract.Address(), hash)
		// State is not loaded yet
		if bytes.Equal(val.Bytes(), (common.Hash{}).Bytes()) {
			*loc = *UnknownValuePlaceHolder
		} else {
			loc.SetBytes(val.Bytes())
		}
	}
	return nil, nil
}

// If loc is unknown, do nothing
func opSstore(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	loc := scope.Stack.pop()
	if !loc.Eq(UnknownValuePlaceHolder) {
		val := scope.Stack.pop()
		// Even if val is UnknownValuePlaceHolder, it's ok to save it into statedb
		interpreter.evm.StateDB.SetState(scope.Contract.Address(),
			loc.Bytes32(), val.Bytes32())
	}
	return nil, nil
}

// Jump dest must be known. If it's not, engine doesn't know how to set pc
func opJump(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	pos := scope.Stack.pop()
	if !scope.Contract.validJumpdest(&pos) {
		return nil, ErrInvalidJump
	}
	*pc = pos.Uint64()
	return nil, nil
}

// pos should be a constant, but cond may be fake value
func opJumpi(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	pos, cond := scope.Stack.pop(), scope.Stack.pop()

	if !cond.Eq(UnknownValuePlaceHolder) {
		if !cond.IsZero() {
			if !scope.Contract.validJumpdest(&pos) {
				return nil, ErrInvalidJump
			}
			*pc = pos.Uint64()
		} else {
			*pc++
		}
	} else {
		// Avoid possible infinite loop
		jump2 := scope.Jumps2[*pc]
		jump2++
		scope.Jumps2[*pc] = jump2

		if jump2 > 4 {
			//fmt.Printf("\t%06x BREAK\tJUMPI %5x times %d branch %v:%v\n", *pc, pos.Uint64(), jump2, interpreter.evm.depth, interpreter.evm.branchDepth+1)
			return nil, ErrJumpiInfiniteLoop
		}

		// If condition value is unknown, need to follow both branches
		// But if branch depth is too deep or this branch is re-entered again, only follow non-zero branch
		if interpreter.evm.branchDepth < RunBranchDepth && jump2 < 2 {
			//fmt.Printf("\t%06x IN \tJUMPI %5x times %d branch %v:%v\n", *pc, pos.Uint64(), jump2, interpreter.evm.depth, interpreter.evm.branchDepth+1)
			_, err := interpreter.RunBranch(*pc+1, scope)
			//fmt.Printf("\t%06x OUT\tJUMPI %5x times %d branch %v:%v\n", *pc, pos.Uint64(), jump2, interpreter.evm.depth, interpreter.evm.branchDepth+1)
			if errors.Is(err, ErrAbort) {
				//fmt.Printf("Exit branch with timeout %v:%v\n", interpreter.evm.depth, interpreter.evm.branchDepth+1)
				return nil, ErrAbort
			}
		}
		if !scope.Contract.validJumpdest(&pos) {
			return nil, ErrInvalidJump
		}
		*pc = pos.Uint64()
	}
	return nil, nil
}

func opJumpdest(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, nil
}

func opPc(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(*pc))
	return nil, nil
}

// Memory size should always be known
func opMsize(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(uint64(scope.Memory.Len())))
	return nil, nil
}

func opGas(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	scope.Stack.push(new(uint256.Int).SetUint64(scope.Contract.Gas))
	return nil, nil
}

// TODO
// Does not handle this opcode yet
func opCreate(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		value        = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)
	if interpreter.evm.chainRules.IsEIP150 {
		gas -= gas / 64
	}
	// reuse size int for stackvalue
	stackvalue := size

	scope.Contract.UseGas(gas)
	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		bigVal = value.ToBig()
	}

	res, addr, returnGas, suberr := interpreter.evm.Create(scope.Contract, input, gas, bigVal)
	// Push item on the stack based on the returned error. If the ruleset is
	// homestead we must check for CodeStoreOutOfGasError (homestead only
	// rule) and treat as an error, if the ruleset is frontier we must
	// ignore this error and pretend the operation was successful.
	if interpreter.evm.chainRules.IsHomestead && suberr == ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else if suberr != nil && suberr != ErrCodeStoreOutOfGas {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		return res, nil
	}
	return nil, nil
}

// TODO
// Does not handle this opcode yet
func opCreate2(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		endowment    = scope.Stack.pop()
		offset, size = scope.Stack.pop(), scope.Stack.pop()
		salt         = scope.Stack.pop()
		input        = scope.Memory.GetCopy(int64(offset.Uint64()), int64(size.Uint64()))
		gas          = scope.Contract.Gas
	)

	// Apply EIP150
	gas -= gas / 64
	scope.Contract.UseGas(gas)
	// reuse size int for stackvalue
	stackvalue := size
	//TODO: use uint256.Int instead of converting with toBig()
	bigEndowment := big0
	if !endowment.IsZero() {
		bigEndowment = endowment.ToBig()
	}
	res, addr, returnGas, suberr := interpreter.evm.Create2(scope.Contract, input, gas,
		bigEndowment, &salt)
	// Push item on the stack based on the returned error.
	if suberr != nil {
		stackvalue.Clear()
	} else {
		stackvalue.SetBytes(addr.Bytes())
	}
	scope.Stack.push(&stackvalue)
	scope.Contract.Gas += returnGas

	if suberr == ErrExecutionReverted {
		return res, nil
	}
	return nil, nil
}

// toAddr is possible to be unknown if the target contract address is stored in a storage slot.
// value is also possible to be unknown.
// inOffset, inSize, retOffset and retSize should not be unknown because they are known in compiling time.
func opCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	stack := scope.Stack
	// Pop gas. The actual gas in interpreter.evm.callGasTemp.
	// We can use this as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

	// If toAddr is unknown, ret is unknown
	if addr.Eq(UnknownValuePlaceHolder) {
		if retSize.Uint64() >= 32 {
			scope.Memory.Set(retOffset.Uint64(), 32, UnknownValuePlaceHolder.Bytes())
		}
		return UnknownValuePlaceHolder.Bytes(), nil
	}

	// Looks like this should not happen, but need to verify
	if inOffset.Eq(UnknownValuePlaceHolder) || inSize.Eq(UnknownValuePlaceHolder) || retOffset.Eq(UnknownValuePlaceHolder) || retSize.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}

	toAddr := common.Address(addr.Bytes20())
	// Get the arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	var bigVal = big0
	//TODO: use uint256.Int instead of converting with toBig()
	// By using big0 here, we save an alloc for the most common case (non-ether-transferring contract calls),
	// but it would make more sense to extend the usage of uint256.Int
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}

	ret, returnGas, err := interpreter.evm.Call(scope.Contract, toAddr, args, gas, bigVal)

	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	return ret, nil
}

// Data acccess, like call
func opCallCode(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, value, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

	// If toAddr is unknown, ret is unknown
	if addr.Eq(UnknownValuePlaceHolder) {
		if retSize.Uint64() >= 32 {
			scope.Memory.Set(retOffset.Uint64(), 32, UnknownValuePlaceHolder.Bytes())
		}
		return UnknownValuePlaceHolder.Bytes(), nil
	}

	// Looks like this should not happen, but need to verify
	if inOffset.Eq(UnknownValuePlaceHolder) || inSize.Eq(UnknownValuePlaceHolder) || retOffset.Eq(UnknownValuePlaceHolder) || retSize.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}

	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	//TODO: use uint256.Int instead of converting with toBig()
	var bigVal = big0
	if !value.IsZero() {
		gas += params.CallStipend
		bigVal = value.ToBig()
	}

	ret, returnGas, err := interpreter.evm.CallCode(scope.Contract, toAddr, args, gas, bigVal)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	return ret, nil
}

// Data acccess, like call
func opDelegateCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	stack := scope.Stack
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

	// If toAddr is unknown, ret is unknown
	if addr.Eq(UnknownValuePlaceHolder) {
		if retSize.Uint64() >= 32 {
			scope.Memory.Set(retOffset.Uint64(), 32, UnknownValuePlaceHolder.Bytes())
		}
		return UnknownValuePlaceHolder.Bytes(), nil
	}

	// Looks like this should not happen, but need to verify
	if inOffset.Eq(UnknownValuePlaceHolder) || inSize.Eq(UnknownValuePlaceHolder) || retOffset.Eq(UnknownValuePlaceHolder) || retSize.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}

	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	ret, returnGas, err := interpreter.evm.DelegateCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	return ret, nil
}

// Data acccess, like call
func opStaticCall(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	// Pop gas. The actual gas is in interpreter.evm.callGasTemp.
	stack := scope.Stack
	// We use it as a temporary value
	temp := stack.pop()
	gas := interpreter.evm.callGasTemp
	// Pop other call parameters.
	addr, inOffset, inSize, retOffset, retSize := stack.pop(), stack.pop(), stack.pop(), stack.pop(), stack.pop()

	// If toAddr is unknown, ret is unknown
	if addr.Eq(UnknownValuePlaceHolder) {
		if retSize.Uint64() >= 32 {
			scope.Memory.Set(retOffset.Uint64(), 32, UnknownValuePlaceHolder.Bytes())
		}
		return UnknownValuePlaceHolder.Bytes(), nil
	}

	// Looks like this should not happen, but need to verify
	if inOffset.Eq(UnknownValuePlaceHolder) || inSize.Eq(UnknownValuePlaceHolder) || retOffset.Eq(UnknownValuePlaceHolder) || retSize.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}

	toAddr := common.Address(addr.Bytes20())
	// Get arguments from the memory.
	args := scope.Memory.GetPtr(int64(inOffset.Uint64()), int64(inSize.Uint64()))

	ret, returnGas, err := interpreter.evm.StaticCall(scope.Contract, toAddr, args, gas)
	if err != nil {
		temp.Clear()
	} else {
		temp.SetOne()
	}
	stack.push(&temp)
	if err == nil || err == ErrExecutionReverted {
		ret = common.CopyBytes(ret)
		scope.Memory.Set(retOffset.Uint64(), retSize.Uint64(), ret)
	}
	scope.Contract.Gas += returnGas

	return ret, nil
}

// The offset must be known, but size may not be known
func opReturn(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	// Must not happen
	if offset.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}
	// If size is not known, the return data is unknown
	if size.Eq(UnknownValuePlaceHolder) {
		return UnknownValuePlaceHolder.Bytes(), nil
	}

	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))
	return ret, nil
}

// The offset and size should be known in previous Steps
func opRevert(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	if offset.Eq(UnknownValuePlaceHolder) || size.Eq(UnknownValuePlaceHolder) {
		return nil, ErrUnknownMemPos
	}
	ret := scope.Memory.GetPtr(int64(offset.Uint64()), int64(size.Uint64()))

	return ret, nil
}

func opStop(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	return nil, nil
}

// beneficiary could be an unknown address
func opSuicide(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	beneficiary := scope.Stack.pop()
	balance := interpreter.evm.StateDB.GetBalance(scope.Contract.Address())
	if !beneficiary.Eq(UnknownValuePlaceHolder) {
		interpreter.evm.StateDB.AddBalance(beneficiary.Bytes20(), balance)
	}
	interpreter.evm.StateDB.Suicide(scope.Contract.Address())
	if interpreter.cfg.Debug {
		interpreter.cfg.Tracer.CaptureEnter(SELFDESTRUCT, scope.Contract.Address(), beneficiary.Bytes20(), []byte{}, 0, balance)
		interpreter.cfg.Tracer.CaptureExit([]byte{}, 0, nil)
	}
	return nil, nil
}

// following functions are used by the instruction jump  table
// Log could be ignored
func makeLog(size int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		stack := scope.Stack
		stack.pop()
		stack.pop()
		for i := 0; i < size; i++ {
			stack.pop()
		}
		return nil, nil
	}
}

// opPush1 is a specialized version of pushN
// The operand of pushN is always a constant value
func opPush1(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
	var (
		codeLen = uint64(len(scope.Contract.Code))
		integer = new(uint256.Int)
	)
	*pc += 1
	if *pc < codeLen {
		scope.Stack.push(integer.SetUint64(uint64(scope.Contract.Code[*pc])))
	} else {
		scope.Stack.push(integer.Clear())
	}
	return nil, nil
}

// make push instruction function
func makePush(size uint64, pushByteSize int) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		codeLen := len(scope.Contract.Code)

		startMin := codeLen
		if int(*pc+1) < startMin {
			startMin = int(*pc + 1)
		}

		endMin := codeLen
		if startMin+pushByteSize < endMin {
			endMin = startMin + pushByteSize
		}

		integer := new(uint256.Int)
		scope.Stack.push(integer.SetBytes(common.RightPadBytes(
			scope.Contract.Code[startMin:endMin], pushByteSize)))

		*pc += size
		return nil, nil
	}
}

// make dup instruction function
func makeDup(size int64) executionFunc {
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		scope.Stack.dup(int(size))
		return nil, nil
	}
}

// make swap instruction function
func makeSwap(size int64) executionFunc {
	// switch n + 1 otherwise n would be swapped with n
	size++
	return func(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
		scope.Stack.swap(int(size))
		return nil, nil
	}
}
