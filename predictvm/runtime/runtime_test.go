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

package runtime

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/asm"
	"math/big"
	vm "predict_acl/predictvm"
	"strings"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := new(Config)
	setDefaults(cfg)

	if cfg.Difficulty == nil {
		t.Error("expected difficulty to be non nil")
	}

	if cfg.Time == nil {
		t.Error("expected time to be non nil")
	}
	if cfg.GasLimit == 0 {
		t.Error("didn't expect gaslimit to be zero")
	}
	if cfg.GasPrice == nil {
		t.Error("expected time to be non nil")
	}
	if cfg.Value == nil {
		t.Error("expected time to be non nil")
	}
	if cfg.GetHashFn == nil {
		t.Error("expected time to be non nil")
	}
	if cfg.BlockNumber == nil {
		t.Error("expected block number to be non nil")
	}
}

func TestEVM(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("crashed with: %v", r)
		}
	}()

	Execute([]byte{
		byte(vm.DIFFICULTY),
		byte(vm.TIMESTAMP),
		byte(vm.GASLIMIT),
		byte(vm.PUSH1),
		byte(vm.ORIGIN),
		byte(vm.BLOCKHASH),
		byte(vm.COINBASE),
	}, nil, nil)
}

func TestExecute(t *testing.T) {
	ret, _, err := Execute([]byte{
		byte(vm.PUSH1), 10,
		byte(vm.PUSH1), 0,
		byte(vm.MSTORE),
		byte(vm.PUSH1), 32,
		byte(vm.PUSH1), 0,
		byte(vm.RETURN),
	}, nil, nil)
	if err != nil {
		t.Fatal("didn't expect error", err)
	}

	num := new(big.Int).SetBytes(ret)
	if num.Cmp(big.NewInt(10)) != 0 {
		t.Error("Expected 10, got", num)
	}
}

func TestAccessList(t *testing.T) {

	id := 1
	prettyPrint := func(comment string, code []byte) {
		instrs := make([]string, 0)
		it := asm.NewInstructionIterator(code)
		for it.Next() {
			if it.Arg() != nil && 0 < len(it.Arg()) {
				instrs = append(instrs, fmt.Sprintf("%v 0x%x", it.Op(), it.Arg()))
			} else {
				instrs = append(instrs, fmt.Sprintf("%v", it.Op()))
			}
		}
		ops := strings.Join(instrs, ", ")
		fmt.Printf("### Case %d\n\n", id)
		id++
		fmt.Printf("%v\n\nBytecode: \n```\n0x%x\n```\nOperations: \n```\n%v\n```\n\n",
			comment, code, ops)

		state := vm.NewStateDB()
		address := common.HexToAddress("0x0a0a0a0a0a0a0a")
		state.SetCode(address, code)

		sender := common.HexToAddress("0x1122")

		tracer := vm.NewAccessListTracer(nil, sender, address, nil)

		config := &Config{
			EVMConfig: vm.Config{
				Debug:  true,
				Tracer: tracer,
			},
			State:  state,
			Origin: sender,
		}

		_, _, err := Call(address, nil, config)
		if err != nil {
			t.Fatal("didn't expect error", err)
		}

		al := tracer.AccessList()
		for _, tuple := range al {
			fmt.Printf("%v\n", tuple.Address)
			for _, slot := range tuple.StorageKeys {
				fmt.Printf("\t%v\n", slot.Hex())
			}
		}
	}

	{ // Basic access list testcase
		code := []byte{
			// Three checks against a precompile
			byte(vm.PUSH1), 1, byte(vm.EXTCODEHASH), byte(vm.POP),
			byte(vm.PUSH1), 2, byte(vm.EXTCODESIZE), byte(vm.POP),
			byte(vm.PUSH1), 3, byte(vm.BALANCE), byte(vm.POP),
			// Three checks against a non-precompile
			byte(vm.PUSH1), 0xf1, byte(vm.EXTCODEHASH), byte(vm.POP),
			byte(vm.PUSH1), 0xf2, byte(vm.EXTCODESIZE), byte(vm.POP),
			byte(vm.PUSH1), 0xf3, byte(vm.BALANCE), byte(vm.POP),

			byte(vm.STOP),
		}
		prettyPrint("Test access list.", code)
	}

	{
		// Test Sload

		code := []byte{
			// directly specified slot
			byte(vm.PUSH1), 0xf1, byte(vm.SLOAD), byte(vm.POP),
			//
			byte(vm.PUSH1), 1, byte(vm.DUP1), byte(vm.PUSH1), 0x10, byte(vm.SWAP1), byte(vm.SLOAD), byte(vm.POP), byte(vm.POP), byte(vm.POP),

			byte(vm.STOP),
		}
		prettyPrint("Test access list.", code)

	}

	{
		// Expected slot key is 0xd976efa78ad29ed9a36b7b646a8316d94e2c0992fc889454e231f704190e7a66
		code := []byte{
			// Map
			byte(vm.PUSH1), 0xee,
			byte(vm.PUSH1), 0,
			byte(vm.MSTORE),
			byte(vm.PUSH1), 0,
			byte(vm.PUSH1), 0x20,
			byte(vm.MSTORE),
			byte(vm.PUSH1), 0x40,
			byte(vm.PUSH1), 0,
			byte(vm.SHA3),
			byte(vm.SLOAD),
			byte(vm.STOP),
		}
		prettyPrint("Test access list.", code)
	}

	{
		// Test call
		code := []byte{
			byte(vm.PUSH1), 0x10,
			byte(vm.PUSH1), 0x00,
			byte(vm.PUSH1), 0x40,
			byte(vm.PUSH1), 0x00,
			byte(vm.PUSH1), 0x01,
			byte(vm.PUSH1), 0xF0,
			byte(vm.PUSH1), 0x01,
			byte(vm.CALL),
			byte(vm.RETURNDATASIZE),
			byte(vm.STOP),
		}

		prettyPrint("Test access list.", code)

	}

	{
		// jumpi

		code := []byte{
			byte(vm.PUSH1),
			0xf1,
			byte(vm.SLOAD),
			byte(vm.PUSH1),
			0x0a,
			byte(vm.JUMPI),
			byte(vm.PUSH1),
			0xf2,
			byte(vm.SLOAD),
			byte(vm.STOP),
			byte(vm.JUMPDEST),
			byte(vm.PUSH1), 0xee,
			byte(vm.PUSH1), 0,
			byte(vm.MSTORE),
			byte(vm.PUSH1), 0,
			byte(vm.PUSH1), 0x20,
			byte(vm.MSTORE),
			byte(vm.PUSH1), 0x40,
			byte(vm.PUSH1), 0,
			byte(vm.SHA3),
			byte(vm.SLOAD),
			byte(vm.STOP),
		}
		prettyPrint("Test access list.", code)

	}

}
