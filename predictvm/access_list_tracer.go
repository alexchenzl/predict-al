// Copyright 2021 The go-ethereum Authors
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
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// accessList is an accumulator for the set of accounts and storage slots an EVM
// contract execution Touches.
type accessList map[common.Address]accessListSlots

// accessListSlots is an accumulator for the set of storage slots within a single
// contract that an EVM contract execution Touches.
type accessListSlots map[common.Hash]struct{}

// newAccessList creates a new accessList.
func newAccessList() accessList {
	return make(map[common.Address]accessListSlots)
}

// addAddress adds an address to the accesslist.
func (al accessList) addAddress(address common.Address) {
	// Set address if not previously present
	if _, present := al[address]; !present {
		al[address] = make(map[common.Hash]struct{})
	}
}

// addSlot adds a storage slot to the accesslist.
func (al accessList) addSlot(address common.Address, slot common.Hash) {
	// Set address if not previously present
	al.addAddress(address)

	// Set the slot on the surely existent storage set
	al[address][slot] = struct{}{}
}

func (al accessList) hasAddress(address common.Address) bool {
	_, present := al[address]
	return present
}

func (al accessList) hasSlot(address common.Address, slot common.Hash) bool {
	if slots, ok := al[address]; ok {
		_, present := slots[slot]
		return present
	}
	return false
}

// equal checks if the content of the current access list is the same as the
// content of the other one.
func (al accessList) equal(other accessList) bool {
	// Cross reference the accounts first
	if len(al) != len(other) {
		return false
	}
	for addr := range al {
		if _, ok := other[addr]; !ok {
			return false
		}
	}
	for addr := range other {
		if _, ok := al[addr]; !ok {
			return false
		}
	}
	// Accounts match, cross reference the storage slots too
	for addr, slots := range al {
		otherslots := other[addr]

		if len(slots) != len(otherslots) {
			return false
		}
		for hash := range slots {
			if _, ok := otherslots[hash]; !ok {
				return false
			}
		}
		for hash := range otherslots {
			if _, ok := slots[hash]; !ok {
				return false
			}
		}
	}
	return true
}

// accesslist converts the accesslist to a types.AccessList.
func (al accessList) accessList() types.AccessList {
	acl := make(types.AccessList, 0, len(al))
	for addr, slots := range al {
		tuple := types.AccessTuple{Address: addr, StorageKeys: []common.Hash{}}
		for slot := range slots {
			tuple.StorageKeys = append(tuple.StorageKeys, slot)
		}
		acl = append(acl, tuple)
	}
	return acl
}

// AccessListTracer is a tracer that accumulates touched accounts and storage
// slots into an internal set.
type AccessListTracer struct {
	excl      map[common.Address]struct{} // Set of account to exclude from the list
	list      accessList                  // Set of accounts and storage slots touched
	knownList accessList                  // Already known accounts and storage slots in last rounds
	Touches   int                         // Total state access times
	HasMore   bool                        // Whether there's more unknown states in this round
	logger    *StructLogger               // Detailed debug information logger
}

// NewAccessListTracer creates a new tracer that can generate AccessLists.
// An optional AccessList can be set as already known AccessList
func NewAccessListTracer(acl types.AccessList, from, to *common.Address, precompiles []common.Address, cfg *LogConfig) *AccessListTracer {
	excl := map[common.Address]struct{}{}
	for _, addr := range precompiles {
		excl[addr] = struct{}{}
	}

	list := newAccessList()
	knownList := newAccessList()

	knownList.addAddress(*from)
	if to != nil {
		knownList.addAddress(*to)
	}

	for _, al := range acl {
		if _, ok := excl[al.Address]; !ok {
			knownList.addAddress(al.Address)
		}
		for _, slot := range al.StorageKeys {
			knownList.addSlot(al.Address, slot)
		}
	}

	var logger *StructLogger
	if cfg != nil && cfg.Debug {
		logger = NewStructLogger(cfg)
	}

	return &AccessListTracer{
		excl:      excl,
		list:      list,
		knownList: knownList,
		HasMore:   false,
		logger:    logger,
	}
}

// AppendListToKnownList append access list to known access list, and replace the access list with a new empty list
func (a *AccessListTracer) AppendListToKnownList() {
	for addr, slots := range a.list {
		if len(slots) > 0 {
			for slot := range slots {
				a.knownList.addSlot(addr, slot)
			}
		} else {
			a.knownList.addAddress(addr)
		}
	}
	a.list = newAccessList()
}

func (a *AccessListTracer) GetKnowAccounts() []common.Address {
	accounts := make([]common.Address, 0, len(a.knownList))
	for addr := range a.knownList {
		accounts = append(accounts, addr)
	}
	return accounts
}

// GetNewAccounts return new accounts found in this round
func (a *AccessListTracer) GetNewAccounts() []common.Address {
	accounts := make([]common.Address, 0, len(a.list))
	for addr := range a.list {
		// Some accounts which have slots maybe have been found in last rounds
		if !a.knownList.hasAddress(addr) {
			accounts = append(accounts, addr)
		}
	}
	return accounts
}

// GetNewStorageSlots return new slots found in this round, in which new accounts are excluded
func (a *AccessListTracer) GetNewStorageSlots() types.AccessList {
	acl := make(types.AccessList, 0, len(a.list))
	for addr, slots := range a.list {
		if len(slots) > 0 {
			// Exclude accounts without storage slots
			tuple := types.AccessTuple{Address: addr, StorageKeys: []common.Hash{}}
			for slot := range slots {
				tuple.StorageKeys = append(tuple.StorageKeys, slot)
			}
			acl = append(acl, tuple)
		}
	}
	return acl
}

func (a *AccessListTracer) CaptureStart(env *EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) {
}

// CaptureState captures all opcodes that touch storage or addresses and adds them to the accesslist.
func (a *AccessListTracer) CaptureState(env *EVM, pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error) {
	if a.logger != nil {
		a.logger.CaptureState(env, pc, op, gas, cost, scope, rData, depth, err)
		a.logger.WriteLastTrace(os.Stdout, "")
	}

	stack := scope.Stack
	// For predicting purpose, it's not necessary to record SSTORE
	if op == SLOAD && stack.len() >= 1 {
		loc := stack.data[stack.len()-1]
		if !loc.Eq(UnknownValuePlaceHolder) {
			slot := common.Hash(loc.Bytes32())
			address := scope.Contract.Address()
			if !a.knownList.hasSlot(address, slot) {
				a.list.addSlot(address, slot)
			}
		} else {
			// This slot address depends on another unknown storage slot
			a.HasMore = true
		}
		a.Touches++
		//fmt.Printf("%x\t%v\t%v %v\n", pc, op, scope.Contract.Address(), loc.Hex())
	}
	if (op == EXTCODECOPY || op == EXTCODEHASH || op == EXTCODESIZE || op == BALANCE || op == SELFDESTRUCT) && stack.len() >= 1 {
		loc := stack.data[stack.len()-1]
		if !loc.Eq(UnknownValuePlaceHolder) {
			addr := common.Address(loc.Bytes20())
			if _, ok := a.excl[addr]; !ok {
				if !a.knownList.hasAddress(addr) {
					a.list.addAddress(addr)
				}
			}
		} else {
			a.HasMore = true
		}
		a.Touches++
		//fmt.Printf("%x\t%v\t%v\n", pc, op, loc.Hex())
	}
	if (op == DELEGATECALL || op == CALL || op == STATICCALL || op == CALLCODE) && stack.len() >= 5 {
		loc := stack.data[stack.len()-2]
		if !loc.Eq(UnknownValuePlaceHolder) {
			addr := common.Address(loc.Bytes20())
			if _, ok := a.excl[addr]; !ok {
				if !a.knownList.hasAddress(addr) {
					a.list.addAddress(addr)
					// A  contract call means more storage access
					a.HasMore = true
				}
			}
		} else {
			a.HasMore = true
		}
		a.Touches++
		//fmt.Printf("%x\t%v\t%v\n", pc, op, loc.Hex())
	}
}

func (a *AccessListTracer) CaptureFault(env *EVM, pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, depth int, err error) {
	if a.logger != nil {
		a.logger.CaptureFault(env, pc, op, gas, cost, scope, depth, err)
		a.logger.WriteLastTrace(os.Stdout, "Fault Captured: ")
	}
}

func (a *AccessListTracer) CaptureEnd(output []byte, gasUsed uint64, t time.Duration, err error) {
	if a.logger != nil {
		a.logger.CaptureEnd(output, gasUsed, t, err)
	}
}

func (*AccessListTracer) CaptureEnter(typ OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
}

func (*AccessListTracer) CaptureExit(output []byte, gasUsed uint64, err error) {}

// AccessList returns the current accesslist maintained by the tracer.
func (a *AccessListTracer) AccessList() types.AccessList {
	return a.list.accessList()
}

func (a *AccessListTracer) KnownAccessList() types.AccessList {
	return a.knownList.accessList()
}

// Equal returns if the content of two access list traces are equal.
func (a *AccessListTracer) Equal(other *AccessListTracer) bool {
	return a.list.equal(other.list) && a.knownList.equal(other.knownList)
}
