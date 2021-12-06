// Copyright 2020 The go-ethereum Authors
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
	"github.com/ethereum/go-ethereum/params"
)

func makeGasSStoreFunc(clearingRefund uint64) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		return 0, nil
	}
}

// gasSLoadEIP2929 calculates dynamic gas for SLOAD according to EIP-2929
// For SLOAD, if the (address, storage_key) pair (where address is the address of the contract
// whose storage is being read) is not yet in accessed_storage_keys,
// charge 2100 gas and add the pair to accessed_storage_keys.
// If the pair is already in accessed_storage_keys, charge 100 gas.
func gasSLoadEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return params.WarmStorageReadCostEIP2929, nil
}

// gasExtCodeCopyEIP2929 implements extcodecopy according to EIP-2929
// EIP spec:
// > If the target is not in accessed_addresses,
// > charge COLD_ACCOUNT_ACCESS_COST gas, and add the address to accessed_addresses.
// > Otherwise, charge WARM_STORAGE_READ_COST gas.
func gasExtCodeCopyEIP2929(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return 0, nil
}

// gasEip2929AccountCheck checks whether the first stack item (as address) is present in the access list.
// If it is, this method returns '0', otherwise 'cold-warm' gas, presuming that the opcode using it
// is also using 'warm' as constant factor.
// This method is used by:
// - extcodehash,
// - extcodesize,
// - (ext) balance
func gasEip2929AccountCheck(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return 0, nil
}

func makeCallVariantGasCallEIP2929(oldCalculator gasFunc) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		return 0, nil
	}
}

var (
	gasCallEIP2929         = makeCallVariantGasCallEIP2929(gasCall)
	gasDelegateCallEIP2929 = makeCallVariantGasCallEIP2929(gasDelegateCall)
	gasStaticCallEIP2929   = makeCallVariantGasCallEIP2929(gasStaticCall)
	gasCallCodeEIP2929     = makeCallVariantGasCallEIP2929(gasCallCode)
	gasSelfdestructEIP2929 = makeSelfdestructGasFn(true)
	// gasSelfdestructEIP3529 implements the changes in EIP-2539 (no refunds)
	gasSelfdestructEIP3529 = makeSelfdestructGasFn(false)

	// gasSStoreEIP2929 implements gas cost for SSTORE according to EIP-2929
	//
	// When calling SSTORE, check if the (address, storage_key) pair is in accessed_storage_keys.
	// If it is not, charge an additional COLD_SLOAD_COST gas, and add the pair to accessed_storage_keys.
	// Additionally, modify the parameters defined in EIP 2200 as follows:
	//
	// Parameter 	Old value 	New value
	// SLOAD_GAS 	800 	= WARM_STORAGE_READ_COST
	// SSTORE_RESET_GAS 	5000 	5000 - COLD_SLOAD_COST
	//
	//The other parameters defined in EIP 2200 are unchanged.
	// see gasSStoreEIP2200(...) in core/vm/gas_table.go for more info about how EIP 2200 is specified
	gasSStoreEIP2929 = makeGasSStoreFunc(params.SstoreClearsScheduleRefundEIP2200)

	// gasSStoreEIP2539 implements gas cost for SSTORE according to EPI-2539
	// Replace `SSTORE_CLEARS_SCHEDULE` with `SSTORE_RESET_GAS + ACCESS_LIST_STORAGE_KEY_COST` (4,800)
	gasSStoreEIP3529 = makeGasSStoreFunc(params.SstoreClearsScheduleRefundEIP3529)
)

// makeSelfdestructGasFn can create the selfdestruct dynamic gas function for EIP-2929 and EIP-2539
func makeSelfdestructGasFn(refundsEnabled bool) gasFunc {
	gasFunc := func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		return 0, nil
	}
	return gasFunc
}
