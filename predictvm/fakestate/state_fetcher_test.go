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

package fakestate

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"os"
	"testing"
)

// Need to set the GETH_RPC_TESTING environment variable  before running these tests
func TestFetcher(t *testing.T) {

	url := os.Getenv("GETH_RPC_TESTING")
	statedb := NewStateDB()
	fetcher := NewStateFetcher(statedb, url, 5)

	defer fetcher.Close()

	address := common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7")

	accounts := make([]*common.Address, 3)
	keys := make([]*common.Hash, 3)

	accounts[0] = &address
	accounts[1] = &address
	accounts[2] = &address

	keys[0] = nil
	hash1 := common.HexToHash("0x0")
	hash2 := common.HexToHash("0x1")

	keys[1] = &hash1
	keys[2] = &hash2

	fetcher.Fetch(accounts, keys)

	stateObj := statedb.getStateObject(address)

	fmt.Printf("%v:\n", address)
	fmt.Printf("\t%v\t%v\t%v\n\n", stateObj.Balance(), stateObj.Nonce(), stateObj.CodeHash())
	fmt.Printf("\t%v\n\n", stateObj.Code())

	fmt.Printf("\t%v\t%v\n", *keys[1], stateObj.GetState(*keys[1]))
	fmt.Printf("\t%v\t%v\n", *keys[2], stateObj.GetState(*keys[2]))
}
