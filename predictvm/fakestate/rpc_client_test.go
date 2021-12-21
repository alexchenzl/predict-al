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
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"os"
	"testing"
)

func createClient() (*Client, context.Context, error) {
	url := os.Getenv("GETH_RPC_TESTING")
	ctx := context.Background()
	client, err := DialContext(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	return client, ctx, nil
}

// Need to set the GETH_RPC_TESTING environment variable  before running these tests
func TestGetAccount(t *testing.T) {

	client, ctx, err := createClient()
	if err != nil {
		t.Fatal("Failed to create client", err)
	}
	defer func() { client.Close() }()

	accounts := make([]common.Address, 3)
	accounts[0] = common.HexToAddress("0x3cd751e6b0078be393132286c442345e5dc49699")
	accounts[1] = common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7")
	accounts[2] = common.HexToAddress("0x3cd751e6b0078be393132286c442345e5dc49690")

	results, err := client.GetAccountsAt(ctx, accounts, nil)
	if err != nil {
		t.Fatal("Failed to create client", err)
	}

	for _, account := range results {
		fmt.Printf("%v:\n\t%v\n\t%v\n\t%v\n\n", account.Address, account.Balance, account.Nonce, account.Code)
	}

}

func TestGetStorages(t *testing.T) {
	client, ctx, err := createClient()
	if err != nil {
		t.Fatal("Failed to create client", err)
	}
	defer func() { client.Close() }()

	accounts := make([]common.Address, 3)
	accounts[0] = common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7")
	accounts[1] = common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7")
	accounts[2] = common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec8")

	keys := make([]common.Hash, 3)
	keys[0] = common.HexToHash("0x0")
	keys[1] = common.HexToHash("0x1")
	keys[2] = common.HexToHash("0x10000")

	results, err := client.GetStoragesAt(ctx, accounts, keys, nil)
	if err != nil {
		t.Fatal("Failed to create client", err)
	}

	for _, item := range results {
		fmt.Printf("%v:\n\t%v\n\t%v\n\n", item.Address, item.Key, item.Value)
	}

}
