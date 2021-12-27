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
	"math/big"
	"os"
	"testing"
)

// Note: these tests are executed on mainnet
func createClient() (*RpcClient, context.Context, error) {
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
		t.Fatal("Failed to get accounts", err)
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
		t.Fatal("Failed to get storages: ", err)
	}

	for _, item := range results {
		fmt.Printf("%v:\t%v --- %v\n", item.Address, item.Key, item.Value)
	}

}

func TestClient_GetBlockHeader(t *testing.T) {
	client, ctx, err := createClient()
	if err != nil {
		t.Fatal("Failed to create client:", err)
	}
	defer func() { client.Close() }()

	expectation := "0xdc2d938e4cd0a149681e9e04352953ef5ab399d59bcd5b0357f6c0797470a524"
	head, err := client.GetBlockHeader(ctx, big.NewInt(10000))

	if err != nil || expectation != head.Hash().Hex() {
		t.Fatal("Failed to get block header:", err)
	}
}

func TestGetRecentBlockHashes(t *testing.T) {
	client, ctx, err := createClient()
	if err != nil {
		t.Fatal("Failed to create client:", err)
	}
	defer func() { client.Close() }()

	results, err := client.GetRecentBlockHashes(ctx, big.NewInt(10000), 3)
	hash10000 := "0xdc2d938e4cd0a149681e9e04352953ef5ab399d59bcd5b0357f6c0797470a524"
	hash9999 := "0xb9ecd2df84ee2687efc0886f5177f6674bad9aeb73de9323e254e15c5a34fc93"
	hash9998 := "0x21d58047bf33bd8a90f1e5fc79b6ad8d15aa9906cfa64e78b2124940fb84ea1e"
	if err != nil || results[10000].Hex() != hash10000 || results[9999].Hex() != hash9999 || results[9998].Hex() != hash9998 {
		t.Fatal("Failed to get recent block hashes:", err)
	}
}

func TestGetTransaction(t *testing.T) {
	client, ctx, err := createClient()
	if err != nil {
		t.Fatal("Failed to create client:", err)
	}
	defer func() { client.Close() }()

	tx, _, err := client.GetTransactionByHash(ctx, common.HexToHash("0x2bec27048e5a4c3075223e6b0fe20a9b5179516552b4cf167c159694ad197c1f"))

	fmt.Printf("%v, %v", tx.BlockNumber, tx.From)

}
