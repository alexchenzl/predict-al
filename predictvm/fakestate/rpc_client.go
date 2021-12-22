package fakestate

import (
	"context"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// Client defines typed wrappers for the Ethereum RPC API.
type Client struct {
	c *rpc.Client
}

// Dial connects a client to the given URL.
func Dial(rawurl string) (*Client, error) {
	return DialContext(context.Background(), rawurl)
}

func DialContext(ctx context.Context, rawurl string) (*Client, error) {
	c, err := rpc.DialContext(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient creates a client that uses the given RPC client.
func NewClient(c *rpc.Client) *Client {
	return &Client{c}
}

func (ec *Client) Close() {
	ec.c.Close()
}

type AccountResult struct {
	Address common.Address
	Balance *big.Int
	Nonce   uint64
	Code    []byte
}

type StorageResult struct {
	Address common.Address
	Key     common.Hash
	Value   []byte
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	pending := big.NewInt(-1)
	if number.Cmp(pending) == 0 {
		return "pending"
	}
	return hexutil.EncodeBig(number)
}

func buildAccountReq(reqs []rpc.BatchElem, account *common.Address, blockNumberArg string) {
	if len(reqs) == 3 {
		reqs[0] = rpc.BatchElem{
			Method: "eth_getBalance",
			Args:   []interface{}{account, blockNumberArg},
			Result: new(hexutil.Big),
		}
		reqs[1] = rpc.BatchElem{
			Method: "eth_getTransactionCount",
			Args:   []interface{}{account, blockNumberArg},
			Result: new(hexutil.Uint64),
		}
		reqs[2] = rpc.BatchElem{
			Method: "eth_getCode",
			Args:   []interface{}{account, blockNumberArg},
			Result: new(hexutil.Bytes),
		}
	}
}

func (ec *Client) GetAccountAt(ctx context.Context, account *common.Address, blockNumber *big.Int) (*AccountResult, error) {
	if account != nil {
		reqs := make([]rpc.BatchElem, 3)

		blockNumberArg := toBlockNumArg(blockNumber)
		buildAccountReq(reqs[0:3], account, blockNumberArg)

		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}

		result := &AccountResult{
			Address: *account,
		}
		result.Balance = (*big.Int)(reqs[0].Result.(*hexutil.Big))
		result.Nonce = *(*uint64)(reqs[1].Result.(*hexutil.Uint64))
		code := *(reqs[2].Result.(*hexutil.Bytes))
		if len(code) == 0 {
			result.Code = nil
		} else {
			result.Code = code
		}
		return result, nil
	}
	return nil, nil
}

func (ec *Client) GetStorageAt(ctx context.Context, account *common.Address, key *common.Hash, blockNumber *big.Int) (*StorageResult, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "eth_getStorageAt", *account, *key, toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}

	storage := &StorageResult{
		Address: *account,
	}

	storage.Key = *key
	// Even if a storage key doesn't occur in a contract, this API will return an all-zero byte array instead of nil
	storage.Value = result
	return storage, err
}

func (ec *Client) GetAccountsAt(ctx context.Context, accounts []common.Address, blockNumber *big.Int) ([]AccountResult, error) {
	if len(accounts) > 0 {
		reqs := make([]rpc.BatchElem, len(accounts)*3)
		blockNumberArg := toBlockNumArg(blockNumber)
		for i := range accounts {
			idx := i * 3
			buildAccountReq(reqs[idx:idx+3], &accounts[i], blockNumberArg)
		}
		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}

		results := make([]AccountResult, len(accounts))
		for i := range accounts {
			idx := i * 3
			for j := 0; j < 3; j++ {
				if reqs[idx].Error != nil {
					return nil, reqs[idx].Error
				}
			}
			results[i].Address = accounts[i]
			results[i].Balance = (*big.Int)(reqs[idx].Result.(*hexutil.Big))
			results[i].Nonce = *(*uint64)(reqs[idx+1].Result.(*hexutil.Uint64))

			code := *(reqs[idx+2].Result.(*hexutil.Bytes))
			if len(code) == 0 {
				results[i].Code = nil
			} else {
				results[i].Code = code
			}
		}
		return results, nil
	}
	return nil, nil
}

func (ec *Client) GetStoragesAt(ctx context.Context, accounts []common.Address, keys []common.Hash, blockNumber *big.Int) ([]StorageResult, error) {

	if len(accounts) > 0 {
		if len(keys) != len(accounts) {
			return nil, errors.New("invalid parameters")
		}

		reqs := make([]rpc.BatchElem, len(accounts))
		for i := range accounts {
			reqs[i] = rpc.BatchElem{
				Method: "eth_getStorageAt",
				Args:   []interface{}{accounts[i], keys[i], toBlockNumArg(blockNumber)},
				Result: new(hexutil.Bytes),
			}
		}

		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}

		results := make([]StorageResult, len(accounts))

		for i := range accounts {
			if reqs[i].Error != nil {
				return nil, reqs[i].Error
			}
			results[i].Address = accounts[i]
			results[i].Key = keys[i]
			// Even if a storage key doesn't occur in a contract, this API will return an all-zero byte array instead of nil
			results[i].Value = *(reqs[i].Result.(*hexutil.Bytes))
		}
		return results, nil
	}

	return nil, nil
}
