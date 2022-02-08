package fakestate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// RpcClient defines typed wrappers for the Ethereum RPC API.
type RpcClient struct {
	c *rpc.Client
}

// Dial connects a client to the given URL.
func Dial(rawurl string) (*RpcClient, error) {
	return DialContext(context.Background(), rawurl)
}

func DialContext(ctx context.Context, rawurl string) (*RpcClient, error) {
	c, err := rpc.DialContext(ctx, rawurl)
	if err != nil {
		return nil, err
	}
	return NewClient(c), nil
}

// NewClient creates a client that uses the given RPC client.
func NewClient(c *rpc.Client) *RpcClient {
	return &RpcClient{c}
}

func (ec *RpcClient) Close() {
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

// GetAccountAt get balance, nonce and code of an account in one rpc call
func (ec *RpcClient) GetAccountAt(ctx context.Context, account *common.Address, blockNumber *big.Int) (*AccountResult, error) {
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

func (ec *RpcClient) GetStorageAt(ctx context.Context, account *common.Address, key *common.Hash, blockNumber *big.Int) (*StorageResult, error) {
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

// GetAccountsAt get all accounts in a batch call
func (ec *RpcClient) GetAccountsAt(ctx context.Context, accounts []common.Address, blockNumber *big.Int) ([]AccountResult, error) {
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
				if reqs[idx+j].Error != nil {
					return nil, reqs[idx+j].Error
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

// GetStoragesAt get all storage slots in a batch call
func (ec *RpcClient) GetStoragesAt(ctx context.Context, contracts []common.Address, keys []common.Hash, blockNumber *big.Int) ([]StorageResult, error) {

	if len(contracts) > 0 {
		if len(keys) != len(contracts) {
			return nil, errors.New("invalid parameters")
		}

		reqs := make([]rpc.BatchElem, len(contracts))
		for i := range contracts {
			reqs[i] = rpc.BatchElem{
				Method: "eth_getStorageAt",
				Args:   []interface{}{contracts[i], keys[i], toBlockNumArg(blockNumber)},
				Result: new(hexutil.Bytes),
			}
		}

		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}

		results := make([]StorageResult, len(contracts))

		for i := range contracts {
			if reqs[i].Error != nil {
				return nil, reqs[i].Error
			}
			results[i].Address = contracts[i]
			results[i].Key = keys[i]
			// Even if a storage key doesn't occur in a contract, this API will return an all-zero byte array instead of nil
			results[i].Value = *(reqs[i].Result.(*hexutil.Bytes))
		}
		return results, nil
	}

	return nil, nil
}

// GetStatesAt get all contracts' storage slots and accounts states in a batch call
func (ec *RpcClient) GetStatesAt(ctx context.Context, contracts []common.Address, keys []common.Hash, accounts []common.Address, blockNumber *big.Int) ([]interface{}, error) {

	if len(contracts) > 0 || len(accounts) > 0 {
		if len(keys) != len(contracts) {
			return nil, errors.New("invalid parameters")
		}

		reqs := make([]rpc.BatchElem, len(contracts)+len(accounts)*3)
		blockNumberArg := toBlockNumArg(blockNumber)
		// request slots
		for i := range contracts {
			reqs[i] = rpc.BatchElem{
				Method: "eth_getStorageAt",
				Args:   []interface{}{contracts[i], keys[i], blockNumberArg},
				Result: new(hexutil.Bytes),
			}
		}
		// request accounts
		start := len(contracts)
		for i := range accounts {
			idx := start + i*3
			buildAccountReq(reqs[idx:idx+3], &accounts[i], blockNumberArg)
		}
		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}

		results := make([]interface{}, len(contracts)+len(accounts))
		for i := range contracts {
			if reqs[i].Error != nil {
				return nil, reqs[i].Error
			}
			result := &StorageResult{
				Address: contracts[i],
				Key:     keys[i],
				Value:   *(reqs[i].Result.(*hexutil.Bytes)),
			}
			results[i] = result
		}

		for i := range accounts {
			idx := start + i*3
			for j := 0; j < 3; j++ {
				if reqs[idx+j].Error != nil {
					return nil, reqs[idx+j].Error
				}
			}
			result := &AccountResult{
				Address: accounts[i],
				Balance: (*big.Int)(reqs[idx].Result.(*hexutil.Big)),
				Nonce:   *(*uint64)(reqs[idx+1].Result.(*hexutil.Uint64)),
			}
			code := *(reqs[idx+2].Result.(*hexutil.Bytes))
			if len(code) == 0 {
				result.Code = nil
			} else {
				result.Code = code
			}
			results[start+i] = result
		}
		return results, nil
	}
	return nil, nil
}

// ChainID retrieves the current chain ID for transaction replay protection.
func (ec *RpcClient) ChainID(ctx context.Context) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "eth_chainId")
	if err != nil {
		return nil, err
	}
	return (*big.Int)(&result), err
}

// BlockNumber returns the most recent block number
func (ec *RpcClient) BlockNumber(ctx context.Context) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "eth_blockNumber")
	return uint64(result), err
}

// GetBlockHeader returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (ec *RpcClient) GetBlockHeader(ctx context.Context, blockNumber *big.Int) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "eth_getBlockByNumber", toBlockNumArg(blockNumber), false)
	if err == nil && head == nil {
		err = ethereum.NotFound
	}
	return head, err
}

// GetBlock returns block header and its transactions, but without uncles
func (ec *RpcClient) GetBlock(ctx context.Context, blockNumber *big.Int) (*types.Block, error) {
	return ec.getBlock(ctx, "eth_getBlockByNumber", toBlockNumArg(blockNumber), true)
}

type RpcTransaction struct {
	Tx *types.Transaction
	TxExtraInfo
}

type TxExtraInfo struct {
	BlockNumber *string         `json:"BlockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

func (tx *RpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.Tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.TxExtraInfo)
}

type RpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []RpcTransaction `json:"transactions"`
	UncleHashes  []common.Hash    `json:"uncles"`
}

func (ec *RpcClient) getBlock(ctx context.Context, method string, args ...interface{}) (*types.Block, error) {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, method, args...)
	if err != nil {
		return nil, err
	} else if len(raw) == 0 {
		return nil, ethereum.NotFound
	}
	// Decode header and transactions.
	var head *types.Header
	var body RpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, fmt.Errorf("server returned non-empty uncle list but block header indicates no uncles")
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, fmt.Errorf("server returned empty uncle list but block header indicates uncles")
	}
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, fmt.Errorf("server returned non-empty transaction list but block header indicates no transactions")
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, fmt.Errorf("server returned empty transaction list but block header indicates transactions")
	}

	// Fill the sender cache of transactions in the block.
	txs := make([]*types.Transaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		if tx.From != nil {
			setSenderFromServer(tx.Tx, *tx.From, body.Hash)
		}
		txs[i] = tx.Tx
	}
	var uncles []*types.Header
	return types.NewBlockWithHeader(head).WithBody(txs, uncles), nil
}

// GetRecentBlockHashes get specified count of most recent block hashes, including the current one
func (ec *RpcClient) GetRecentBlockHashes(ctx context.Context, blockNumber *big.Int, count int) (map[uint64]common.Hash, error) {
	var maxNumber uint64
	if blockNumber == nil {
		num, err := ec.BlockNumber(ctx)
		if err != nil {
			return nil, err
		}
		maxNumber = num
	} else {
		maxNumber = blockNumber.Uint64()
	}

	if int(maxNumber) < count {
		count = int(maxNumber)
	}

	reqs := make([]rpc.BatchElem, count)
	for i := 0; i < count; i++ {
		reqs[i] = rpc.BatchElem{
			Method: "eth_getBlockByNumber",
			Args:   []interface{}{hexutil.EncodeUint64(maxNumber - uint64(i)), false},
			Result: new(json.RawMessage),
		}
	}

	if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
		return nil, err
	}

	results := make(map[uint64]common.Hash)
	for _, req := range reqs {
		if req.Error != nil {
			return nil, req.Error
		}
		var head *types.Header
		if err := json.Unmarshal(*req.Result.(*json.RawMessage), &head); err != nil {
			return nil, err
		}

		results[head.Number.Uint64()] = head.Hash()
	}
	return results, nil

}

// GetTransactionByHash returns the transaction with the given hash.
func (ec *RpcClient) GetTransactionByHash(ctx context.Context, hash common.Hash) (*RpcTransaction, bool, error) {
	var json *RpcTransaction
	err := ec.c.CallContext(ctx, &json, "eth_getTransactionByHash", hash)
	if err != nil {
		return nil, false, err
	} else if json == nil {
		return nil, false, ethereum.NotFound
	} else if _, r, _ := json.Tx.RawSignatureValues(); r == nil {
		return nil, false, fmt.Errorf("server returned transaction without signature")
	}
	if json.From != nil && json.BlockHash != nil {
		setSenderFromServer(json.Tx, *json.From, *json.BlockHash)
	}
	return json, json.BlockNumber == nil, nil
}
