package fakestate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"time"

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

// TestNetworkAccess test average state access time on mainnet
func TestNetworkAccess(rpc string) error {

	rpcCtx := context.Background()
	rpcClient, err := DialContext(rpcCtx, rpc)
	if err != nil {
		return err
	}
	defer rpcClient.Close()

	// some verified accounts from etherscan including contracts and external accounts
	accounts := []common.Address{
		common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"),
		common.HexToAddress("0xB8c77482e45F1F44dE1745F52C74426C631bDD52"),
		common.HexToAddress("0x3e17ccb9851a985e2146be4a9874ba2286883ca9"),
		common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"),
		common.HexToAddress("0x61edcdf5bb737adffe5043706e7c5bb1f1a56eea"),
		common.HexToAddress("0xc61b9bb3a7a0767e3179713f3a5c7a9aedce193c"),
		common.HexToAddress("0x6ae6f08fdf96f3773060cd830173521802d523a4"),
		common.HexToAddress("0x93fab8cc2d9e27aa0b757f3ff96e7b15402a6d86"),
	}

	// slots of some contracts
	slots := map[common.Address]common.Hash{
		common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7"): common.HexToHash("0x775ffed4ccf89c25a8839488fe26f859e220f9fa0165f328e1c4e0f55e484ef1"),
		common.HexToAddress("0xc4347dbda0078d18073584602cf0c1572541bb15"): common.HexToHash("0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"),
		common.HexToAddress("0x452aa05fa52b6e23e7001f854e58648169f7ad00"): common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		common.HexToAddress("0x0c6c04acf48a5a093ca59e4bda996362adcdcacf"): common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000014"),
		common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"): common.HexToHash("0xaced72359d8708e95d2112ba70e71fa267967a5588d15e7c78c1904e0debe410"),
		common.HexToAddress("0xd8e3fb3b08eba982f2754988d70d57edc0055ae6"): common.HexToHash("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"),
		common.HexToAddress("0xa1306fd923a100700d5c6f94b806ae65ad65a1d1"): common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001"),
		common.HexToAddress("0xa68dd8cb83097765263adad881af6eed479c4a33"): common.HexToHash("0x745448ebd86f892e3973b919a6686b32d8505f8eb2e02df5a36797f187adb881"),
		common.HexToAddress("0xf411903cbc70a74d22900a5de66a2dda66507255"): common.HexToHash("0xe3ee2b6dbeb46c2e05f3cf0b7622347ca4346a14dc2cc359f69e00ab7c8b59b6"),
		common.HexToAddress("0x44b1f8924d9ed44e81060d538b337ead8025ef94"): common.HexToHash("0x8d8b1e86bb8f933587fcf89e9dc79e54b489335397be5a36a33b922c9d824a7a"),
	}

	blockNums := []*big.Int{
		big.NewInt(13996000),
		big.NewInt(13998000),
		big.NewInt(14000000),
	}

	total := int64(0)
	for _, blockNum := range blockNums {
		for _, account := range accounts {
			start := time.Now()
			_, err := rpcClient.GetAccountAt(rpcCtx, &account, blockNum)
			total += int64(time.Since(start))
			if err != nil {
				fmt.Printf("Error occurs at %v %v, %v", blockNum, account, err)
			}
		}

		for address, key := range slots {
			start := time.Now()
			_, err := rpcClient.GetStorageAt(rpcCtx, &address, &key, blockNum)
			total += int64(time.Since(start))
			if err != nil {
				fmt.Printf("Error occurs at %v %v:%v, %v", blockNum, address, key, err)
			}
		}
	}

	average := time.Duration(total / int64(len(blockNums)*(len(accounts)+len(slots))))

	fmt.Printf("Average state access time is %v\n", average)
	return nil
}
