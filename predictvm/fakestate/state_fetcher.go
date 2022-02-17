package fakestate

import (
	"context"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

type StateRequest struct {
	BlockNumber *big.Int
	Address     *common.Address
	Key         *common.Hash
	Done        chan struct{}
	err         error
}

type StateFetcher struct {
	client   *RpcClient
	statedb  *FakeStateDB
	blockNum *big.Int
}

func NewStateFetcher(statedb *FakeStateDB, client *RpcClient, blockNum *big.Int) *StateFetcher {
	sf := &StateFetcher{
		client:   client,
		statedb:  statedb,
		blockNum: blockNum,
	}
	return sf
}

func (sf *StateFetcher) CopyStatedb() *FakeStateDB {
	return sf.statedb.Copy()
}

func (sf *StateFetcher) Fetch(contracts []common.Address, keys []common.Hash, accounts []common.Address) error {
	if sf.blockNum != nil && sf.blockNum.Sign() < 0 {
		return nil
	}

	results, err := sf.client.GetStatesAt(context.Background(), contracts, keys, accounts, sf.blockNum)
	if err == nil {
		slotNum := len(contracts)
		for i := range results {
			if i < slotNum {
				slot := results[i].(*StorageResult)
				sf.statedb.SetState(slot.Address, slot.Key, common.BytesToHash(slot.Value))
			} else {
				account := results[i].(*AccountResult)
				sf.statedb.SetBalance(account.Address, account.Balance)
				sf.statedb.SetNonce(account.Address, account.Nonce)
				sf.statedb.SetCode(account.Address, account.Code)
			}
		}
	}
	return err
}

func (sf *StateFetcher) FetchFromAndTo(from *common.Address, to *common.Address) error {
	accounts := make([]common.Address, 1, 2)
	accounts[0] = *from
	if to != nil {
		accounts = append(accounts, *to)
	}
	return sf.Fetch(nil, nil, accounts)
}
