package fakestate

import (
	"context"
	"errors"
	"math/big"
	goruntime "runtime"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type StateRequest struct {
	BlockNumber *big.Int
	Address     *common.Address
	Key         *common.Hash
	Done        chan struct{}
	err         error
}

type StateFetcher struct {
	statedb  *FakeStateDB
	maxProcs int
	url      string
	blockNum *big.Int

	lock sync.Mutex // Protect statdb

	req  chan *StateRequest
	stop chan struct{} // Channel to interrupt processing
	term chan struct{} // Channel to signal iterruption
}

func NewStateFetcher(statedb *FakeStateDB, url string, blockNum *big.Int, maxProcs int) *StateFetcher {

	if maxProcs <= 0 {
		maxProcs = goruntime.NumCPU()
		if maxProcs > 1 {
			maxProcs -= 1
		}
	}

	sf := &StateFetcher{
		statedb:  statedb,
		maxProcs: maxProcs,
		url:      url,
		blockNum: blockNum,
		req:      make(chan *StateRequest),
		stop:     make(chan struct{}),
		term:     make(chan struct{}),
	}
	go sf.loop()
	return sf
}

func (sf *StateFetcher) Close() {
	select {
	case <-sf.stop:
	default:
		close(sf.stop)
	}
	<-sf.term
}

func (sf *StateFetcher) CopyStatedb() *FakeStateDB {
	return sf.statedb.Copy()
}

func (sf *StateFetcher) Fetch(accounts []*common.Address, keys []*common.Hash) error {

	if accounts == nil || keys == nil || len(accounts) != len(keys) {
		return errors.New("invalid parameters")
	}

	requests := make([]StateRequest, len(accounts))
	for i := 0; i < len(accounts); i++ {
		requests[i].Address = accounts[i]
		requests[i].Key = keys[i]
		requests[i].BlockNumber = sf.blockNum
		requests[i].Done = make(chan struct{})
		sf.req <- &requests[i]
	}

	for i := 0; i < len(accounts); i++ {
		<-requests[i].Done
		if requests[i].err != nil {
			return requests[i].err
		}
	}
	return nil
}

func (sf *StateFetcher) process(req *StateRequest) {

	defer func() {
		req.Done <- struct{}{}
	}()

	if req.Address != nil {
		ctx := context.Background()
		client, err := DialContext(ctx, sf.url)
		if err != nil {
			req.err = err
			return
		}
		defer client.Close()

		if req.Key == nil {
			account, err := client.GetAccountAt(ctx, req.Address, req.BlockNumber)
			if err == nil {
				sf.lock.Lock()
				sf.statedb.SetBalance(account.Address, account.Balance)
				sf.statedb.SetNonce(account.Address, account.Nonce)
				sf.statedb.SetCode(account.Address, account.Code)
				sf.lock.Unlock()
			} else {
				req.err = err
			}
		} else {
			storage, err := client.GetStorageAt(ctx, req.Address, req.Key, req.BlockNumber)
			if err == nil {
				sf.lock.Lock()
				sf.statedb.SetState(storage.Address, storage.Key, common.BytesToHash(storage.Value))
				sf.lock.Unlock()
			} else {
				req.err = err
			}
		}
	}
}

func (sf *StateFetcher) loop() {
	defer close(sf.term)
	var sem = make(chan int, sf.maxProcs)
	for {
		select {
		case req := <-sf.req:
			sem <- 1
			go func(req *StateRequest) {
				sf.process(req)
				<-sem
			}(req)
		case <-sf.stop:
			return
		}
	}
}
