package fakestate

import (
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type StateRequest struct {
	blockNumber *big.Int
	Address     *common.Address
	Key         *common.Hash
	Done        chan struct{}
	err         error
}

type StateFetcher struct {
	statedb  *FakeStateDB
	maxProcs int
	url      string

	lock sync.Mutex // Protect statdb

	req  chan *StateRequest
	stop chan struct{} // Channel to interrupt processing
	term chan struct{} // Channel to signal iterruption
}

func NewStateFetcher(statedb *FakeStateDB, url string, maxProcs int) *StateFetcher {
	sf := &StateFetcher{
		statedb:  statedb,
		maxProcs: maxProcs,
		url:      url,
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

func (sf *StateFetcher) Fetch(accounts []*common.Address, keys []*common.Hash) error {

	if accounts == nil || keys == nil || len(accounts) != len(keys) {
		return errors.New("invalid parameters")
	}

	requests := make([]StateRequest, len(accounts))

	for i := 0; i < len(accounts); i++ {
		requests[i].Address = accounts[i]
		requests[i].Key = keys[i]
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
			account, err := client.GetAccountAt(ctx, req.Address, req.blockNumber)
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
			storage, err := client.GetStorageAt(ctx, req.Address, req.Key, req.blockNumber)
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
