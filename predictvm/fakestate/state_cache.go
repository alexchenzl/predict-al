package fakestate

import (
	"bufio"
	"context"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"os"
	"strings"
)

type StateCache struct {
	stateObjects map[common.Address]*stateObject
}

func NewStateCache() *StateCache {
	sc := &StateCache{
		stateObjects: make(map[common.Address]*stateObject),
	}
	return sc
}

func (s *StateCache) Initialize(rc *RpcClient, cacheFile string, blockNumber *big.Int) int {

	readFile, err := os.Open(cacheFile)
	if err == nil {
		defer readFile.Close()

		accountsToFetch := make([]common.Address, 0, 100)
		slotContractsToFetch := make([]common.Address, 0, 100)
		slotKeysToFetch := make([]common.Hash, 0, 100)

		fileScanner := bufio.NewScanner(readFile)
		fileScanner.Split(bufio.ScanLines)

		for fileScanner.Scan() {
			hex := fileScanner.Text()
			arr := strings.Fields(hex)
			if len(arr) == 1 {
				accountsToFetch = append(accountsToFetch, common.HexToAddress(arr[0]))
			} else if len(arr) == 2 {
				slotContractsToFetch = append(slotContractsToFetch, common.HexToAddress(arr[0]))
				slotKeysToFetch = append(slotKeysToFetch, common.HexToHash(arr[0]))
			}
		}

		count := 0
		results, err := rc.GetAccountsAt(context.Background(), accountsToFetch, blockNumber)
		if err == nil {
			for _, result := range results {
				s.SetCode(result.Address, result.Code)
				count++
			}
		}

		slotResults, err := rc.GetStoragesAt(context.Background(), slotContractsToFetch, slotKeysToFetch, blockNumber)
		if err == nil {
			for _, slot := range slotResults {
				s.SetState(slot.Address, slot.Key, common.BytesToHash(slot.Value))
				count++
			}
		}
		return count
	}
	return 0
}
func (s *StateCache) GetState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetState(hash)
	}
	return common.Hash{}
}

func (s *StateCache) SetState(addr common.Address, key, value common.Hash) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetState(key, value)
	}
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (s *StateCache) Exist(addr common.Address) bool {
	return s.getStateObject(addr) != nil
}

// Empty returns whether the given account is empty. Empty
// is defined according to EIP161 (balance = nonce = code = 0).
func (s *StateCache) Empty(addr common.Address) bool {
	so := s.getStateObject(addr)
	return so == nil || so.empty()
}

func (s *StateCache) GetCodeSize(addr common.Address) int {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.CodeSize()
	}
	return -1
}

func (s *StateCache) GetCodeHash(addr common.Address) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return common.BytesToHash(stateObject.CodeHash())
}
func (s *StateCache) GetCode(addr common.Address) []byte {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code()
	}
	return nil
}
func (s *StateCache) SetCode(addr common.Address, code []byte) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
}

func (s *StateCache) getStateObject(addr common.Address) *stateObject {
	if obj := s.stateObjects[addr]; obj != nil && !obj.suicided {
		return obj
	}
	return nil
}

func (s *StateCache) setStateObject(object *stateObject) {
	s.stateObjects[object.Address()] = object
}

// GetOrNewStateObject retrieves a state object or create a new state object if nil.
func (s *StateCache) GetOrNewStateObject(addr common.Address) *stateObject {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		stateObject, _ = s.createObject(addr)
	}
	return stateObject
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
//
func (s *StateCache) createObject(addr common.Address) (newobj, prev *stateObject) {
	//prev = s.getDeletedStateObject(addr) // Note, prev might have been deleted, we need that!
	newobj = newObject(addr, types.StateAccount{})
	s.setStateObject(newobj)
	return newobj, nil
}
