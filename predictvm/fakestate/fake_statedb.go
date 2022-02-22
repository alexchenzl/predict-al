package fakestate

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	// emptyRoot is the known root hash of an empty trie.
	emptyRoot = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
)

type Snapshot struct {
	stateObjects map[common.Address]*stateObject
	refund       uint64
}

// FakeStateDB structs within the ethereum protocol are used to store anything
// within the merkle trie. StateDBs take care of caching and storing
// nested states. It's the general query interface to retrieve:
// * Contracts
// * Accounts
type FakeStateDB struct {
	stateObjects map[common.Address]*stateObject

	// The refund counter, also used by state transitioning.
	refund uint64

	nextSnapshotId int
	snapshots      map[int]*Snapshot
}

// New creates a new state from a given trie.
func NewStateDB() *FakeStateDB {
	sdb := &FakeStateDB{
		stateObjects:   make(map[common.Address]*stateObject),
		nextSnapshotId: 0,
		snapshots:      make(map[int]*Snapshot),
	}
	return sdb
}

// getStateObject retrieves a state object given by the address, returning nil if
// the object is not found or was deleted in this execution context. If you need
// to differentiate between non-existent/just-deleted, use getDeletedStateObject.
//
// TODO: since this engine will never Finalize states, state object will never be deleted, this needs optimization later
func (s *FakeStateDB) getStateObject(addr common.Address) *stateObject {
	if obj := s.stateObjects[addr]; obj != nil && !obj.suicided {
		return obj
	}
	return nil
}

func (s *FakeStateDB) setStateObject(object *stateObject) {
	s.stateObjects[object.Address()] = object
}

// GetOrNewStateObject retrieves a state object or create a new state object if nil.
func (s *FakeStateDB) GetOrNewStateObject(addr common.Address) *stateObject {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		stateObject, _ = s.createObject(addr)
	}
	return stateObject
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
//
func (s *FakeStateDB) createObject(addr common.Address) (newobj, prev *stateObject) {
	//prev = s.getDeletedStateObject(addr) // Note, prev might have been deleted, we need that!
	newobj = newObject(addr, types.StateAccount{})
	s.setStateObject(newobj)
	return newobj, nil
}

// CreateAccount explicitly creates a state object. If a state object with the address
// already exists the balance is carried over to the new account.
//
// CreateAccount is called during the EVM CREATE operation. The situation might arise that
// a contract does the following:
//
//   1. sends funds to sha(account ++ (nonce + 1))
//   2. tx_create(sha(account ++ nonce)) (note that this gets the address of 1)
//
// Carrying over the balance ensures that Ether doesn't disappear.
func (s *FakeStateDB) CreateAccount(addr common.Address) {
	newObj, prev := s.createObject(addr)
	if prev != nil {
		newObj.setBalance(prev.data.Balance)
	}
}

// SubBalance subtracts amount from the account associated with addr.
func (s *FakeStateDB) SubBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SubBalance(amount)
	}
}

func (s *FakeStateDB) AddBalance(addr common.Address, amount *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.AddBalance(amount)
	}
}

func (s *FakeStateDB) GetBalance(addr common.Address) *big.Int {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Balance()
	}
	return common.Big0
}

func (s *FakeStateDB) SetBalance(addr common.Address, balance *big.Int) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetBalance(balance)
	}
}

func (s *FakeStateDB) GetNonce(addr common.Address) uint64 {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}
	return 0
}

func (s *FakeStateDB) SetNonce(addr common.Address, nonce uint64) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
}

func (s *FakeStateDB) GetCodeHash(addr common.Address) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return common.BytesToHash(stateObject.CodeHash())
}
func (s *FakeStateDB) GetCode(addr common.Address) []byte {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code()
	}
	return nil
}
func (s *FakeStateDB) SetCode(addr common.Address, code []byte) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
}

func (s *FakeStateDB) GetCodeSize(addr common.Address) int {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.CodeSize()
	}
	return -1
}

func (s *FakeStateDB) AddRefund(gas uint64) {
	s.refund += gas
}
func (s *FakeStateDB) SubRefund(gas uint64) {
	if gas > s.refund {
		panic(fmt.Sprintf("Refund counter below zero (gas: %d > refund: %d)", gas, s.refund))
	}
	s.refund -= gas
}

// GetRefund returns the current value of the refund counter.
func (s *FakeStateDB) GetRefund() uint64 {
	return s.refund
}

func (s *FakeStateDB) GetState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetState(hash)
	}
	return common.Hash{}
}
func (s *FakeStateDB) SetState(addr common.Address, key, value common.Hash) {
	stateObject := s.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetState(key, value)
	}
}

// Suicide marks the given account as suicided.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after Suicide.
func (s *FakeStateDB) Suicide(addr common.Address) bool {
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		return false
	}
	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)

	return true
}

func (s *FakeStateDB) HasSuicided(addr common.Address) bool {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.suicided
	}
	return false
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (s *FakeStateDB) Exist(addr common.Address) bool {
	return s.getStateObject(addr) != nil
}

// Empty returns whether the given account is empty. Empty
// is defined according to EIP161 (balance = nonce = code = 0).
func (s *FakeStateDB) Empty(addr common.Address) bool {
	so := s.getStateObject(addr)
	return so == nil || so.empty()
}

// GetCommittedState retrieves a value from the given account's committed storage trie.
func (s *FakeStateDB) GetCommittedState(addr common.Address, hash common.Hash) common.Hash {
	stateObject := s.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetCommittedState(hash)
	}
	return common.Hash{}
}

func (s *FakeStateDB) RevertToSnapshot(id int) {
	if snapshot, ok := s.snapshots[id]; ok {
		stateObjects := make(map[common.Address]*stateObject, len(snapshot.stateObjects))
		for key, value := range snapshot.stateObjects {
			stateObjects[key] = value.deepCopy()
		}
		s.stateObjects = stateObjects
		s.refund = snapshot.refund
	}
}

func (s *FakeStateDB) Snapshot() int {
	snapshot := &Snapshot{
		stateObjects: make(map[common.Address]*stateObject, len(s.stateObjects)),
		refund:       s.refund,
	}
	for key, value := range s.stateObjects {
		snapshot.stateObjects[key] = value.deepCopy()
	}
	s.snapshots[s.nextSnapshotId] = snapshot
	s.nextSnapshotId++
	return s.nextSnapshotId - 1
}

// Copy creates a deep, independent copy of the state, but not including snapshots
func (s *FakeStateDB) Copy() *FakeStateDB {
	// Copy all the basic fields, initialize the memory ones
	state := &FakeStateDB{
		stateObjects:   make(map[common.Address]*stateObject, len(s.stateObjects)),
		refund:         s.refund,
		nextSnapshotId: 0,
		snapshots:      make(map[int]*Snapshot),
	}
	for key, value := range s.stateObjects {
		state.stateObjects[key] = value.deepCopy()
	}
	return state
}
