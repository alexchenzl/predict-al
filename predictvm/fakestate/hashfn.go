package fakestate

import "github.com/ethereum/go-ethereum/common"

// BlockHashCache contains the recent 256 block hash
type BlockHashCache struct {
	cache map[uint64]common.Hash
}

func NewBlockHashCache(cache map[uint64]common.Hash) *BlockHashCache {
	return &BlockHashCache{
		cache: cache,
	}
}

func (bcache *BlockHashCache) GetHashFn(blockNum uint64) common.Hash {
	if hash, ok := bcache.cache[blockNum]; ok {
		return hash
	}
	return common.Hash{}
}
