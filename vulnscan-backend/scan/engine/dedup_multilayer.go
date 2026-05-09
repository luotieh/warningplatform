package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

type BloomFilter struct {
	bits   []bool
	size   uint
	hashes uint
}

func NewBloomFilter(size uint, fpRate float64) *BloomFilter {
	if size == 0 {
		size = 1000000
	}
	if fpRate <= 0 {
		fpRate = 0.01
	}

	numHashes := uint(-1.44 * log2(fpRate))
	if numHashes < 1 {
		numHashes = 1
	}
	if numHashes > 10 {
		numHashes = 10
	}

	return &BloomFilter{
		bits:   make([]bool, size),
		size:   size,
		hashes: numHashes,
	}
}

func (bf *BloomFilter) Add(data string) {
	for i := uint(0); i < bf.hashes; i++ {
		h := bf.hash(data, i)
		bf.bits[h%bf.size] = true
	}
}

func (bf *BloomFilter) Test(data string) bool {
	for i := uint(0); i < bf.hashes; i++ {
		h := bf.hash(data, i)
		if !bf.bits[h%bf.size] {
			return false
		}
	}
	return true
}

func (bf *BloomFilter) hash(data string, seed uint) uint {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d%s", seed, data)))
	var result uint
	for _, b := range h[:8] {
		result = result*31 + uint(b)
	}
	return result
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	result := 0.0
	for x > 1 {
		x /= 2
		result++
	}
	return result
}

type DedupStore interface {
	Exists(fp string) bool
	Store(fp string) error
	Cleanup(before int64) error
}

type InMemoryDedupStore struct {
	mu   sync.RWMutex
	data map[string]int64
}

func NewInMemoryDedupStore() *InMemoryDedupStore {
	return &InMemoryDedupStore{
		data: make(map[string]int64),
	}
}

func (s *InMemoryDedupStore) Exists(fp string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[fp]
	return ok
}

func (s *InMemoryDedupStore) Store(fp string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[fp] = 0
	return nil
}

func (s *InMemoryDedupStore) Cleanup(before int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for fp, ts := range s.data {
		if ts < before {
			delete(s.data, fp)
		}
	}
	return nil
}

type MultiLayerDeduplicator struct {
	mu                sync.RWMutex
	bloomFilter       *BloomFilter
	exactFingerprints sync.Map
	persistentStore   DedupStore
	crossTaskEnabled  bool
}

func NewMultiLayerDeduplicator(bloomSize uint, fpRate float64, crossTask bool, store DedupStore) *MultiLayerDeduplicator {
	if store == nil {
		store = NewInMemoryDedupStore()
	}
	return &MultiLayerDeduplicator{
		bloomFilter:      NewBloomFilter(bloomSize, fpRate),
		persistentStore:  store,
		crossTaskEnabled: crossTask,
	}
}

func (d *MultiLayerDeduplicator) IsDuplicate(taskID string, f *Finding) bool {
	fp := d.computeFingerprint(taskID, f)

	if !d.bloomFilter.Test(fp) {
		d.bloomFilter.Add(fp)
		d.exactFingerprints.Store(fp, struct{}{})
		if d.crossTaskEnabled {
			d.persistentStore.Store(fp)
		}
		return false
	}

	if _, exists := d.exactFingerprints.Load(fp); !exists {
		d.exactFingerprints.Store(fp, struct{}{})
		if d.crossTaskEnabled {
			d.persistentStore.Store(fp)
		}
		return false
	}

	if d.crossTaskEnabled {
		return d.persistentStore.Exists(fp)
	}

	return true
}

func (d *MultiLayerDeduplicator) computeFingerprint(taskID string, f *Finding) string {
	var parts []string

	if f.Target != nil {
		parts = append(parts, f.Target.Host, f.Target.IP, fmt.Sprintf("%d", f.Target.Port))
	}
	parts = append(parts, f.ModuleID, f.Type, f.Title)

	if f.Data != nil {
		if param, ok := f.Data["param"]; ok {
			parts = append(parts, "p:"+param)
		}
		if via, ok := f.Data["inject_via"]; ok {
			parts = append(parts, "iv:"+via)
		}
	}

	if !d.crossTaskEnabled {
		parts = append(parts, taskID)
	}

	raw := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:16])
}

func (d *MultiLayerDeduplicator) DeduplicateFindings(taskID string, findings []*Finding) []*Finding {
	var unique []*Finding
	for _, f := range findings {
		if !d.IsDuplicate(taskID, f) {
			unique = append(unique, f)
		}
	}
	return unique
}

func (d *MultiLayerDeduplicator) Count() int {
	count := 0
	d.exactFingerprints.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func (d *MultiLayerDeduplicator) Reset() {
	d.bloomFilter = NewBloomFilter(d.bloomFilter.size, 0.01)
	d.exactFingerprints = sync.Map{}
}
