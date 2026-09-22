package ca

import (
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/keycardai/egress-proxy/internal/policy"
)

// renewBefore is how close to a leaf's NotAfter the store stops serving it
// from cache. Inside that window the store mints a new leaf, so a client
// never receives one that is about to expire.
const renewBefore = 5 * time.Minute

var errNoAuthority = errors.New("ca: store has no authority")

// Store is a bounded cache of minted leaves keyed by server name.
//
// When minting fails, the store caches nothing and returns the error, so the
// handshake fails and the proxy refuses the connection. NEVER swallow a
// minting error here.
type Store struct {
	authority *Authority
	// mu serializes minting, so two simultaneous handshakes for one name
	// mint one leaf.
	mu    sync.Mutex
	cache *lru.Cache[string, *tls.Certificate]
	mints atomic.Int64
	now   func() time.Time
}

// NewStore returns a store over authority holding at most size leaves.
func NewStore(authority *Authority, size int) (*Store, error) {
	if authority == nil {
		return nil, errNoAuthority
	}
	cache, err := lru.New[string, *tls.Certificate](max(size, 1))
	if err != nil {
		return nil, fmt.Errorf("ca: leaf cache: %w", err)
	}
	return &Store{authority: authority, cache: cache, now: authority.opts.Now}, nil
}

// Certificate returns the leaf for serverName, minting one on a miss or when
// the cached one is within renewBefore of expiry.
func (s *Store) Certificate(serverName string) (*tls.Certificate, error) {
	key := policy.NormalizeHost(serverName)
	s.mu.Lock()
	defer s.mu.Unlock()

	if cert, ok := s.cache.Get(key); ok && s.usable(cert) {
		return cert, nil
	}
	cert, err := s.authority.Leaf(key)
	if err != nil {
		return nil, err
	}
	s.mints.Add(1)
	s.cache.Add(key, cert)
	return cert, nil
}

// Mints counts the leaves this store minted. Tests read it to show that a
// refused connection never reached the authority.
func (s *Store) Mints() int64 {
	return s.mints.Load()
}

// Len is the number of cached leaves.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cache.Len()
}

func (s *Store) usable(cert *tls.Certificate) bool {
	return cert != nil && cert.Leaf != nil && s.now().Add(renewBefore).Before(cert.Leaf.NotAfter)
}
