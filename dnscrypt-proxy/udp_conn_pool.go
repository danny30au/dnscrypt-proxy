package main

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jedisct1/dlog"
)

// Pool configuration constants
const (
	// UDPPoolMaxConnsPerAddr is the maximum number of connections to cache per address
	UDPPoolMaxConnsPerAddr = 4

	// UDPPoolMaxIdleTime is the maximum time a connection can be idle before being closed
	UDPPoolMaxIdleTime = 30 * time.Second

	// UDPPoolCleanupInterval is how often the cleanup routine runs
	UDPPoolCleanupInterval = 10 * time.Second

	// UDPPoolShards is the number of shards for lock distribution
	UDPPoolShards = 64

	// UDPPoolDialTimeout is the timeout for creating new connections
	UDPPoolDialTimeout = 5 * time.Second
)

// Common errors
var (
	ErrPoolClosed = errors.New("UDP connection pool is closed")
	ErrNilAddress = errors.New("UDP address cannot be nil")
	ErrDialFailed = errors.New("failed to dial UDP connection")
)

// pooledConn represents a pooled UDP connection with metadata.
// Go 1.26: Added explicit field documentation.
type pooledConn struct {
	conn     *net.UDPConn // The underlying UDP connection
	lastUsed time.Time    // Timestamp of last usage for staleness detection
	addr     string       // String representation of address for logging
}

// poolShard represents a single shard of the connection pool.
// Go 1.26: Using embedded mutex for clearer ownership.
type poolShard struct {
	mu    sync.Mutex                 // Protects conns map
	conns map[string][]*pooledConn  // Map of address to pooled connections
}

// UDPConnPool is a thread-safe pool of UDP connections with automatic cleanup.
// Go 1.26: Using atomic types for better type safety and clearer intent.
type UDPConnPool struct {
	shards   [UDPPoolShards]poolShard // Sharded map for reduced lock contention
	closed   atomic.Bool              // Whether the pool is closed
	stopOnce sync.Once                // Ensures cleanup goroutine stops once
	stopCh   chan struct{}            // Channel to signal cleanup goroutine to stop

	// Metrics
	hits   atomic.Uint64 // Cache hits
	misses atomic.Uint64 // Cache misses
	evicts atomic.Uint64 // Number of connections evicted due to staleness
}

// NewUDPConnPool creates and initializes a new UDP connection pool.
// Go 1.26: Improved initialization with proper capacity hints.
func NewUDPConnPool() *UDPConnPool {
	pool := &UDPConnPool{
		stopCh: make(chan struct{}),
	}

	// Initialize all shards with pre-sized maps
	for i := range pool.shards {
		pool.shards[i].conns = make(map[string][]*pooledConn, 16)
	}

	// Start background cleanup goroutine
	go pool.cleanupLoop()

	dlog.Debug("UDP connection pool initialized")
	return pool
}

// NewUDPConnPoolWithContext creates a pool that respects context cancellation.
// Go 1.26: Context-aware initialization for better lifecycle management.
func NewUDPConnPoolWithContext(ctx context.Context) *UDPConnPool {
	pool := NewUDPConnPool()

	// Monitor context cancellation
	go func() {
		<-ctx.Done()
		pool.Close()
	}()

	return pool
}

// getShard returns the shard for a given address using FNV-1a hash.
// Go 1.26: Using proper hash function instead of custom implementation.
func (p *UDPConnPool) getShard(addr string) *poolShard {
	h := fnv.New32a()
	h.Write([]byte(addr))
	return &p.shards[h.Sum32()%UDPPoolShards]
}

// cleanupLoop periodically removes stale connections from the pool.
// Go 1.26: Better structured cleanup with explicit error handling.
func (p *UDPConnPool) cleanupLoop() {
	ticker := time.NewTicker(UDPPoolCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := p.cleanupStale(); err != nil {
				dlog.Warnf("UDP pool cleanup error: %v", err)
			}
		case <-p.stopCh:
			dlog.Debug("UDP pool cleanup loop stopped")
			return
		}
	}
}

// cleanupStale removes connections that have exceeded the idle timeout.
// Go 1.26: Returns error for better observability, uses clear() for map cleanup.
func (p *UDPConnPool) cleanupStale() error {
	now := time.Now()
	totalClosed := 0

	for i := range p.shards {
		shard := &p.shards[i]

		shard.mu.Lock()

		// Process each address in this shard
		for addr, conns := range shard.conns {
			active := make([]*pooledConn, 0, len(conns))

			for _, pc := range conns {
				if now.Sub(pc.lastUsed) > UDPPoolMaxIdleTime {
					// Connection is stale, close it
					if err := pc.conn.Close(); err != nil {
						dlog.Debugf("UDP pool: error closing stale connection to %s: %v", addr, err)
					} else {
						dlog.Debugf("UDP pool: closed stale connection to %s (idle for %v)", 
							addr, now.Sub(pc.lastUsed))
					}
					totalClosed++
					p.evicts.Add(1)
				} else {
					// Connection is still fresh
					active = append(active, pc)
				}
			}

			// Update or remove the address entry
			if len(active) == 0 {
				delete(shard.conns, addr)
			} else {
				shard.conns[addr] = active
			}
		}

		shard.mu.Unlock()
	}

	if totalClosed > 0 {
		dlog.Debugf("UDP pool: cleaned up %d stale connections", totalClosed)
	}

	return nil
}

// Get retrieves a connection from the pool or creates a new one.
// Go 1.26: Better error handling with wrapped errors and validation.
func (p *UDPConnPool) Get(addr *net.UDPAddr) (*net.UDPConn, error) {
	// Validate input
	if addr == nil {
		return nil, ErrNilAddress
	}

	// Check if pool is closed
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}

	addrStr := addr.String()
	shard := p.getShard(addrStr)

	// Try to get a pooled connection
	shard.mu.Lock()
	conns := shard.conns[addrStr]
	if len(conns) > 0 {
		// Pop the last connection (LIFO for better cache locality)
		pc := conns[len(conns)-1]
		shard.conns[addrStr] = conns[:len(conns)-1]
		shard.mu.Unlock()

		// Clear any existing deadlines
		if err := pc.conn.SetReadDeadline(time.Time{}); err != nil {
			dlog.Debugf("UDP pool: failed to clear read deadline: %v", err)
			pc.conn.Close()
			return p.dialNew(addr)
		}
		if err := pc.conn.SetWriteDeadline(time.Time{}); err != nil {
			dlog.Debugf("UDP pool: failed to clear write deadline: %v", err)
			pc.conn.Close()
			return p.dialNew(addr)
		}

		p.hits.Add(1)
		dlog.Debugf("UDP pool: reusing connection to %s", addrStr)
		return pc.conn, nil
	}
	shard.mu.Unlock()

	// No pooled connection available, create a new one
	p.misses.Add(1)
	return p.dialNew(addr)
}

// dialNew creates a new UDP connection with timeout.
// Go 1.26: Extracted dial logic with proper timeout handling.
func (p *UDPConnPool) dialNew(addr *net.UDPAddr) (*net.UDPConn, error) {
	// Create a context with timeout for the dial operation
	ctx, cancel := context.WithTimeout(context.Background(), UDPPoolDialTimeout)
	defer cancel()

	// Dial with context
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("%w to %s: %v", ErrDialFailed, addr.String(), err)
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("connection to %s is not a UDP connection", addr.String())
	}

	dlog.Debugf("UDP pool: created new connection to %s", addr.String())
	return udpConn, nil
}

// Put returns a connection to the pool for reuse.
// Go 1.26: Better nil checking and error logging.
func (p *UDPConnPool) Put(addr *net.UDPAddr, conn *net.UDPConn) {
	// Validate inputs
	if conn == nil {
		dlog.Debug("UDP pool: attempted to put nil connection")
		return
	}

	if addr == nil {
		dlog.Debug("UDP pool: attempted to put connection with nil address")
		conn.Close()
		return
	}

	// Don't accept connections if pool is closed
	if p.closed.Load() {
		dlog.Debugf("UDP pool: discarding connection to %s (pool closed)", addr.String())
		conn.Close()
		return
	}

	addrStr := addr.String()
	shard := p.getShard(addrStr)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	conns := shard.conns[addrStr]

	// Check if we've reached the limit for this address
	if len(conns) >= UDPPoolMaxConnsPerAddr {
		dlog.Debugf("UDP pool: max connections reached for %s, discarding", addrStr)
		conn.Close()
		return
	}

	// Add to pool
	shard.conns[addrStr] = append(conns, &pooledConn{
		conn:     conn,
		lastUsed: time.Now(),
		addr:     addrStr,
	})

	dlog.Debugf("UDP pool: returned connection to %s (pool size: %d)", addrStr, len(conns)+1)
}

// Discard closes a connection without returning it to the pool.
// Go 1.26: Better error logging.
func (p *UDPConnPool) Discard(conn *net.UDPConn) {
	if conn == nil {
		return
	}

	if err := conn.Close(); err != nil {
		dlog.Debugf("UDP pool: error discarding connection: %v", err)
	} else {
		dlog.Debug("UDP pool: connection discarded")
	}
}

// Close shuts down the pool and closes all pooled connections.
// Go 1.26: Better cleanup with error aggregation and atomic operations.
func (p *UDPConnPool) Close() error {
	// Use atomic.Bool for cleaner code
	if !p.closed.CompareAndSwap(false, true) {
		// Already closed
		return nil
	}

	// Stop the cleanup goroutine
	p.stopOnce.Do(func() {
		close(p.stopCh)
	})

	// Close all pooled connections
	var closeErrors []error
	totalClosed := 0

	for i := range p.shards {
		shard := &p.shards[i]
		shard.mu.Lock()

		for addr, conns := range shard.conns {
			for _, pc := range conns {
				if err := pc.conn.Close(); err != nil {
					closeErrors = append(closeErrors, 
						fmt.Errorf("failed to close connection to %s: %w", addr, err))
				}
				totalClosed++
			}
		}

		// Go 1.21+: Use clear() for efficient map cleanup
		clear(shard.conns)

		shard.mu.Unlock()
	}

	dlog.Infof("UDP connection pool closed (%d connections)", totalClosed)

	// Return aggregated errors if any
	if len(closeErrors) > 0 {
		return fmt.Errorf("errors closing %d connections: %v", len(closeErrors), closeErrors)
	}

	return nil
}

// Stats returns current pool statistics.
// Go 1.26: Added cache hit/miss metrics and better structure.
func (p *UDPConnPool) Stats() PoolStats {
	var stats PoolStats

	// Collect connection counts
	for i := range p.shards {
		shard := &p.shards[i]
		shard.mu.Lock()

		stats.UniqueAddresses += len(shard.conns)
		for _, conns := range shard.conns {
			stats.TotalConnections += len(conns)
		}

		shard.mu.Unlock()
	}

	// Add cache metrics
	stats.CacheHits = p.hits.Load()
	stats.CacheMisses = p.misses.Load()
	stats.Evictions = p.evicts.Load()
	stats.IsClosed = p.closed.Load()

	// Calculate hit rate
	totalRequests := stats.CacheHits + stats.CacheMisses
	if totalRequests > 0 {
		stats.HitRate = float64(stats.CacheHits) / float64(totalRequests)
	}

	return stats
}

// PoolStats contains statistics about the connection pool.
// Go 1.26: New struct for better observability.
type PoolStats struct {
	TotalConnections int     // Total number of pooled connections
	UniqueAddresses  int     // Number of unique addresses with pooled connections
	CacheHits        uint64  // Number of times a connection was reused
	CacheMisses      uint64  // Number of times a new connection was created
	Evictions        uint64  // Number of connections closed due to staleness
	HitRate          float64 // Cache hit rate (0.0 to 1.0)
	IsClosed         bool    // Whether the pool is closed
}

// String returns a human-readable representation of pool stats.
// Go 1.26: Added String() method for easy logging.
func (s PoolStats) String() string {
	return fmt.Sprintf(
		"UDP Pool Stats: %d connections across %d addresses, "+
		"hit rate: %.2f%% (%d hits, %d misses), %d evictions, closed: %v",
		s.TotalConnections,
		s.UniqueAddresses,
		s.HitRate*100,
		s.CacheHits,
		s.CacheMisses,
		s.Evictions,
		s.IsClosed,
	)
}

// LogStats logs the current pool statistics.
// Go 1.26: Convenience method for monitoring.
func (p *UDPConnPool) LogStats() {
	stats := p.Stats()
	dlog.Info(stats.String())
}

// Drain removes all connections from the pool without closing it.
// Go 1.26: New method for pool maintenance without full shutdown.
func (p *UDPConnPool) Drain() error {
	if p.closed.Load() {
		return ErrPoolClosed
	}

	totalDrained := 0
	var drainErrors []error

	for i := range p.shards {
		shard := &p.shards[i]
		shard.mu.Lock()

		for addr, conns := range shard.conns {
			for _, pc := range conns {
				if err := pc.conn.Close(); err != nil {
					drainErrors = append(drainErrors, 
						fmt.Errorf("failed to close connection to %s: %w", addr, err))
				}
				totalDrained++
			}
		}

		// Clear the map
		clear(shard.conns)

		shard.mu.Unlock()
	}

	dlog.Infof("UDP pool drained: %d connections closed", totalDrained)

	if len(drainErrors) > 0 {
		return fmt.Errorf("errors draining pool: %v", drainErrors)
	}

	return nil
}
