package main

import (
"encoding/binary"
"net"
"sync"
"sync/atomic"
"time"
"unique"

"github.com/jedisct1/dlog"
)

type UDPPoolConfig struct {
MaxConnsPerAddr int
MaxIdleTime     time.Duration
CleanupInterval time.Duration
}

func DefaultUDPPoolConfig() UDPPoolConfig {
return UDPPoolConfig{
MaxConnsPerAddr: 1000,
MaxIdleTime:     120 * time.Second,
CleanupInterval: 10 * time.Second,
}
}

type pooledConn struct {
conn     *net.UDPConn
lastUsed int64
}

type connKey struct {
ip   [16]byte
port int
zone string
net  string
}

type poolShard struct {
mu       sync.Mutex
conns    map[unique.Handle[connKey]][]pooledConn
connPool sync.Pool
_        [40]byte
}

type UDPConnPool struct {
stats struct {
hits      int64
misses    int64
evicted   int64
totalOpen int64
}

now             int64
cleanupInterval int64
closed          int32
stopCh          chan struct{}
once            sync.Once
config          UDPPoolConfig

_ [64]byte

shards    [64]poolShard
closePool sync.Pool
}

func NewUDPConnPool() *UDPConnPool {
pool := &UDPConnPool{
config: DefaultUDPPoolConfig(),
stopCh: make(chan struct{}),
}
atomic.StoreInt64(&pool.now, time.Now().UnixNano())
atomic.StoreInt64(&pool.cleanupInterval, int64(pool.config.CleanupInterval))

pool.closePool.New = func() interface{} {
s := make([]*net.UDPConn, 0, 64)
return &s
}

for i := range pool.shards {
shard := &pool.shards[i]
shard.conns = make(map[unique.Handle[connKey]][]pooledConn, 64)
shard.connPool.New = func() interface{} {
s := make([]pooledConn, 0, 16)
return &s
}
}
go pool.loop()
return pool
}

//go:inline
func (p *UDPConnPool) getShard(key *connKey) *poolShard {
h := uint32(2166136261)

v1 := binary.LittleEndian.Uint64(key.ip[:8])
v2 := binary.LittleEndian.Uint64(key.ip[8:])

h = (h ^ uint32(v1)) * 16777619
h = (h ^ uint32(v1>>32)) * 16777619
h = (h ^ uint32(v2)) * 16777619
h = (h ^ uint32(v2>>32)) * 16777619
h = (h ^ uint32(key.port)) * 16777619

return &p.shards[h&63]
}

//go:inline
func (p *UDPConnPool) makeKey(network string, addr *net.UDPAddr) connKey {
var k connKey
k.net = network
k.port = addr.Port
k.zone = addr.Zone

ip := addr.IP
if len(ip) == 4 {
k.ip[10] = 0xff
k.ip[11] = 0xff
copy(k.ip[12:], ip)
} else if len(ip) == 16 {
copy(k.ip[:], ip)
}
return k
}

func (p *UDPConnPool) loop() {
cleanupTicker := time.NewTicker(p.config.CleanupInterval)
timeTicker := time.NewTicker(1 * time.Second)
defer cleanupTicker.Stop()
defer timeTicker.Stop()

for {
select {
case <-timeTicker.C:
atomic.StoreInt64(&p.now, time.Now().UnixNano())

case <-cleanupTicker.C:
p.cleanupStale()
interval := time.Duration(atomic.LoadInt64(&p.cleanupInterval))
if interval != p.config.CleanupInterval {
cleanupTicker.Reset(interval)
}

case <-p.stopCh:
return
}
}
}

func (p *UDPConnPool) cleanupStale() {
now := atomic.LoadInt64(&p.now)
maxIdle := int64(p.config.MaxIdleTime)

toClosePtr := p.closePool.Get().(*[]*net.UDPConn)
toClose := (*toClosePtr)[:0]
totalConns := 0

for i := range p.shards {
shard := &p.shards[i]
shard.mu.Lock()

for key, conns := range shard.conns {
totalConns += len(conns)
n := 0
for j := range conns {
if now-conns[j].lastUsed > maxIdle {
toClose = append(toClose, conns[j].conn)
continue
}
if n != j {
conns[n] = conns[j]
}
n++
}

if n == 0 {
delete(shard.conns, key)
} else if n < len(conns) {
if cap(conns) > 128 && n < cap(conns)>>2 {
connPoolPtr := shard.connPool.Get().(*[]pooledConn)
newConns := (*connPoolPtr)[:0]
if cap(newConns) < n {
newConns = make([]pooledConn, n, n)
} else {
newConns = newConns[:n]
}
copy(newConns, conns[:n])
shard.conns[key] = newConns
} else {
for k := n; k < len(conns); k++ {
conns[k] = pooledConn{}
}
shard.conns[key] = conns[:n]
}
}
}
shard.mu.Unlock()
}

evicted := len(toClose)
if evicted > 0 {
count := int64(evicted)
atomic.AddInt64(&p.stats.evicted, count)
atomic.AddInt64(&p.stats.totalOpen, -count)
for i := range toClose {
_ = toClose[i].Close()
toClose[i] = nil
}

evictionRate := float64(evicted) / float64(totalConns+evicted)
currentInterval := atomic.LoadInt64(&p.cleanupInterval)

if evictionRate < 0.05 {
newInterval := currentInterval * 2
if newInterval > int64(60*time.Second) {
newInterval = int64(60 * time.Second)
}
if newInterval != currentInterval {
atomic.StoreInt64(&p.cleanupInterval, newInterval)
dlog.Debugf("UDP pool: low eviction rate (%.1f%%), increasing interval to %v", evictionRate*100, time.Duration(newInterval))
}
} else if evictionRate > 0.30 {
newInterval := currentInterval / 2
if newInterval < int64(time.Second) {
newInterval = int64(time.Second)
}
if newInterval != currentInterval {
atomic.StoreInt64(&p.cleanupInterval, newInterval)
dlog.Debugf("UDP pool: high eviction rate (%.1f%%), decreasing interval to %v", evictionRate*100, time.Duration(newInterval))
}
}

dlog.Debugf("UDP pool: evicted %d stale connections (%.1f%%)", count, evictionRate*100)
}

*toClosePtr = toClose
p.closePool.Put(toClosePtr)
}

func (p *UDPConnPool) GetNet(network string, addr *net.UDPAddr) (*net.UDPConn, error) {
key := p.makeKey(network, addr)
handle := unique.Make(key)
shard := p.getShard(&key)

shard.mu.Lock()
conns := shard.conns[handle]
n := len(conns)
if n > 0 {
pc := conns[n-1]
conns[n-1] = pooledConn{}
shard.conns[handle] = conns[:n-1]
shard.mu.Unlock()

atomic.AddInt64(&p.stats.hits, 1)
return pc.conn, nil
}
shard.mu.Unlock()

atomic.AddInt64(&p.stats.misses, 1)
conn, err := net.DialUDP(network, nil, addr)
if err == nil {
atomic.AddInt64(&p.stats.totalOpen, 1)
_ = conn.SetReadBuffer(2 * 1024 * 1024)
_ = conn.SetWriteBuffer(2 * 1024 * 1024)
}
return conn, err
}

func (p *UDPConnPool) PutNet(network string, addr *net.UDPAddr, conn *net.UDPConn) {
if conn == nil {
return
}
if atomic.LoadInt32(&p.closed) != 0 {
_ = conn.Close()
atomic.AddInt64(&p.stats.totalOpen, -1)
return
}

key := p.makeKey(network, addr)
handle := unique.Make(key)
shard := p.getShard(&key)

shard.mu.Lock()
if atomic.LoadInt32(&p.closed) != 0 {
shard.mu.Unlock()
_ = conn.Close()
atomic.AddInt64(&p.stats.totalOpen, -1)
return
}

conns := shard.conns[handle]
if len(conns) >= p.config.MaxConnsPerAddr {
shard.mu.Unlock()
_ = conn.Close()
atomic.AddInt64(&p.stats.totalOpen, -1)
return
}

now := atomic.LoadInt64(&p.now)
shard.conns[handle] = append(conns, pooledConn{conn: conn, lastUsed: now})
shard.mu.Unlock()
}

func (p *UDPConnPool) Close() {
p.once.Do(func() {
close(p.stopCh)
atomic.StoreInt32(&p.closed, 1)

for i := range p.shards {
shard := &p.shards[i]
shard.mu.Lock()
for _, conns := range shard.conns {
for j := range conns {
_ = conns[j].conn.Close()
}
}
shard.conns = nil
shard.mu.Unlock()
}
dlog.Debug("UDP connection pool closed")
})
}

func (p *UDPConnPool) Stats() map[string]int64 {
return map[string]int64{
"hits":       atomic.LoadInt64(&p.stats.hits),
"misses":     atomic.LoadInt64(&p.stats.misses),
"evicted":    atomic.LoadInt64(&p.stats.evicted),
"total_open": atomic.LoadInt64(&p.stats.totalOpen),
}
}

func (p *UDPConnPool) Get(addr *net.UDPAddr) (*net.UDPConn, error) {
return p.GetNet("udp", addr)
}

func (p *UDPConnPool) Put(addr *net.UDPAddr, conn *net.UDPConn) {
p.PutNet("udp", addr, conn)
}

func (p *UDPConnPool) Discard(conn *net.UDPConn) {
if conn != nil {
_ = conn.Close()
atomic.AddInt64(&p.stats.totalOpen, -1)
}
}
