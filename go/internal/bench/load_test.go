//go:build loadbench

package bench

// Sustained throughput with many concurrent flows (Lee, 2026-11-18): reported only, never a gate, as Culvert
// judges timing (benchstat on its own runners). `make bench-load` runs it.
//
// Method. N TCP flows are opened (SYN, SYN-ACK, ACK) and then fed in interleaved rounds: round k sends the k-th
// payload segment of every flow, so all N are in flight at once, reassembling and inspecting; nothing is
// closed until the end, when Finish ends every flow. The flows cycle through four synthetic kinds: an HTTP
// request in two segments, a TLS ClientHello in three, an SSH banner and KEXINIT in two, and 512 bytes of
// unidentifiable noise in four (the engine inspects noise until its byte budget). Packets are built decoded
// (transport.TCP), so frame decoding is not measured; everything after it is (tracking, reassembly, dispatch,
// inspection, App-ID and the session record). Throughput is payload bytes over the process's CPU time
// (getrusage) for the feeding rounds: bytes per second per core. Memory is the Go heap in use, sampled after the
// flows are opened, after every round and after Finish, with a collection before each sample so the number is
// live data. With P > 1 the flows are sharded over P analyzers on P goroutines (the engine is single-threaded
// per analyzer, ADR 0001), and CPU time covers them all.

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/analyzer"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

type loadFlow struct {
	client, server transport.Endpoint
	segments       [][]byte
}

func loadSegments(kind int) [][]byte {
	switch kind {
	case 0:
		http := []byte("GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: load\r\nAccept: */*\r\n\r\n")
		return [][]byte{http[:20], http[20:]}
	case 1:
		hello := tlsHello()
		return [][]byte{hello[:5], hello[5:40], hello[40:]}
	case 2:
		ssh := sshKexinit()
		return [][]byte{ssh[:21], ssh[21:]}
	}
	noise := make([]byte, 512)
	for i := range noise {
		noise[i] = byte(0x80 | (i*151+7)%127)
	}
	return [][]byte{noise[:128], noise[128:256], noise[256:384], noise[384:]}
}

// tlsHello is a TLS 1.3 ClientHello with a server name (protocol_fixtures.client_hello_with's layout).
func tlsHello() []byte {
	name := []byte("www.example.com")
	sni := append([]byte{0, 0, 0, byte(len(name) + 5), 0, byte(len(name) + 3), 0, 0, byte(len(name))}, name...)
	versions := []byte{0, 43, 0, 3, 2, 3, 4}
	ext := append(sni, versions...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 6, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f, 1, 0, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func loadFlows(n int) []loadFlow {
	ports := []uint16{80, 443, 22, 9000}
	flows := make([]loadFlow, n)
	templates := [4][][]byte{loadSegments(0), loadSegments(1), loadSegments(2), loadSegments(3)}
	for i := range flows {
		kind := i % 4
		flows[i] = loadFlow{
			client:   transport.Endpoint{Addr: fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255), Port: uint16(20000 + i%40000)},
			server:   transport.Endpoint{Addr: "198.51.100." + strconv.Itoa(1+kind), Port: ports[kind]},
			segments: templates[kind], // shared, read-only
		}
	}
	return flows
}

func cpuSeconds() float64 {
	var u syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &u); err != nil {
		return 0
	}
	return float64(u.Utime.Sec+u.Stime.Sec) + float64(u.Utime.Usec+u.Stime.Usec)/1e6
}

func heapMiB() float64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.HeapInuse) / (1 << 20)
}

type shard struct {
	an      *analyzer.Analyzer
	flows   []loadFlow
	now     float64
	bytes   int
	packets int
}

func (s *shard) feed(p *transport.TCP) {
	s.now += 1e-6
	s.an.Process(s.now, p)
	s.an.Rows = s.an.Rows[:0] // the session records are output, not engine state: drained as an adapter would
}

func (s *shard) open() {
	for _, f := range s.flows {
		s.feed(&transport.TCP{Source: f.client, Destination: f.server, Sequence: 999, Flags: transport.SYN})
		s.feed(&transport.TCP{Source: f.server, Destination: f.client, Sequence: 8999, Ack: 1000, Flags: transport.SYN | transport.ACK})
		s.feed(&transport.TCP{Source: f.client, Destination: f.server, Sequence: 1000, Ack: 9000, Flags: transport.ACK})
	}
}

func (s *shard) round(k int) {
	for _, f := range s.flows {
		if k >= len(f.segments) {
			continue
		}
		offset := 0
		for _, seg := range f.segments[:k] {
			offset += len(seg)
		}
		seg := f.segments[k]
		s.feed(&transport.TCP{Source: f.client, Destination: f.server, Sequence: uint32(1000 + offset), Ack: 9000,
			Flags: 0x08 | transport.ACK, Payload: seg}) // PSH | ACK
		s.bytes += len(seg)
		s.packets++
	}
}

func TestLoad_ConcurrentFlowsReport(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	sizes := []int{10000, 100000}
	if v := os.Getenv("LOAD_FLOWS"); v != "" {
		n, _ := strconv.Atoi(v)
		sizes = []int{n}
	}
	workers := []int{1, runtime.GOMAXPROCS(0)}
	if workers[1] == 1 {
		workers = workers[:1]
	}
	for _, n := range sizes {
		for _, p := range workers {
			flows := loadFlows(n)
			shards := make([]*shard, p)
			for w := range shards {
				an, err := analyzer.New(pack, analyzer.Options{Rows: true, Session: session.Options{MaxConnections: n/p + 1, ByteLimit: 16384,
					IdleTimeout: 3600, MaxUDPFlows: 1, Compact: true, Observation: "handshake"}})
				if err != nil {
					t.Fatal(err)
				}
				shards[w] = &shard{an: an}
			}
			for i, f := range flows {
				shards[i%p].flows = append(shards[i%p].flows, f)
			}
			base := heapMiB()
			parallel := func(step func(*shard)) {
				var wg sync.WaitGroup
				for _, s := range shards {
					wg.Add(1)
					go func(s *shard) { defer wg.Done(); step(s) }(s)
				}
				wg.Wait()
			}
			parallel(func(s *shard) { s.open() })
			opened := heapMiB()
			samples := []string{fmt.Sprintf("open %.1f", opened-base)}
			peak := opened - base
			cpu0, wall0 := cpuSeconds(), time.Now()
			measuredCPU, measuredWall := 0.0, time.Duration(0)
			for k := 0; k < 4; k++ {
				c, w := cpuSeconds(), time.Now()
				parallel(func(s *shard) { s.round(k) })
				measuredCPU += cpuSeconds() - c
				measuredWall += time.Since(w)
				h := heapMiB() - base
				if h > peak {
					peak = h
				}
				samples = append(samples, fmt.Sprintf("round %d %.1f", k+1, h))
			}
			_ = cpu0
			_ = wall0
			parallel(func(s *shard) {
				if err := s.an.Finish("load test end"); err != nil {
					t.Error(err)
				}
				s.an.Rows = nil // a truncated slice would keep the final records reachable
			})
			after := heapMiB() - base
			total, packets := 0, 0
			for _, s := range shards {
				total += s.bytes
				packets += s.packets
			}
			t.Logf("flows %6d  workers %d  payload %6.1f MiB in %d segments  CPU %6.2f s  wall %6.2f s  %7.1f MiB/s and %4.0f k segments/s per core  %7.1f MiB/s wall  "+
				"heap peak %7.1f MiB (%5.0f B/flow)  after Finish %5.1f MiB  samples [%s]",
				n, p, float64(total)/(1<<20), packets, measuredCPU, measuredWall.Seconds(), float64(total)/(1<<20)/measuredCPU, float64(packets)/measuredCPU/1000,
				float64(total)/(1<<20)/measuredWall.Seconds(), peak, peak*(1<<20)/float64(n), after, joinSamples(samples))
			runtime.KeepAlive(shards)
		}
	}
}

func joinSamples(samples []string) string {
	out := ""
	for i, s := range samples {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
