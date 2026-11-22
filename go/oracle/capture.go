// Package oracle compares the Go engine with tshark on traffic that real, unmodified implementations (OpenSSL,
// curl, quic-go) exchange over 127.0.0.1 (PRO-127). It is test-only: no shipped package imports it, and its
// dependencies (gopacket, quic-go) are pinned in this module's go.sum, never in go/go.mod or go/vendor.
//
// The traffic passes through a relay that writes it to a pcap with synthetic Ethernet, IPv4 and TCP/UDP headers
// (no capture privileges), in a test temporary directory that is removed afterwards. gopacket reads and
// reassembles that pcap independently of the engine's own decoder; the engine classifies each flow; tshark, run
// as an external process, dissects the same file. See README.md for the recipe, the pinned tools and licences.
package oracle

import (
	"net"
	"os"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Recorder writes synthetic frames to one pcap file. Safe for concurrent use.
type Recorder struct {
	mu   sync.Mutex
	file *os.File
	w    *pcapgo.Writer
	now  time.Time
	err  error
}

// NewRecorder creates path as an Ethernet pcap.
func NewRecorder(path string) (*Recorder, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		return nil, err
	}
	return &Recorder{file: f, w: w, now: time.Unix(1_800_000_000, 0)}, nil
}

// Close flushes the file and reports the first write error.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.file.Close(); r.err == nil {
		r.err = err
	}
	return r.err
}

// write serialises one frame (checksums computed) with a timestamp one millisecond after the previous frame.
func (r *Recorder) write(ip *layers.IPv4, transport gopacket.SerializableLayer, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return
	}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, transport, gopacket.Payload(payload)); err != nil {
		r.err = err
		return
	}
	r.now = r.now.Add(time.Millisecond)
	data := buf.Bytes()
	r.err = r.w.WritePacket(gopacket.CaptureInfo{Timestamp: r.now, CaptureLength: len(data), Length: len(data)}, data)
}

func ipv4(src, dst net.IP, proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{Version: 4, TTL: 64, Protocol: proto, SrcIP: src.To4(), DstIP: dst.To4()}
}

// UDP records one datagram.
func (r *Recorder) UDP(src, dst *net.UDPAddr, payload []byte) {
	ip := ipv4(src.IP, dst.IP, layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: layers.UDPPort(src.Port), DstPort: layers.UDPPort(dst.Port)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		r.mu.Lock()
		r.err = err
		r.mu.Unlock()
		return
	}
	r.write(ip, udp, payload)
}

// Shape is how a TCP flow's bytes become segments: at most Segment bytes each (0: one segment per read), and
// with Swap every second pair of segments is written in reverse order, so readers must reassemble out of order.
type Shape struct {
	Segment int
	Swap    bool
}

// TCPFlow records one connection: the three-way handshake, data in both directions and a FIN exchange.
type TCPFlow struct {
	r              *Recorder
	mu             sync.Mutex
	client, server *net.TCPAddr
	seq            [2]uint32 // next sequence number sent by the client [0] and the server [1]
	shape          Shape
}

// NewTCPFlow writes the handshake of a connection from client to server.
func (r *Recorder) NewTCPFlow(client, server *net.TCPAddr, shape Shape) *TCPFlow {
	f := &TCPFlow{r: r, client: client, server: server, seq: [2]uint32{1000, 5000}, shape: shape}
	f.segment(0, &layers.TCP{SYN: true}, nil)
	f.seq[0]++
	f.segment(1, &layers.TCP{SYN: true, ACK: true}, nil)
	f.seq[1]++
	f.segment(0, &layers.TCP{ACK: true}, nil)
	return f
}

// segment writes one TCP segment from side (0 client, 1 server) at that side's current sequence number.
func (f *TCPFlow) segment(side int, tcp *layers.TCP, payload []byte) {
	f.segmentAt(side, f.seq[side], tcp, payload)
}

func (f *TCPFlow) segmentAt(side int, seq uint32, tcp *layers.TCP, payload []byte) {
	src, dst := f.client, f.server
	if side == 1 {
		src, dst = f.server, f.client
	}
	ip := ipv4(src.IP, dst.IP, layers.IPProtocolTCP)
	tcp.SrcPort, tcp.DstPort = layers.TCPPort(src.Port), layers.TCPPort(dst.Port)
	tcp.Seq, tcp.Window = seq, 65535
	if !tcp.SYN || tcp.ACK {
		tcp.ACK, tcp.Ack = true, f.seq[1-side]
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		f.r.mu.Lock()
		f.r.err = err
		f.r.mu.Unlock()
		return
	}
	f.r.write(ip, tcp, payload)
}

// Data records bytes sent by the client (fromClient) or the server, shaped by the flow's Shape.
func (f *TCPFlow) Data(fromClient bool, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	side := 1
	if fromClient {
		side = 0
	}
	size := f.shape.Segment
	if size <= 0 {
		size = len(data)
	}
	type piece struct {
		seq  uint32
		data []byte
	}
	var pieces []piece
	for pos := 0; pos < len(data); pos += size {
		end := min(pos+size, len(data))
		pieces = append(pieces, piece{f.seq[side] + uint32(pos), data[pos:end]})
	}
	if f.shape.Swap {
		for i := 0; i+1 < len(pieces); i += 4 {
			pieces[i], pieces[i+1] = pieces[i+1], pieces[i]
		}
	}
	for _, p := range pieces {
		f.segmentAt(side, p.seq, &layers.TCP{PSH: true}, p.data)
	}
	f.seq[side] += uint32(len(data))
}

// Close writes the FIN exchange.
func (f *TCPFlow) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.segment(0, &layers.TCP{FIN: true}, nil)
	f.seq[0]++
	f.segment(1, &layers.TCP{FIN: true}, nil)
	f.seq[1]++
	f.segment(0, &layers.TCP{}, nil)
}
