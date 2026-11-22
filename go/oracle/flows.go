package oracle

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/gopacket/gopacket/reassembly"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/protocols/quicx"
)

// Flow is the client-to-server side of one TCP connection (as reassembled chunks, in order) or one UDP flow (its
// datagrams). Key is "tcp|udp client>server", the same key the tshark rows are grouped by.
type Flow struct {
	Key    string
	Proto  string
	Chunks [][]byte
}

func key(proto, srcIP, srcPort, dstIP, dstPort string) string {
	return fmt.Sprintf("%s %s:%s>%s:%s", proto, srcIP, srcPort, dstIP, dstPort)
}

type streamFactory struct{ flows map[string]*Flow }

type stream struct{ flow *Flow }

func (f *streamFactory) New(netFlow, tcpFlow gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	k := key("tcp", netFlow.Src().String(), tcpFlow.Src().String(), netFlow.Dst().String(), tcpFlow.Dst().String())
	flow, ok := f.flows[k]
	if !ok { // the pool can create a stream more than once for a connection (after its close); keep one flow
		flow = &Flow{Key: k, Proto: "tcp"}
		f.flows[k] = flow
	}
	return &stream{flow: flow}
}

func (s *stream) Accept(*layers.TCP, gopacket.CaptureInfo, reassembly.TCPFlowDirection, reassembly.Sequence, *bool,
	reassembly.AssemblerContext) bool {
	return true
}

func (s *stream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()
	length, _ := sg.Lengths()
	if dir == reassembly.TCPDirClientToServer && length > 0 {
		s.flow.Chunks = append(s.flow.Chunks, append([]byte(nil), sg.Fetch(length)...))
	}
}

func (s *stream) ReassemblyComplete(reassembly.AssemblerContext) bool { return true }

type captureContext gopacket.CaptureInfo

func (c captureContext) GetCaptureInfo() gopacket.CaptureInfo { return gopacket.CaptureInfo(c) }

// ReadFlows reads a pcap with gopacket and returns its flows, sorted by key. The TCP client is the SYN sender;
// the UDP client is the sender of a flow's first datagram.
func ReadFlows(path string) ([]*Flow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		return nil, err
	}
	factory := &streamFactory{flows: map[string]*Flow{}}
	assembler := reassembly.NewAssembler(reassembly.NewStreamPool(factory))
	udp := map[string]*Flow{}
	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			break // io.EOF, or a truncated record at the end
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ip == nil {
			continue
		}
		if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, captureContext(ci))
			continue
		}
		if u, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			src, dst := ip.SrcIP.String(), ip.DstIP.String()
			sp, dp := fmt.Sprint(int(u.SrcPort)), fmt.Sprint(int(u.DstPort))
			forward, backward := key("udp", src, sp, dst, dp), key("udp", dst, dp, src, sp)
			if _, ok := udp[backward]; ok {
				continue // a server datagram
			}
			flow := udp[forward]
			if flow == nil {
				flow = &Flow{Key: forward, Proto: "udp"}
				udp[forward] = flow
			}
			flow.Chunks = append(flow.Chunks, append([]byte(nil), u.Payload...))
		}
	}
	assembler.FlushAll()
	var out []*Flow
	for _, m := range []map[string]*Flow{factory.flows, udp} {
		for _, flow := range m {
			out = append(out, flow)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Fields are the values both sides report, normalised: lower-case names, an HTTP Host without its port, TLS
// versions as "1.2"/"1.3", QUIC versions as "1"/"2", ALPN lists comma-joined in offer order.
type Fields struct {
	SNI, ALPN, TLSVersion, HTTPHost, QUICVersion string
}

// Get returns one field by its report name.
func (f Fields) Get(name string) string {
	switch name {
	case "sni":
		return f.SNI
	case "alpn":
		return f.ALPN
	case "tls_version":
		return f.TLSVersion
	case "http_host":
		return f.HTTPHost
	case "quic_version":
		return f.QUICVersion
	}
	panic("unknown field " + name)
}

func evidence(o contracts.Observation, field string) string {
	for _, e := range o.Evidence {
		if e.Field == field {
			return e.Value
		}
	}
	return ""
}

// Engine classifies a flow with the Go engine and no hint: TCP chunks are fed in order as gopacket delivered
// them (so a split ClientHello arrives split), UDP datagrams one by one with the flow's scope until one is
// identified. The observation's status is returned with the fields.
func Engine(flow *Flow) (Fields, contracts.Status, error) {
	cfg := contracts.DefaultConfig()
	var o contracts.Observation
	if flow.Proto == "tcp" {
		in, err := engine.New(cfg, "")
		if err != nil {
			return Fields{}, "", err
		}
		for _, chunk := range flow.Chunks {
			in.Feed(chunk)
		}
		o = in.Observation
	} else {
		d, err := engine.NewDatagram(cfg)
		if err != nil {
			return Fields{}, "", err
		}
		// As the analyzer does: the host owns a bounded cross-datagram CRYPTO store, so a ClientHello whose
		// CRYPTO frames span several Initials (quic-go splits and reorders them) is assembled across them.
		d.Assembler = quicx.NewAssembler(64, 60)
		for i, datagram := range flow.Chunks {
			now := float64(i)
			if o, err = d.InspectFlow(datagram, "", flow.Key, &now); err != nil {
				return Fields{}, "", err
			}
			if o.Status == contracts.Identified && o.Hostname != nil {
				break // the first datagram that completes the ClientHello
			}
		}
	}
	var out Fields
	host := ""
	if o.Hostname != nil {
		host = strings.ToLower(*o.Hostname)
	}
	if evidence(o, "hostname") != "" && strings.HasPrefix(sourceOf(o, "hostname"), "wire:http") {
		out.HTTPHost = host
	} else {
		out.SNI = host
	}
	out.ALPN = strings.Join(o.OfferedALPN, ",")
	out.TLSVersion = evidence(o, "tls_offered_max_version")
	out.QUICVersion = evidence(o, "quic_version")
	return out, o.Status, nil
}

func sourceOf(o contracts.Observation, field string) string {
	for _, e := range o.Evidence {
		if e.Field == field {
			return e.Source
		}
	}
	return ""
}
