package oracle

import (
	"net"
	"sync"
	"time"
)

// TCPRelay accepts connections on 127.0.0.1 and forwards each to target, recording both directions as one flow.
type TCPRelay struct {
	ln     net.Listener
	target string
	rec    *Recorder
	shape  Shape
	wg     sync.WaitGroup
}

// StartTCPRelay listens on an ephemeral loopback port.
func StartTCPRelay(rec *Recorder, target string, shape Shape) (*TCPRelay, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t := &TCPRelay{ln: ln, target: target, rec: rec, shape: shape}
	t.wg.Add(1)
	go t.serve()
	return t, nil
}

// Addr is the address clients connect to.
func (t *TCPRelay) Addr() *net.TCPAddr { return t.ln.Addr().(*net.TCPAddr) }

// Close stops accepting and waits for every relayed connection to finish.
func (t *TCPRelay) Close() {
	t.ln.Close()
	t.wg.Wait()
}

func (t *TCPRelay) serve() {
	defer t.wg.Done()
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			t.relay(c.(*net.TCPConn))
		}()
	}
}

func (t *TCPRelay) relay(client *net.TCPConn) {
	defer client.Close()
	conn, err := net.DialTimeout("tcp4", t.target, 5*time.Second)
	if err != nil {
		return
	}
	server := conn.(*net.TCPConn)
	defer server.Close()
	flow := t.rec.NewTCPFlow(client.RemoteAddr().(*net.TCPAddr), client.LocalAddr().(*net.TCPAddr), t.shape)
	var copies sync.WaitGroup
	pipe := func(dst, src *net.TCPConn, fromClient bool) {
		defer copies.Done()
		buf := make([]byte, 64<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				flow.Data(fromClient, buf[:n]) // recorded before it is forwarded, so the file keeps causal order
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = dst.CloseWrite()
	}
	copies.Add(2)
	go pipe(server, client, true)
	go pipe(client, server, false)
	copies.Wait()
	flow.Close()
}

// UDPRelay forwards datagrams between one client and target, recording each.
type UDPRelay struct {
	conn   *net.UDPConn
	target *net.UDPAddr
	rec    *Recorder
	wg     sync.WaitGroup
	mu     sync.Mutex
	up     map[string]*net.UDPConn // client address -> its connection to target
}

// StartUDPRelay listens on an ephemeral loopback port.
func StartUDPRelay(rec *Recorder, target string) (*UDPRelay, error) {
	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	u := &UDPRelay{conn: conn, target: addr, rec: rec, up: map[string]*net.UDPConn{}}
	u.wg.Add(1)
	go u.serve()
	return u, nil
}

// Addr is the address clients send to.
func (u *UDPRelay) Addr() *net.UDPAddr { return u.conn.LocalAddr().(*net.UDPAddr) }

// Close stops the relay.
func (u *UDPRelay) Close() {
	u.conn.Close()
	u.mu.Lock()
	for _, c := range u.up {
		c.Close()
	}
	u.mu.Unlock()
	u.wg.Wait()
}

func (u *UDPRelay) serve() {
	defer u.wg.Done()
	buf := make([]byte, 64<<10)
	for {
		n, client, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := append([]byte(nil), buf[:n]...)
		u.rec.UDP(client, u.Addr(), data)
		up, err := u.upstream(client)
		if err != nil {
			return
		}
		_, _ = up.Write(data)
	}
}

// upstream is the client's own socket to the target; its replies are recorded as sent by the relay address.
func (u *UDPRelay) upstream(client *net.UDPAddr) (*net.UDPConn, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if c, ok := u.up[client.String()]; ok {
		return c, nil
	}
	c, err := net.DialUDP("udp4", nil, u.target)
	if err != nil {
		return nil, err
	}
	u.up[client.String()] = c
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		buf := make([]byte, 64<<10)
		for {
			n, err := c.Read(buf)
			if err != nil { // closed by Close, or the target went away
				return
			}
			data := append([]byte(nil), buf[:n]...)
			u.rec.UDP(u.Addr(), client, data)
			if _, err := u.conn.WriteToUDP(data, client); err != nil {
				return
			}
		}
	}()
	return c, nil
}
