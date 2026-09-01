package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Pinger reports whether an IPv4 or IPv6 address is reachable over ICMP echo.
type Pinger interface {
	Ping(ctx context.Context, ip string) error
}

// NopPinger always succeeds; used when CAP_NET_RAW is unavailable.
type NopPinger struct{}

func (NopPinger) Ping(_ context.Context, _ string) error { return nil }

// ICMPPinger opens a fresh raw ICMP socket per Ping call for concurrency safety.
type ICMPPinger struct {
	id int // ICMP identifier, fixed per process
}

// NewICMPPinger probes for CAP_NET_RAW and returns a Pinger, or an error
// indicating the caller should fall back to NopPinger.
func NewICMPPinger() (*ICMPPinger, error) {
	var probeErr error
	for _, candidate := range [][2]string{{"ip6:ipv6-icmp", "::"}, {"ip4:icmp", "0.0.0.0"}} {
		conn, err := icmp.ListenPacket(candidate[0], candidate[1])
		if err != nil {
			probeErr = errors.Join(probeErr, err)
			continue
		}
		if closeErr := conn.Close(); closeErr != nil {
			return nil, fmt.Errorf("close probe socket: %w", closeErr)
		}
		return &ICMPPinger{id: os.Getpid() & 0xffff}, nil
	}
	return nil, fmt.Errorf("open ICMP socket: %w", probeErr)
}

func (p *ICMPPinger) Ping(ctx context.Context, ip string) error {
	addr := &net.IPAddr{IP: net.ParseIP(ip)}
	if addr.IP == nil {
		return fmt.Errorf("invalid ip %q", ip)
	}
	network, listenAddr := "ip4:icmp", "0.0.0.0"
	echoRequest, echoReply, protocol := icmp.Type(ipv4.ICMPTypeEcho), icmp.Type(ipv4.ICMPTypeEchoReply), ipv4.ICMPTypeEchoReply.Protocol()
	if addr.IP.To4() == nil {
		network, listenAddr = "ip6:ipv6-icmp", "::"
		echoRequest, echoReply, protocol = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply.Protocol()
	}
	conn, err := icmp.ListenPacket(network, listenAddr)
	if err != nil {
		return fmt.Errorf("open icmp socket: %w", err)
	}
	defer func() { _ = conn.Close() }()

	msg := icmp.Message{
		Type: echoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   p.id,
			Seq:  1,
			Data: []byte("vk-cocoon"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal icmp echo: %w", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("icmp ping requires context deadline")
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	if _, err := conn.WriteTo(b, addr); err != nil {
		return fmt.Errorf("send icmp echo to %s: %w", ip, err)
	}

	reply := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(reply)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("read icmp reply: %w", err)
		}
		parsed, err := icmp.ParseMessage(protocol, reply[:n])
		if err != nil {
			continue
		}
		if parsed.Type != echoReply {
			continue
		}
		// Also match on peer address to avoid cross-socket reply stealing.
		echo, ok := parsed.Body.(*icmp.Echo)
		if !ok || echo.ID != p.id {
			continue
		}
		if peerAddr, ok := peer.(*net.IPAddr); ok && !peerAddr.IP.Equal(addr.IP) {
			continue
		}
		return nil
	}
}
