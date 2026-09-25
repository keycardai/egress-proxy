// Command netfixture is a network fixture for the netsetup and transparent
// capture scenarios. It runs on both sides of the rules and ships in no
// product image.
//
// Every probe prints one line and exits 0, so the script asserts on what the
// line says:
//
//	netfixture serve tcp:PORT|udp:PORT...  answer "upstream PORT" on each port
//	netfixture capture PORT                answer "captured ORIGINAL" for each redirected connection
//	netfixture dial HOST:PORT              print the first line a TCP peer sends
//	netfixture udp HOST:PORT               send one datagram and print the reply
//	netfixture ping HOST                   send one ICMP echo request and print the result
//	netfixture ndp HOST                    send one neighbour solicitation from a raw socket
//	netfixture https ADDRESS CERT KEY      answer HTTPS with the request path and log each request
//	netfixture get URL                     fetch URL without a proxy and print the status and body
//
// get ignores proxy variables. A request goes through the proxy only when
// the capture redirects it.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/keycardai/egress-proxy/internal/transparent"
)

const (
	// probeTimeout is how long a probe waits for an answer. A packet the
	// rules drop gets none, so this is also how long a dropped probe takes.
	probeTimeout = 5 * time.Second
	// startTimeout is how long dial retries a refused connection, which is
	// a peer that has not started listening yet.
	startTimeout = 10 * time.Second
	retryEvery   = 100 * time.Millisecond
	// minArgs is a subcommand and its first argument.
	minArgs = 2
	// replySize holds any reply serve sends. packetSize holds an ICMP echo
	// reply.
	replySize  = 64
	packetSize = 1500
	// protocolICMP is the IPv4 protocol number icmp.ParseMessage takes.
	protocolICMP = 1
	// solicitReserved is the reserved field that opens a neighbour
	// solicitation body.
	solicitReserved = 4
	// httpsArgs is the number of arguments for https ADDRESS CERT KEY.
	httpsArgs         = 4
	requestTimeout    = 30 * time.Second
	readHeaderTimeout = 10 * time.Second
)

var errUsage = errors.New("usage: netfixture serve SPEC... | capture PORT | dial ADDRESS | " +
	"udp ADDRESS | ping HOST | ndp HOST | https ADDRESS CERT KEY | get URL")

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "netfixture: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) < minArgs {
		return errUsage
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "capture":
		return capture(args[1])
	case "https":
		if len(args) != httpsArgs {
			return errUsage
		}
		return serveHTTPS(args[1], args[2], args[3])
	case "get":
		return get(args[1], out)
	default:
		return probe(args[0], args[1], out)
	}
}

// probe runs a probe that prints one line and exits 0.
func probe(command, target string, out io.Writer) error {
	switch command {
	case "dial":
		fmt.Fprintln(out, dial(target))
	case "udp":
		fmt.Fprintln(out, datagram(target))
	case "ping":
		fmt.Fprintln(out, ping(target))
	case "ndp":
		fmt.Fprintln(out, solicit(target))
	default:
		return errUsage
	}
	return nil
}

// serve answers on every port it is given, on both address families, until
// it is killed.
func serve(specs []string) error {
	errs := make(chan error, len(specs))
	for _, spec := range specs {
		network, port, ok := strings.Cut(spec, ":")
		if !ok || (network != "tcp" && network != "udp") {
			return errUsage
		}
		reply := "upstream " + port + "\n"
		if network == "tcp" {
			listener, err := net.Listen("tcp", ":"+port) //nolint:noctx // a fixture that runs until it is killed
			if err != nil {
				return err //nolint:wrapcheck // the command prints it as it is
			}
			go func() { errs <- answerStreams(listener, func(net.Conn) string { return reply }) }()
			continue
		}
		conn, err := net.ListenPacket("udp", ":"+port) //nolint:noctx // same
		if err != nil {
			return err //nolint:wrapcheck // same
		}
		go func() { errs <- answerDatagrams(conn, reply) }()
	}
	return <-errs
}

// capture answers each connection a REDIRECT sent it with the destination
// the connection was opened to. It binds the port on loopback, as the proxy
// does.
func capture(portText string) error {
	port, err := strconv.Atoi(portText)
	if err != nil {
		return errUsage
	}
	listeners, err := transparent.Listen(context.Background(), port)
	if err != nil {
		return err //nolint:wrapcheck // the command prints it as it is
	}
	errs := make(chan error, len(listeners))
	for _, listener := range listeners {
		go func() {
			errs <- answerStreams(listener, func(conn net.Conn) string {
				original, err := transparent.OriginalDestination(conn)
				if err != nil {
					return "capture " + err.Error() + "\n"
				}
				return "captured " + original.String() + "\n"
			})
		}()
	}
	return <-errs
}

func answerStreams(listener net.Listener, reply func(net.Conn) string) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err //nolint:wrapcheck // the command prints it as it is
		}
		_, _ = io.WriteString(conn, reply(conn))
		_ = conn.Close()
	}
}

func answerDatagrams(conn net.PacketConn, reply string) error {
	buf := make([]byte, 1)
	for {
		_, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return err //nolint:wrapcheck // the command prints it as it is
		}
		_, _ = conn.WriteTo([]byte(reply), peer)
	}
}

// serveHTTPS answers each request with its path, so the client output shows
// which request reached the upstream.
func serveHTTPS(address, certFile, keyFile string) error {
	server := &http.Server{
		Addr:              address,
		ReadHeaderTimeout: readHeaderTimeout,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(os.Stderr, "request %s %s host=%s\n", r.Method, r.URL.RequestURI(), r.Host)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			//nolint:gosec // G705: this fixture echoes text as text/plain
			fmt.Fprintf(w, "hello from upstream %s\n", r.URL.Path)
		}),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return server.ListenAndServeTLS(certFile, keyFile) //nolint:wrapcheck // the command prints it as it is
}

// get makes one request with Transport.Proxy nil, so HTTPS_PROXY cannot route
// it.
func get(url string, out io.Writer) error {
	client := &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{Proxy: nil},
	}
	//nolint:noctx,gosec // the client timeout bounds the request. G704: the URL is this fixture's argument
	resp, err := client.Get(url)
	if err != nil {
		return err //nolint:wrapcheck // the command prints it as it is
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err //nolint:wrapcheck // the command prints it as it is
	}
	fmt.Fprintf(out, "%d %s", resp.StatusCode, body)
	return nil
}

// dial connects over TCP and prints the first line the peer sends. A SYN
// the rules drop gets no answer, so the connection times out.
func dial(address string) string {
	deadline := time.Now().Add(startTimeout)
	for {
		//nolint:noctx,gosec // the timeout bounds it, and G704: the address is this fixture's argument
		conn, err := net.DialTimeout("tcp", address, probeTimeout)
		if errors.Is(err, syscall.ECONNREFUSED) && time.Now().Before(deadline) {
			time.Sleep(retryEvery)
			continue
		}
		if err != nil {
			return "tcp " + outcome(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(probeTimeout))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return "tcp read " + outcome(err)
		}
		return strings.TrimSpace(line)
	}
}

// datagram sends one UDP datagram and prints the reply. A DROP in OUTPUT
// fails the send itself.
func datagram(address string) string {
	//nolint:noctx,gosec // the timeout bounds it, and G704: the address is this fixture's argument
	conn, err := net.DialTimeout("udp", address, probeTimeout)
	if err != nil {
		return "udp " + outcome(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err = conn.Write([]byte("?")); err != nil {
		return "udp " + outcome(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(probeTimeout))
	buf := make([]byte, replySize)
	n, err := conn.Read(buf)
	if err != nil {
		return "udp " + outcome(err)
	}
	return "udp REPLY " + strings.TrimSpace(string(buf[:n]))
}

// ping sends one ICMP echo request from an unprivileged ICMP socket, which
// net.ipv4.ping_group_range must allow for the calling uid.
func ping(host string) string {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return "ping socket " + outcome(err)
	}
	defer func() { _ = conn.Close() }()
	request, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{Seq: 1, Data: []byte("netfixture")},
	}).Marshal(nil)
	if err != nil {
		return "ping " + err.Error()
	}
	if _, err = conn.WriteTo(request, &net.UDPAddr{IP: net.ParseIP(host)}); err != nil {
		return "ping " + outcome(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(probeTimeout))
	buf := make([]byte, packetSize)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return "ping " + outcome(err)
	}
	reply, err := icmp.ParseMessage(protocolICMP, buf[:n])
	if err != nil || reply.Type != ipv4.ICMPTypeEchoReply {
		return fmt.Sprintf("ping unexpected %v %v", reply, err)
	}
	return "ping REPLY"
}

// solicit sends one ICMPv6 neighbour solicitation from a raw socket, which
// needs CAP_NET_RAW. The message has the type the ruleset accepts for
// neighbour discovery, and a process chooses its destination and payload.
func solicit(host string) string {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return "ndp socket " + outcome(err)
	}
	defer func() { _ = conn.Close() }()
	target := net.ParseIP(host)
	// The body is the reserved bytes and the 16-byte target address, RFC 4861
	// section 4.3.
	body := append(make([]byte, solicitReserved), target.To16()...)
	message, err := (&icmp.Message{
		Type: ipv6.ICMPTypeNeighborSolicitation,
		Body: &icmp.RawBody{Data: body},
	}).Marshal(nil)
	if err != nil {
		return "ndp " + err.Error()
	}
	if _, err = conn.WriteTo(message, &net.IPAddr{IP: target}); err != nil {
		return "ndp " + outcome(err)
	}
	return "ndp SENT"
}

// outcome names an error by what a probe cares about.
func outcome(err error) string {
	var timeout interface{ Timeout() bool }
	switch {
	case errors.Is(err, syscall.EPERM):
		return "EPERM"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "REFUSED"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "TIMEOUT"
	default:
		return err.Error()
	}
}
