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
//	netfixture udp [-sport PORT] HOST:PORT send one datagram and print the reply
//	netfixture hangup HOST:PORT            open a TCP connection and close it first
//	netfixture lastack PORT                accept one connection, close it after the peer, report the ACK
//	netfixture ping HOST                   send one ICMP echo request and print the result
//	netfixture ndp HOST                    send one neighbour solicitation from a raw socket
//	netfixture https ADDRESS CERT KEY      answer HTTPS with the request path and log each request
//	netfixture get URL                     fetch URL without a proxy and print the status and body
//	netfixture dns ADDRESS LOG NAME=IP...  answer DNS for the named hosts and log each question
//	netfixture dig [-tcp] SERVER NAME      ask one resolver one question and print the answer
//
// get ignores proxy variables. A request goes through the proxy only when
// the capture redirects it. dns appends one line per question to LOG, so a
// scenario can prove that a refused name did not reach the resolver.
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
	"sync"
	"syscall"
	"time"

	mdns "github.com/miekg/dns"
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
	// dnsArgs is the smallest argument count of dns ADDRESS LOG NAME=IP.
	dnsArgs = 4
	// digArgs is the argument count of dig SERVER NAME.
	digArgs = 3
	// answerTTL is the lifetime on every answer the resolver sends.
	answerTTL = 30
	// digTimeout bounds one question.
	digTimeout = 10 * time.Second
	// logMode is the mode the query log is created with.
	logMode = 0o644
	// udpAnswerSize is how large a datagram the resolver reads.
	udpAnswerSize = 4096
	// digUDP and digTCP are the networks dig asks over, as mdns.Client
	// names them.
	digUDP = "udp"
	digTCP = "tcp"
	// lingerTime bounds the close in lastack. An ACK that arrives takes
	// one round trip on the lab network.
	lingerTime = 3 * time.Second
)

var errUsage = errors.New("usage: netfixture serve SPEC... | capture PORT | dial ADDRESS | " +
	"udp [-sport PORT] ADDRESS | hangup ADDRESS | lastack PORT | ping HOST | ndp HOST | " +
	"https ADDRESS CERT KEY | get URL | dns ADDRESS LOG NAME=IP... | dig [-tcp] SERVER NAME")

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
	case "dns", "dig":
		return dnsMode(args, out)
	default:
		return probe(args[0], args[1:], out)
	}
}

// probe runs a probe that prints one line and exits 0.
func probe(command string, args []string, out io.Writer) error {
	if command == "udp" {
		return udp(args, out)
	}
	target := args[0]
	switch command {
	case "dial":
		fmt.Fprintln(out, dial(target))
	case "hangup":
		fmt.Fprintln(out, hangup(target))
	case "lastack":
		fmt.Fprintln(out, lastAck(target))
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

// dnsMode runs the resolver or the one-question client.
func dnsMode(args []string, out io.Writer) error {
	if args[0] == "dig" {
		return dig(args[1:], out)
	}
	if len(args) < dnsArgs {
		return errUsage
	}
	return resolve(args[1], args[2], args[3:])
}

// resolve answers DNS on address over UDP and TCP. A listed name answers
// its address and every other name answers NXDOMAIN, which is what a
// cluster resolver does for a name it does not serve.
//
// Every question is appended to logPath, one line each. A scenario reads
// that file to prove a refused name did not reach the resolver.
func resolve(address, logPath string, hosts []string) error {
	answers := map[string]string{}
	for _, entry := range hosts {
		name, addr, ok := strings.Cut(entry, "=")
		if !ok {
			return errUsage
		}
		answers[mdns.CanonicalName(name)] = addr
	}
	//nolint:gosec // G302,G304: a fixture log in the scenario's own work directory
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, logMode)
	if err != nil {
		return fmt.Errorf("open %s: %w", logPath, err)
	}
	defer func() { _ = logFile.Close() }()
	handler := &resolver{answers: answers, log: logFile}
	packet, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", address)
	if err != nil {
		return fmt.Errorf("listen on udp %s: %w", address, err)
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", address)
	if err != nil {
		return fmt.Errorf("listen on tcp %s: %w", address, err)
	}
	udp := &mdns.Server{PacketConn: packet, Handler: handler, UDPSize: udpAnswerSize}
	go func() { _ = udp.ActivateAndServe() }()
	tcp := &mdns.Server{Listener: listener, Handler: handler}
	return tcp.ActivateAndServe() //nolint:wrapcheck // the command prints it as it is
}

// resolver answers the names it was given and logs every question.
type resolver struct {
	answers map[string]string
	mu      sync.Mutex
	log     io.Writer
}

func (r *resolver) ServeDNS(w mdns.ResponseWriter, query *mdns.Msg) {
	reply := new(mdns.Msg)
	reply.SetReply(query)
	for _, question := range query.Question {
		r.record(question)
		addr, known := r.answers[mdns.CanonicalName(question.Name)]
		if !known {
			reply.SetRcode(query, mdns.RcodeNameError)
			continue
		}
		if question.Qtype != mdns.TypeA {
			continue
		}
		reply.Answer = append(reply.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: question.Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: answerTTL},
			A:   net.ParseIP(addr),
		})
	}
	_ = w.WriteMsg(reply)
}

// record appends one line per question, so a scenario reads what reached
// this resolver.
func (r *resolver) record(question mdns.Question) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fmt.Fprintf(r.log, "query %s %s\n", mdns.TypeToString[question.Qtype], mdns.CanonicalName(question.Name))
	if flusher, ok := r.log.(interface{ Sync() error }); ok {
		_ = flusher.Sync()
	}
}

// dig asks one resolver one question and prints the response code and
// every address in the answer. It names the resolver outright, so a
// scenario drives a query at an address the redirect has to catch.
func dig(args []string, out io.Writer) error {
	network := digUDP
	if len(args) > 0 && args[0] == "-tcp" {
		network, args = digTCP, args[1:]
	}
	if len(args) != digArgs-1 {
		return errUsage
	}
	query := new(mdns.Msg)
	query.SetQuestion(mdns.Fqdn(args[1]), mdns.TypeA)
	client := &mdns.Client{Net: network, Timeout: digTimeout}
	reply, _, err := client.Exchange(query, args[0])
	if err != nil {
		return err //nolint:wrapcheck // the command prints it as it is
	}
	addresses := make([]string, 0, len(reply.Answer))
	for _, record := range reply.Answer {
		if a, ok := record.(*mdns.A); ok {
			addresses = append(addresses, a.A.String())
		}
	}
	fmt.Fprintf(out, "%s %s", mdns.RcodeToString[reply.Rcode], strings.Join(addresses, ","))
	return nil
}

// dial connects over TCP and prints the first line the peer sends. A SYN
// the rules drop gets no answer, so the connection times out.
func dial(address string) string {
	conn, err := connect(address)
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

// connect opens a TCP connection. It retries a refused connection, which is
// a peer that has not started listening yet.
func connect(address string) (net.Conn, error) {
	deadline := time.Now().Add(startTimeout)
	for {
		//nolint:noctx,gosec // the timeout bounds it, and G704: the address is this fixture's argument
		conn, err := net.DialTimeout("tcp", address, probeTimeout)
		if errors.Is(err, syscall.ECONNREFUSED) && time.Now().Before(deadline) {
			time.Sleep(retryEvery)
			continue
		}
		return conn, err //nolint:wrapcheck // the caller prints it as it is
	}
}

// hangup opens a TCP connection and closes it before the peer does, so
// this end's socket finishes the close after the process has let it go.
func hangup(address string) string {
	conn, err := connect(address)
	if err != nil {
		return "tcp " + outcome(err)
	}
	if err = conn.Close(); err != nil {
		return "hangup " + outcome(err)
	}
	return "hangup closed"
}

// lastAck accepts one connection, waits for the peer to close it, and then
// closes its own end. SO_LINGER makes the close block while the socket is
// in LAST_ACK (linux net/core/stream.c, sk_stream_wait_close), so a close
// that takes the whole linger time means the peer's ACK never arrived.
func lastAck(port string) string {
	listener, err := net.Listen("tcp", ":"+port) //nolint:noctx // one connection, bounded by the deadlines below
	if err != nil {
		return "lastack " + outcome(err)
	}
	defer func() { _ = listener.Close() }()
	accepted, err := listener.Accept()
	if err != nil {
		return "lastack " + outcome(err)
	}
	conn, ok := accepted.(*net.TCPConn)
	if !ok {
		return "lastack not a TCP connection"
	}
	_ = conn.SetReadDeadline(time.Now().Add(probeTimeout))
	if _, err = io.Copy(io.Discard, conn); err != nil {
		return "lastack read " + outcome(err)
	}
	_ = conn.SetLinger(int(lingerTime / time.Second))
	start := time.Now()
	_ = conn.Close()
	if time.Since(start) >= lingerTime {
		return "lastack TIMEOUT"
	}
	return "lastack ACKED"
}

// udp parses [-sport PORT] ADDRESS and sends one datagram.
func udp(args []string, out io.Writer) error {
	source := 0
	if len(args) == 3 && args[0] == "-sport" {
		port, err := strconv.Atoi(args[1])
		if err != nil {
			return errUsage
		}
		source, args = port, args[2:]
	}
	if len(args) != 1 {
		return errUsage
	}
	fmt.Fprintln(out, datagram(args[0], source))
	return nil
}

// datagram sends one UDP datagram from the source port, or from a port the
// kernel picks when it is 0, and prints the reply. A DROP in OUTPUT fails
// the send itself.
func datagram(address string, source int) string {
	dialer := net.Dialer{Timeout: probeTimeout, LocalAddr: &net.UDPAddr{Port: source}}
	conn, err := dialer.Dial("udp", address)
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
