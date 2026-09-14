// Command fcae-psiphon-console runs the Psiphon tunnel-core library
// (MobileLibrary/psi — the same code path as the desktop libfcae_psiphon
// shim) as a plain desktop binary, without the FCAE GUI.
//
// It exists because "compile the psiphon library for desktops" is only
// useful if it can be driven: this is the local equivalent of upstream's
// ConsoleClient, built from FCAE's own go module.
//
// Usage:
//
//	fcae-psiphon-console -config psiphon_config.json [flags]
//
// The config file is a Psiphon config JSON object. Flags override or inject
// individual fields, so a minimal file like this is enough to try a tunnel:
//
//	{
//	  "PropagationChannelId": "FFFFFFFFFFFFFFFF",
//	  "SponsorId": "FFFFFFFFFFFFFFFF",
//	  "ClientVersion": "1"
//	}
//
// A server-entry source is REQUIRED or the controller sits forever on
// "CandidateServers: count 0" (see the warning this tool prints). Provide
// either:
//
//   - -embedded <file>: an encoded server entry list (the body of a Psiphon
//     server_list payload); passed to psi.Start as the embedded list, or
//   - RemoteServerListUrl + RemoteServerListSignaturePublicKey in the config
//     JSON, pointing at your Psiphon-provided remote server list.
//
// Example, chaining through a local Aether SOCKS listener:
//
//	fcae-psiphon-console -config psiphon_config.json \
//	    -upstream socks5://127.0.0.1:1819 -socks 1080
//
// Exit codes: 0 connected (or clean Ctrl-C), 1 usage/config error, 2 start
// failure, 3 not connected within -wait seconds.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi"
)

const (
	exitOK       = 0
	exitUsage    = 1
	exitStart    = 2
	exitNoTunnel = 3
)

func main() {
	configPath := flag.String("config", "psiphon_config.json",
		"path to the Psiphon config JSON object")
	embeddedPath := flag.String("embedded", "",
		"path to an encoded server entry list (imported before dialing)")
	dataRoot := flag.String("data-root", "psiphon-data",
		"writable directory for the tunnel-core datastore")
	region := flag.String("region", "",
		"egress region (ISO country code; empty = auto)")
	socksPort := flag.Int("socks", 0, "local SOCKS port (0 = Psiphon chooses)")
	httpPort := flag.Int("http", 0, "local HTTP CONNECT port (0 = Psiphon chooses)")
	upstream := flag.String("upstream", "",
		"upstream proxy URL, e.g. socks5://127.0.0.1:1819 (chains Psiphon behind Aether)")
	wait := flag.Duration("wait", 0,
		"fail with exit 3 if no tunnel within this long (0 = wait forever)")
	flag.Parse()

	config, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fcae-psiphon-console: reading -config: %v\n", err)
		os.Exit(exitUsage)
	}

	config, err = renderConfig(config, renderOptions{
		dataRoot: *dataRoot,
		region:   *region,
		socks:    *socksPort,
		http:     *httpPort,
		upstream: *upstream,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "fcae-psiphon-console: %v\n", err)
		os.Exit(exitUsage)
	}

	embedded := ""
	if *embeddedPath != "" {
		raw, err := os.ReadFile(*embeddedPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fcae-psiphon-console: reading -embedded: %v\n", err)
			os.Exit(exitUsage)
		}
		embedded = string(raw)
	}

	config = ensureServerEntrySource(config, embedded)

	if err := os.MkdirAll(*dataRoot, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "fcae-psiphon-console: creating -data-root: %v\n", err)
		os.Exit(exitUsage)
	}

	provider := newConsoleProvider()

	fmt.Fprintln(os.Stderr, "fcae-psiphon-console: starting Psiphon library…")
	if err := psi.Start(string(config), embedded, "", provider, false, false, false); err != nil {
		fmt.Fprintf(os.Stderr, "fcae-psiphon-console: psi.Start: %v\n", err)
		os.Exit(exitStart)
	}

	connected := make(chan struct{}, 1)
	go provider.watchNotices(connected)

	if *wait > 0 {
		select {
		case <-connected:
		case <-time.After(*wait):
			fmt.Fprintln(os.Stderr, "fcae-psiphon-console: no tunnel established in time")
			psi.Stop()
			os.Exit(exitNoTunnel)
		case <-signalCh():
			fmt.Fprintln(os.Stderr, "fcae-psiphon-console: signal — stopping")
			psi.Stop()
			os.Exit(exitOK)
		}
	}

	<-signalCh()
	fmt.Fprintln(os.Stderr, "fcae-psiphon-console: signal — stopping")
	psi.Stop()
	// Give the controller a moment to flush its datastore; psi.Stop already
	// joined the controller goroutine, so this is only for notice output.
	os.Exit(exitOK)
}

func signalCh() chan os.Signal {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	return sig
}

// consoleProvider implements psi.PsiphonProvider for a plain desktop process.
type consoleProvider struct {
	notices chan string
}

func newConsoleProvider() *consoleProvider {
	return &consoleProvider{notices: make(chan string, 512)}
}

func (p *consoleProvider) Notice(noticeJSON string) {
	fmt.Println(noticeJSON)
	select {
	case p.notices <- noticeJSON:
	default: // never block tunnel-core's notice goroutine
	}
}

// watchNotices scans notices for the lifecycle milestones worth printing
// once, and signals `connected` on the first established tunnel.
func (p *consoleProvider) watchNotices(connected chan struct{}) {
	seen := false
	for raw := range p.notices {
		var n struct {
			NoticeType string `json:"noticeType"`
			Data       struct {
				Port  int `json:"port"`
				Count int `json:"count"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(raw), &n) != nil {
			continue
		}
		switch n.NoticeType {
		case "ListeningSocksProxyPort":
			if n.Data.Port > 0 {
				fmt.Fprintf(os.Stderr,
					"fcae-psiphon-console: SOCKS proxy on 127.0.0.1:%d\n", n.Data.Port)
			}
		case "ListeningHttpProxyPort":
			if n.Data.Port > 0 {
				fmt.Fprintf(os.Stderr,
					"fcae-psiphon-console: HTTP proxy on 127.0.0.1:%d\n", n.Data.Port)
			}
		case "Tunnels":
			if n.Data.Count > 0 && !seen {
				seen = true
				fmt.Fprintln(os.Stderr, "fcae-psiphon-console: tunnel established")
				select {
				case connected <- struct{}{}:
				default:
				}
			}
		}
	}
}

// BindToDevice is a desktop no-op: the routing table already excludes the
// tunnel (there is no TUN of ours to loop into).
func (p *consoleProvider) BindToDevice(int) (string, error) { return "", nil }

func (p *consoleProvider) HasNetworkConnectivity() int { return 1 }
func (p *consoleProvider) GetNetworkID() string        { return "CONSOLE" }

// GetDNSServersAsString returns "" so tunnel-core keeps the standard library
// resolver: without a DeviceBinder, upstream allows it (unlike Android, where
// it is refused and a real resolver list is mandatory).
func (p *consoleProvider) GetDNSServersAsString() string { return "" }

func (p *consoleProvider) IPv6Synthesize(string) string { return "" }
func (p *consoleProvider) HasIPv6Route() int            { return 0 }

type renderOptions struct {
	dataRoot string
	region   string
	socks    int
	http     int
	upstream string
}

// renderConfig merges flag overrides into the config JSON object.
//
// UpstreamProxyURL deserves a note: tunnel-core's `upstreamproxy` package
// speaks the socks5://, socks4a:// and http:// URI schemes only. This is the
// hook that chains Psiphon behind Aether (dial Aether first, then point
// Psiphon at its SOCKS listener).
func renderConfig(raw []byte, opts renderOptions) ([]byte, error) {
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, fmt.Errorf("config is not a JSON object: %w", err)
	}
	if strings.TrimSpace(opts.dataRoot) != "" {
		object["DataRootDirectory"] = opts.dataRoot
	}
	if strings.TrimSpace(opts.region) != "" {
		object["EgressRegion"] = opts.region
	}
	if opts.socks > 0 {
		object["LocalSocksProxyPort"] = opts.socks
	}
	if opts.http > 0 {
		object["LocalHttpProxyPort"] = opts.http
	}
	if strings.TrimSpace(opts.upstream) != "" {
		object["UpstreamProxyURL"] = opts.upstream
	}
	out, err := json.Marshal(object)
	if err != nil {
		return nil, fmt.Errorf("re-rendering config: %w", err)
	}
	return out, nil
}

// Legacy PUBLIC remote server list + signature key from the open-source
// Psiphon 3 clients (community clients embed the same values). Fallback so
// the console can bootstrap without provisioning.
const (
	defaultServerListURL = "https://s3.amazonaws.com//psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	defaultServerListKey = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH" +
		"5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5" +
		"OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42Kcot" +
		"LFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6" +
		"/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7G" +
		"stZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1O" +
		"geF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8" +
		"u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz" +
		"31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xal" +
		"KxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
)

// ensureServerEntrySource mirrors the desktop shim: embedded list wins, then
// any remote/obfuscated list already in the config, then the legacy public
// remote server list so a fresh datastore can bootstrap.
func ensureServerEntrySource(config []byte, embedded string) []byte {
	if embedded != "" {
		return config
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(config, &probe); err != nil {
		return config
	}
	for _, key := range []string{
		"RemoteServerListUrl", "RemoteServerListURLs",
		"ObfuscatedServerListRootURL", "ObfuscatedServerListRootURLs",
		"TargetServerEntry",
	} {
		if _, ok := probe[key]; ok {
			return config
		}
	}
	probe["RemoteServerListUrl"] = json.RawMessage(`"` + defaultServerListURL + `"`)
	probe["RemoteServerListSignaturePublicKey"] = json.RawMessage(`"` + defaultServerListKey + `"`)
	out, err := json.Marshal(probe)
	if err != nil {
		return config
	}
	fmt.Fprintln(os.Stderr,
		"fcae-psiphon-console: no server-entry source configured; using the built-in legacy public remote server list")
	return out
}
