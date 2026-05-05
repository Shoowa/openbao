package assert

import (
	"net"
	"net/http"
	"runtime"
	"time"
)

func DefaultDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}
}

// DefaultPooledTransport returns a shared http.Transport. Don't use this for
// transient transports as it can leak file descriptors. Only use this for
// transports that will be re-used for the same hosts.
func DefaultPooledTransport() *http.Transport {
	transportPool := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           DefaultDialer().DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
	}

	return transportPool
}

// DefaultTransport returns a http.Transport with idle connections and
// keep-alives disabled.
func DefaultTransport() *http.Transport {
	tp := DefaultPooledTransport()
	tp.DisableKeepAlives = true
	tp.MaxIdleConnsPerHost = -1
	return tp
}

// DefaultClient returns a http.Client with an unshared Transpot, disabled idle
// connections, and disabled keep-alives.
func DefaultClient() *http.Client {
	return &http.Client{
		Transport: DefaultTransport(),
	}
}

// DefaultPooledClient returns a http.Client with a shared Transport. Don't use
// this for transient clients, because it can leak file descriptors. Only use
// this for clients that will be re-used for the same hosts.
func DefaultPooledClient() *http.Client {
	return &http.Client{
		Transport: DefaultPooledTransport(),
	}
}
