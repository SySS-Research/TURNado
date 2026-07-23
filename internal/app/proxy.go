package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

func dialViaProxy(proxyURL string, timeout time.Duration, target string) (net.Conn, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid --proxy URL %q: %w", proxyURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid --proxy URL %q: missing host", proxyURL)
	}

	base := &net.Dialer{Timeout: timeout}

	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := xproxy.SOCKS5("tcp", u.Host, auth, base)
		if err != nil {
			return nil, fmt.Errorf("socks5 proxy dialer: %w", err)
		}
		if cd, ok := d.(xproxy.ContextDialer); ok {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return cd.DialContext(ctx, "tcp", target)
		}
		return d.Dial("tcp", target)
	case "http", "https":
		return httpConnect(base, u, target)
	default:
		return nil, fmt.Errorf("unsupported --proxy scheme %q (use socks5, socks5h, http, or https)", u.Scheme)
	}
}

func httpConnect(base *net.Dialer, u *url.URL, target string) (net.Conn, error) {
	var (
		conn net.Conn
		err  error
	)
	if strings.ToLower(u.Scheme) == "https" {
		conn, err = tls.DialWithDialer(base, "tcp", u.Host, &tls.Config{ServerName: hostOnly(u.Host)})
	} else {
		conn, err = base.Dial("tcp", u.Host)
	}
	if err != nil {
		return nil, fmt.Errorf("connect to proxy %s: %w", u.Host, err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if u.User != nil {
		pw, _ := u.User.Password()
		req.SetBasicAuth(u.User.Username(), pw)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}

	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT to proxy: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response from proxy: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT to %s failed: %s", target, resp.Status)
	}

	if n := br.Buffered(); n > 0 {
		buffered, _ := br.Peek(n)
		return &prefixConn{Conn: conn, prefix: append([]byte(nil), buffered...)}, nil
	}
	return conn, nil
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
