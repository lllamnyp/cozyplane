package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

const maxFlowSnapshotBytes = 16 << 20

func flowLocalTransport() *http.Transport {
	return &http.Transport{
		// Proxy must remain nil: even a configured environment proxy must not
		// receive operator-only flows from the node loopback.
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
	}
}

func fetchLocalFlows(ctx context.Context, target string, out io.Writer, transport http.RoundTripper) error {
	if len(target) > 16<<10 {
		return fmt.Errorf("flow request exceeds 16 KiB")
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil ||
		u.Fragment != "" || u.RawPath != "" || (u.Path != "/flows" && u.Path != "/flows/stream") {
		return fmt.Errorf("only local flow paths are accepted")
	}
	if u.Path == "/flows" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	if transport == nil {
		local := flowLocalTransport()
		defer local.CloseIdleConnections()
		transport = local
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, flowLoopbackURL+u.RequestURI(), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("local flow endpoint returned HTTP %d", resp.StatusCode)
	}
	if u.Path == "/flows/stream" {
		_, err = io.Copy(out, resp.Body)
		return err
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, maxFlowSnapshotBytes+1))
	if err != nil {
		return err
	}
	if n > maxFlowSnapshotBytes {
		return fmt.Errorf("flow snapshot exceeds 16 MiB")
	}
	return nil
}
