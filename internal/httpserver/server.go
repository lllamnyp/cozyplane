// Package httpserver shares time and connection budgets for auxiliary HTTP.
package httpserver

import (
	"net"
	"net/http"
	"time"

	"golang.org/x/net/netutil"
)

const (
	maxConnections = 128
	maxHeaderBytes = 32 << 10
)

type Server struct {
	*http.Server
}

func New(address string, handler http.Handler) *Server {
	return &Server{Server: &http.Server{Addr: address, Handler: handler, MaxHeaderBytes: maxHeaderBytes, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}}
}

func (s *Server) Serve(listener net.Listener) error {
	return s.Server.Serve(netutil.LimitListener(listener, maxConnections))
}

func (s *Server) ListenAndServe() error {
	address := s.Addr
	if address == "" {
		address = ":http"
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return s.Serve(listener)
}
