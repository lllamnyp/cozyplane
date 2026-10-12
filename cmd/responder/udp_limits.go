package main

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/miekg/dns"
)

// installDNSUDPAdmission is used only for the real UDPConn listeners. The raw
// reader admits complete, acceptable messages before the library spawns a
// worker. Every returned packet then reaches the handler or invalid callback,
// so malformed/ignored input cannot leave an admission slot behind.
func installDNSUDPAdmission(server *dns.Server, slots chan struct{}) {
	accept := dns.DefaultMsgAcceptFunc
	server.MsgAcceptFunc = accept
	server.DecorateReader = func(reader dns.Reader) dns.Reader {
		return dnsUDPReader{Reader: reader, slots: slots, accept: accept}
	}
	handler := server.Handler
	server.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		defer func() { <-slots }()
		handler.ServeDNS(w, req)
	})
	server.MsgInvalidFunc = func([]byte, error) { <-slots }
}

type dnsUDPReader struct {
	dns.Reader
	slots  chan struct{}
	accept dns.MsgAcceptFunc
}

func (r dnsUDPReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	for {
		packet, session, err := r.Reader.ReadUDP(conn, timeout)
		if err != nil {
			return nil, nil, err
		}
		if len(packet) < 12 {
			continue
		}
		select {
		case r.slots <- struct{}{}:
		default:
			continue
		}
		header := dns.Header{Id: binary.BigEndian.Uint16(packet[0:2]), Bits: binary.BigEndian.Uint16(packet[2:4]), Qdcount: binary.BigEndian.Uint16(packet[4:6]), Ancount: binary.BigEndian.Uint16(packet[6:8]), Nscount: binary.BigEndian.Uint16(packet[8:10]), Arcount: binary.BigEndian.Uint16(packet[10:12])}
		if r.accept(header) != dns.MsgAccept {
			<-r.slots
			continue
		}
		var query dns.Msg
		if err := query.Unpack(packet); err != nil || len(query.Question) != int(header.Qdcount) || len(query.Answer) != int(header.Ancount) || len(query.Ns) != int(header.Nscount) || len(query.Extra) != int(header.Arcount) {
			<-r.slots
			continue
		}
		return packet, session, nil
	}
}
