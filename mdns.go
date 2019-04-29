package mdns

// Cloned from: https://github.com/hashicorp/mdns
// The MIT License (MIT)
// Copyright (c) 2014 Armon Dadgar

import (
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"strings"
	"time"
)

var (
	mdnsIPv4Addr = &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	mdnsIPv6Addr = &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353}

	// See man mdns-scan for examples
	//
	protocolTable = []string{
		"_ident._tcp.",
		"_finger._tcp.",
		"_workstation._tcp.",
		//"_netbios-ns._udp.",
		"_spotify-connect._tcp.",
		"_afpovertcp._tcp.",
		"_device-info._udp.",
		"_snmp._udp.",
		"_music._tcp.",
		"_printer._tcp.",
		"_http.tcp.",
		"_raop._tcp.",
		"_airplay._tcp.",
		"_nvstream._tcp.",
		"_googlecast._tcp.",
		"_sleep-proxy._udp.",
		"_touch-able._tcp.",
		"_ssh._tcp.",
		"_services._dns-sd._udp.",
		//"lb.dns-sd._udp.",
	}
)

// Handler provides a query interface that can be used to
// search for service providers using mDNS
type Handler struct {

	// We will spaw a goroutine for each connection
	uconn4 *net.UDPConn
	uconn6 *net.UDPConn
	mconn4 *net.UDPConn
	mconn6 *net.UDPConn

	// Collect all msg from the 4 connections
	msgCh chan *dns.Msg

	// Table to hold entries - some entries may be incomplete
	table map[string]*Entry

	// Notification channel for the caller
	notification chan<- *Entry

	// workers *GoroutinePool
}

// Entry is returned after we query for a service
type Entry struct {
	Name       string
	Host       string
	AddrV4     net.IP
	AddrV6     net.IP
	Port       int
	Info       string
	InfoFields []string
	Aliases    map[string]string

	hasTXT bool
	sent   bool
}

// complete is used to check if we have all the info we need
func (s *Entry) complete() bool {
	//return (s.AddrV4 != nil || s.AddrV6 != nil) && s.Port != 0 && s.hasTXT
	return (s.AddrV4 != nil || s.AddrV6 != nil)
}

// NewHandler create a Multicast DNS handler for a given interface
//
func NewHandler(nic string) (c *Handler, err error) {

	client := &Handler{}
	client.table = make(map[string]*Entry)

	// FIXME: Set the multicast interface
	// if params.Interface != nil {
	// if err := Handler.setInterface(params.Interface); err != nil {
	// return nil, err
	// }
	// }

	// channel to receive responses
	client.msgCh = make(chan *dns.Msg, 32)

	// Unicast
	if client.uconn4, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0}); err != nil {
		log.Errorf("MDNS: Failed to bind to udp4 port: %v", err)
	}

	if client.uconn6, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0}); err != nil {
		log.Errorf("MDNS: Failed to bind to udp6 port: %v", err)
	}

	if client.uconn4 == nil && client.uconn6 == nil {
		return nil, fmt.Errorf("MDNS failed to bind to any unicast udp port")
	}

	// Multicast
	if client.mconn4, err = net.ListenMulticastUDP("udp4", nil, mdnsIPv4Addr); err != nil {
		log.Errorf("MDNS: Failed to bind to udp4 port: %v", err)
	}
	if client.mconn6, err = net.ListenMulticastUDP("udp6", nil, mdnsIPv6Addr); err != nil {
		log.Errorf("MDNS: Failed to bind to udp6 port: %v", err)
	}

	if client.mconn4 == nil && client.mconn6 == nil {
		return nil, fmt.Errorf("MDNS failed to bind to any multicast udp port")
	}

	return client, nil
}

// AddNotificationChannel set the channel for notifications
func (c *Handler) AddNotificationChannel(notification chan<- *Entry) {
	c.notification = notification
}

func (c *Handler) getName(ip string) (name string) {

	for _, value := range c.table {
		if value.complete() && value.AddrV4.String() == ip {
			return value.Name
		}
	}
	return ""
}

func (c *Handler) getTable() (table []Entry) {

	for _, value := range c.table {
		if value.complete() {
			table = append(table, *value)
		}
	}
	return table
}

// PrintTable will print entries to stdout
func (c *Handler) PrintTable() {
	table := c.table // there is race here; make it really unlikely to occur

	for k, e := range table {
		var ip net.IP
		if e.AddrV4.Equal(net.IPv4zero) {
			ip = e.AddrV6
		} else {
			ip = e.AddrV4
		}
		log.Infof("MDNS entry %16s %16s %16s %14s %4v Fields: %v Aliases: %v", k, e.Name, e.Host, ip, e.Port, e.InfoFields, e.Aliases)
	}
}

// Stop is used to cleanup the Handler
func (c *Handler) Stop() {
	GoroutinePool.Stop() // will stop all goroutines
}

func (c *Handler) closeAll() {
	c.uconn4.Close()
	c.mconn4.Close()
	c.mconn4.Close()
	c.mconn4.Close()
	c.uconn6.Close()
	c.mconn6.Close()
	c.mconn6.Close()
	c.mconn6.Close()
}

// setInterface is used to set the query interface, uses sytem
// default if not provided
func (c *Handler) setInterface(iface *net.Interface) error {
	p := ipv4.NewPacketConn(c.uconn4)
	if err := p.SetMulticastInterface(iface); err != nil {
		return err
	}
	p2 := ipv6.NewPacketConn(c.uconn6)
	if err := p2.SetMulticastInterface(iface); err != nil {
		return err
	}
	p = ipv4.NewPacketConn(c.mconn4)
	if err := p.SetMulticastInterface(iface); err != nil {
		return err
	}
	p2 = ipv6.NewPacketConn(c.mconn6)
	if err := p2.SetMulticastInterface(iface); err != nil {
		return err
	}
	return nil
}

// queryLoop is used to perform a lookup and stream results
func (c *Handler) queryLoop(queryInterval time.Duration) {
	h := GoroutinePool.Begin("mdns queryLoop")
	defer h.End()

	for {
		log.Infof("mdns sending mdns query for %x services", len(protocolTable))
		for _, service := range protocolTable {
			// query packet
			m := new(dns.Msg)
			m.SetQuestion(service, dns.TypePTR)

			// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
			// Section
			//
			// In the Question Section of a Multicast DNS query, the top bit of the qclass
			// field is used to indicate that unicast responses are preferred for this
			// particular question.  (See Section 5.4.)
			m.Question[0].Qclass |= 1 << 15
			m.RecursionDesired = false

			if err := c.sendQuery(m); err != nil {
				log.Error("mdns error sending mdns query", service, err)
			}
			time.Sleep(15 * time.Millisecond)
		}

		select {
		case <-GoroutinePool.StopChannel:
			return
		case <-time.After(queryInterval):
		}
	}
}

// sendQuery is used to multicast a query out
func (c *Handler) sendQuery(q *dns.Msg) error {

	buf, err := q.Pack()
	if err != nil {
		return err
	}

	if c.uconn4 != nil {
		if _, err = c.uconn4.WriteToUDP(buf, mdnsIPv4Addr); err != nil {
			return err
		}
	}
	if c.uconn6 != nil {
		if _, err = c.uconn6.WriteToUDP(buf, mdnsIPv6Addr); err != nil {
			return err
		}
	}
	return nil
}

// recv is used to receive until we get a shutdown
func (c *Handler) recvLoop(l *net.UDPConn, msgCh chan *dns.Msg) {
	h := GoroutinePool.Begin("mdns recvLoop")
	defer h.End()

	buf := make([]byte, 65536)

	for !h.Stopping() {
		n, err := l.Read(buf)
		if h.Stopping() {
			return
		}
		if err != nil {
			log.Printf("MDNS mdns: Failed to read packet: %v", err)
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			log.Printf("MDNS mdns: Failed to unpack packet: %v", err)
			continue
		}
		msgCh <- msg
	}
}

// ensureName is used to ensure the named node is in progress
func (c *Handler) ensureName(name string) *Entry {
	if inp, ok := c.table[name]; ok {
		return inp
	}
	inp := &Entry{
		Name:    strings.Split(name, ".")[0],
		Aliases: make(map[string]string),
	}

	c.table[name] = inp
	return inp
}

// alias is used to setup an alias between two entries
func (c *Handler) findAlias(name string) *Entry {
	for _, entry := range c.table {
		if _, ok := entry.Aliases[name]; ok {
			return entry
		}
	}
	log.Debugf("MDNS cannot find alias for name=%s", name)
	return nil
}

// ListenAndServe is the main loop to listen for MDNS packets.
func (c *Handler) ListenAndServe(queryInterval time.Duration) {
	h := GoroutinePool.Begin("mdns ListenAndServe")
	defer h.End()

	go c.recvLoop(c.uconn4, c.msgCh)
	go c.recvLoop(c.uconn6, c.msgCh)
	go c.recvLoop(c.mconn4, c.msgCh)
	go c.recvLoop(c.mconn6, c.msgCh)

	go c.queryLoop(queryInterval)

	// Listen until we reach the timeout
	// finish := time.After(c.params.Timeout)
	for {
		var entry *Entry
		select {
		case resp := <-c.msgCh:
			// log.Debug("MDNS channel resp = ", resp)
			for _, answer := range append(resp.Answer, resp.Extra...) {
				log.Debug("mdns processing answer ")
				switch rr := answer.(type) {
				case *dns.A:
					// Pull out the IP
					log.Debugf("MDNS dns.A name=%s IP=%s", rr.Hdr.Name, rr.A)
					entry = c.ensureName(rr.Hdr.Name)
					entry.AddrV4 = rr.A
				case *dns.PTR:
					// Create new entry for this
					log.Debugf("mdns dns.PTR name=%s ptr=%s", rr.Hdr.Name, rr.Ptr)
					/***
					entry = c.ensureName(rr.Ptr)
					***/

				case *dns.SRV:
					log.Debugf("mdns dns.SRV name=%s target=%s port=%v", rr.Hdr.Name, rr.Target, rr.Port)

					// rr.Target is the host name and Hdr.Name contains the FQN
					entry = c.ensureName(rr.Target)
					entry.Aliases[rr.Hdr.Name] = rr.Hdr.Name
					entry.Host = rr.Target
					entry.Port = int(rr.Port)

				case *dns.TXT:
					log.Debugf("mdns dns.TXT name=%s txt=%s", rr.Hdr.Name, rr.Txt)
					// Pull out the txt
					if entry = c.findAlias(rr.Hdr.Name); entry != nil {
						entry.Info = strings.Join(rr.Txt, "|")
						entry.InfoFields = rr.Txt
						entry.hasTXT = true
					}

				case *dns.AAAA:
					log.Debugf("mdns dns.AAAA name=%s ip=%s", rr.Hdr.Name, rr.AAAA)
					// Pull out the IP
					entry = c.ensureName(rr.Hdr.Name)
					entry.AddrV6 = rr.AAAA
				}
			}

			if entry == nil || !entry.complete() {
				continue
			}

			log.Info("mdns got new entry ", *entry)
			entry.sent = true
			// iphone send  "Bob's\ iphone"
			entry.Name = strings.Replace(entry.Name, "\\", "", -1)

			// Notify if channel given
			if c.notification != nil {
				c.notification <- entry
			}

		case <-GoroutinePool.StopChannel:
			c.closeAll()
			return
		}
	}
}
