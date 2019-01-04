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
	"sync"
	"time"
)

var (
	mdnsIPv4Addr = &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	mdnsIPv6Addr = &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353}

	mdnsMutex sync.Mutex

	// See man mdns-scan for examples
	//
	protocolTable []string = []string{
		"_ident._tcp",
		"_finger._tcp",
		"_workstation._tcp",
		//"_netbios-ns._udp",
		"_spotify-connect._tcp",
		"_afpovertcp._tcp",
		"_device-info._udp",
		"_snmp._udp",
		"_music._tcp",
		"_printer._tcp",
		"_http.tcp",
		"_raop._tcp",
		"_airplay._tcp",
		"_nvstream._tcp",
		"_googlecast._tcp",
		"_sleep-proxy._udp",
		"_touch-able._tcp",
		"_ssh._tcp",
		"_services._dns-sd._udp",
		//"lb.dns-sd._udp",
	}
)

// MDNSServiceEntry is returned after we query for a service
type MDNSServiceEntry struct {
	Name       string
	Host       string
	AddrV4     net.IP
	AddrV6     net.IP
	Port       int
	Info       string
	InfoFields []string

	hasTXT bool
	sent   bool
}

// complete is used to check if we have all the info we need
func (s *MDNSServiceEntry) complete() bool {
	//return (s.AddrV4 != nil || s.AddrV6 != nil) && s.Port != 0 && s.hasTXT
	return (s.AddrV4 != nil || s.AddrV6 != nil)
}

// Client provides a query interface that can be used to
// search for service providers using mDNS
type MDNSClient struct {

	// We will spaw a goroutine for each connection
	uconn4 *net.UDPConn
	uconn6 *net.UDPConn
	mconn4 *net.UDPConn
	mconn6 *net.UDPConn

	// Collect all msg from the 4 connections
	msgCh chan *dns.Msg

	inprogress map[string]*MDNSServiceEntry

	// Notification channel for the caller
	notification chan<- *MDNSServiceEntry

	closed    bool
	closeLock sync.Mutex
}

func (c *MDNSClient) Discovery() {
	for i := range protocolTable {
		c.Query("local", protocolTable[i], false)
		time.Sleep(25 * time.Millisecond)
	}
}

func MDNSService() (c *MDNSClient, err error) {

	client := &MDNSClient{}
	client.inprogress = make(map[string]*MDNSServiceEntry)

	// FIXME: Set the multicast interface
	// if params.Interface != nil {
	// if err := MDNSClient.setInterface(params.Interface); err != nil {
	// return nil, err
	// }
	// }

	// channel to receive responses
	client.msgCh = make(chan *dns.Msg, 32)

	client.uconn4, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Errorf("MDNS: Failed to bind to udp4 port: %v", err)
	}
	client.uconn6, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	if err != nil {
		log.Errorf("MDNS: Failed to bind to udp6 port: %v", err)
	}

	if client.uconn4 == nil && client.uconn6 == nil {
		return nil, fmt.Errorf("MDNS failed to bind to any unicast udp port")
	}

	client.mconn4, err = net.ListenMulticastUDP("udp4", nil, mdnsIPv4Addr)
	if err != nil {
		log.Errorf("MDNS: Failed to bind to udp4 port: %v", err)
	}
	client.mconn6, err = net.ListenMulticastUDP("udp6", nil, mdnsIPv6Addr)
	if err != nil {
		log.Errorf("MDNS: Failed to bind to udp6 port: %v", err)
	}

	if client.mconn4 == nil && client.mconn6 == nil {
		return nil, fmt.Errorf("MDNS failed to bind to any multicast udp port")
	}

	return client, nil
}

func (c *MDNSClient) AddNotificationChannel(notification chan<- *MDNSServiceEntry) {
	c.notification = notification
}

func (c *MDNSClient) GetName(ip string) (name string) {
	mdnsMutex.Lock()
	defer mdnsMutex.Unlock()

	for _, value := range c.inprogress {
		if value.complete() && value.AddrV4.String() == ip {
			return value.Name
		}
	}
	return ""
}

func (c *MDNSClient) GetTable() (table []MDNSServiceEntry) {
	mdnsMutex.Lock()
	defer mdnsMutex.Unlock()

	for _, value := range c.inprogress {
		if value.complete() {
			table = append(table, *value)
		}
	}
	return table
}

//func (c *MDNSClient) PrintTable() {
func PrintTable(inprogress map[string]*MDNSServiceEntry) {
	// table := c.GetTable()

	for k, e := range inprogress {
		var ip net.IP
		if e.AddrV4.Equal(net.IPv4zero) {
			ip = e.AddrV6
		} else {
			ip = e.AddrV4
		}
		log.Infof("MDNS entry %16s %16s %16s %14s %4v %20v %v", k, e.Name, e.Host, ip, e.Port, e.Info, e.InfoFields)
		//log.Infof("MDNS entry %16s %16s %16s %14s %4v", k, e.Name, e.Host, ip, e.Port)
	}
}

// Close is used to cleanup the MDNSClient
func (c *MDNSClient) Close() error {
	c.closeLock.Lock()
	defer c.closeLock.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	log.Printf("[INFO] mdns: Closing MDNSClient %v", *c)
	// close(c.closedCh)

	return nil
}

// setInterface is used to set the query interface, uses sytem
// default if not provided
func (c *MDNSClient) setInterface(iface *net.Interface) error {
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

func (c *MDNSClient) ListenAndServe() error {
	log.Info("naming start ListenAndServe")

	go c.recv(c.uconn4, c.msgCh)
	go c.recv(c.uconn6, c.msgCh)
	go c.recv(c.mconn4, c.msgCh)
	go c.recv(c.mconn6, c.msgCh)

	// Listen until we reach the timeout
	// finish := time.After(c.params.Timeout)
	for {
		select {
		case resp := <-c.msgCh:
			// log.Debug("MDNS channel resp = ", resp)
			var inp *MDNSServiceEntry
			for _, answer := range append(resp.Answer, resp.Extra...) {
				//log.Info("naming in mdnsclient anwer ", answer)
				switch rr := answer.(type) {
				// Only need the A record
				/***
								case *dns.PTR:
									// Create new entry for this
									log.Infof("naming dns.PTR %s - Name %s", rr.Ptr, rr.Hdr.Name)
									inp = ensureName(c.inprogress, rr.Ptr)

								case *dns.SRV:
									// Check for a target mismatch
									// rr.Target is the host name in general but Hdr.Name contains the FQN

									if rr.Target != rr.Hdr.Name {
										alias(c.inprogress, rr.Hdr.Name, rr.Target)
									}

									// Get the port
									inp = ensureName(c.inprogress, rr.Hdr.Name)
									inp.Host = rr.Target
									inp.Port = int(rr.Port)

								case *dns.TXT:
									// Pull out the txt
									inp = ensureName(c.inprogress, rr.Hdr.Name)
									inp.Info = strings.Join(rr.Txt, "|")
									inp.InfoFields = rr.Txt
									inp.hasTXT = true

								case *dns.AAAA:
									// Pull out the IP
									inp = ensureName(c.inprogress, rr.Hdr.Name)
									inp.AddrV6 = rr.AAAA
				***/
				case *dns.A:
					// Pull out the IP
					// log.Infof("MDNS add %s IP %s", rr.Hdr.Name, rr.A)
					inp = ensureName(c.inprogress, rr.Hdr.Name)
					inp.AddrV4 = rr.A

				}
			}

			if inp == nil {
				continue
			}

			inp.sent = true
			// iphone send  "Denis's\ iphone"
			inp.Name = strings.Replace(inp.Name, "\\", "", -1)

			// Notify if channel given
			if c.notification != nil {
				c.notification <- inp
			}

			// case <-finish:
			// return nil
		}
	}
}

// query is used to perform a lookup and stream results
func (c *MDNSClient) Query(domain string, service string, unicast bool) error {
	// Create the service name
	serviceAddr := fmt.Sprintf("%s.%s.", strings.Trim(service, "."), strings.Trim(domain, "."))

	// Send the query
	m := new(dns.Msg)
	m.SetQuestion(serviceAddr, dns.TypePTR)
	// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	// Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	if unicast {
		m.Question[0].Qclass |= 1 << 15
	}
	m.RecursionDesired = false

	log.Info("naming send mdns query for ", serviceAddr)
	if err := c.sendQuery(m); err != nil {
		return err
	}

	return nil
}

// sendQuery is used to multicast a query out
func (c *MDNSClient) sendQuery(q *dns.Msg) error {

	buf, err := q.Pack()
	if err != nil {
		return err
	}

	if c.uconn4 != nil {
		c.uconn4.WriteToUDP(buf, mdnsIPv4Addr)
	}
	if c.uconn6 != nil {
		c.uconn6.WriteToUDP(buf, mdnsIPv6Addr)
	}
	return nil
}

// recv is used to receive until we get a shutdown
func (c *MDNSClient) recv(l *net.UDPConn, msgCh chan *dns.Msg) {
	if l == nil {
		return
	}
	buf := make([]byte, 65536)

	for !c.closed {
		n, err := l.Read(buf)
		if err != nil {
			log.Printf("MDNS mdns: Failed to read packet: %v", err)
			continue
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			log.Printf("MDNS mdns: Failed to unpack packet: %v", err)
			continue
		}
		log.Debug("naming recv mdns packet ")
		msgCh <- msg
	}
}

// ensureName is used to ensure the named node is in progress
func ensureName(inprogress map[string]*MDNSServiceEntry, name string) *MDNSServiceEntry {
	mdnsMutex.Lock()
	defer mdnsMutex.Unlock()

	if inp, ok := inprogress[name]; ok {
		return inp
	}
	inp := &MDNSServiceEntry{
		Name: strings.Split(name, ".")[0],
	}

	inprogress[name] = inp
	PrintTable(inprogress)
	return inp
}

// alias is used to setup an alias between two entries
func alias(inprogress map[string]*MDNSServiceEntry, src, dst string) {
	srcEntry := ensureName(inprogress, src)

	mdnsMutex.Lock()
	defer mdnsMutex.Unlock()

	log.Debugf("MDNS Alias src %s dst %s", src, dst)

	inprogress[dst] = srcEntry
}
