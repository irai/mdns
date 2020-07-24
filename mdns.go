package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	// LogAll controls the level of logging in module. By default the module is silent.
	// Set LogAll to true to see module logs.
	LogAll bool

	mdnsIPv4Addr = &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	mdnsIPv6Addr = &net.UDPAddr{IP: net.ParseIP("ff02::fb"), Port: 5353}

	// ErrInvalidChannel nil channel passed for notification
	ErrInvalidChannel = errors.New("invalid channel")
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

	// Table to hold mDNS entries
	table      *mdnsTable
	sync.Mutex // anonymous

	// Notification channel for new or updated entries
	notification chan<- Entry
}

// NewHandler creates an IPv4 Multicast DNS handler for a given interface
// It will also attempt to create an IPv6 port if available.
//
func NewHandler(nic string) (c *Handler, err error) {

	client := &Handler{}
	client.table = &mdnsTable{table: make(map[string]*Entry)}

	// channel to receive responses
	client.msgCh = make(chan *dns.Msg, 32)

	// Unicast
	if client.uconn4, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0}); err != nil {
		return nil, fmt.Errorf("failed to bind to udp4 port: %w", err)
	}

	if client.uconn6, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: 0}); err != nil {
		log.Debugf("MDNS: Failed to bind to udp6 port: %v", err)
	}

	// Multicast
	if client.mconn4, err = net.ListenMulticastUDP("udp4", nil, mdnsIPv4Addr); err != nil {
		return nil, fmt.Errorf("failed to bind to multicast udp4 port: %w", err)
	}
	if client.mconn6, err = net.ListenMulticastUDP("udp6", nil, mdnsIPv6Addr); err != nil {
		log.Debugf("MDNS: Failed to bind to udp6 port: %v", err)
	}

	return client, nil
}

// AddNotificationChannel set the channel for notifications
func (c *Handler) AddNotificationChannel(notification chan<- Entry) error {
	if notification == nil {
		return ErrInvalidChannel
	}
	c.notification = notification
	go func() {
		q := cap(notification)
		i := 0
		c.Lock()
		defer c.Unlock()
		for _, entry := range c.table.table {
			if i >= q { // prevent locking by notifying up to channel size only
				return
			}
			i++
			c.notification <- *entry
		}
	}()
	return nil
}

// PrintTable log the printer table
func (c *Handler) PrintTable() {
	c.table.printTable()
}

func (c *Handler) closeAll() {
	if c.uconn4 != nil {
		c.uconn4.Close()
	}
	if c.mconn4 != nil {
		c.mconn4.Close()
	}
	if c.uconn6 != nil {
		c.uconn6.Close()
	}
	if c.mconn6 != nil {
		c.mconn6.Close()
	}
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

// recvLoop is used to receive until we get a shutdown
func (c *Handler) recvLoop(ctx context.Context, l *net.UDPConn, msgCh chan *dns.Msg) error {

	buf := make([]byte, 65536)

	for {
		n, err := l.Read(buf)

		if err != nil {
			if nerr, ok := err.(net.Error); ok && !nerr.Temporary() {
				if ctx.Err() != context.Canceled {
					return err
				}
				return nil
			}

			if LogAll {
				log.Debugf("mdns: temporary read failure: %v", err)
			}
			continue
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			if LogAll {
				log.Debugf("mdns: skipping invalid packet: %v", err)
			}
			continue
		}

		msgCh <- msg

	}
}

// ListenAndServe is the main loop to listen for MDNS packets.
func (c *Handler) ListenAndServe(ctx context.Context) error {
	var wg sync.WaitGroup
	forceEnd := make(chan error)

	if c.uconn4 != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.recvLoop(ctx, c.uconn4, c.msgCh); err != nil {
				forceEnd <- fmt.Errorf("mdns ipv4 listen failed: %w", err)
			}
		}()
	}
	if c.mconn4 != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.recvLoop(ctx, c.mconn4, c.msgCh); err != nil {
				forceEnd <- fmt.Errorf("mdns multicast ipv4 listen failed: %w", err)
			}

		}()
	}
	if c.uconn6 != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.recvLoop(ctx, c.uconn6, c.msgCh); err != nil {
				forceEnd <- fmt.Errorf("mdns ipv6 listen failed: %w", err)
			}

		}()
	}
	if c.mconn6 != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.recvLoop(ctx, c.mconn6, c.msgCh); err != nil {
				forceEnd <- fmt.Errorf("mdns multicast ipv6 listen failed: %w", err)
			}

		}()
	}

	// Listen until the ctx is cancelled
	for {
		select {

		case <-ctx.Done():
			c.closeAll()
			wg.Wait()
			return nil

		case err := <-forceEnd:
			c.closeAll()
			wg.Wait()
			return err

		case resp := <-c.msgCh:

			// only interested in mdns responses
			if !resp.Response {
				if LogAll && log.IsLevelEnabled(log.TraceLevel) {
					log.Debugf("mdns skipping mdns query %v", resp.Question)
				}
				continue
			}

			entry := &Entry{services: make(map[string]*srv)}
			discoverResponse := false

			if LogAll && log.IsLevelEnabled(log.DebugLevel) {
				log.Debugf("mdns processing answer id=%v opcode=%v rcode=%v question=%v ", resp.Id, dns.OpcodeToString[resp.Opcode], dns.RcodeToString[resp.Rcode], resp.Question)
			}

			for _, answer := range append(resp.Answer, resp.Extra...) {

				switch rr := answer.(type) {

				case *dns.A:
					// A record - IPv4
					// dns.A name=sonosB8E9372ACF56.local. IP=192.168.1.106
					if LogAll {
						log.Debugf("mdns dns.A name=%s IP=%s", rr.Hdr.Name, rr.A)
					}
					entry.IPv4 = rr.A

				case *dns.AAAA:
					// AAAA record - IPv6
					if LogAll {
						log.Debugf("mdns dns.AAAA name=%s ip=%s", rr.Hdr.Name, rr.AAAA)
					}
					entry.IPv6 = rr.AAAA

				case *dns.PTR:
					// Rever DNS lookup (opposite of A record)
					if LogAll {
						log.Tracef("mdns dns.PTR name=%s ptr=%s", rr.Hdr.Name, rr.Ptr)
					}

					// if PTR is a service discover then this is a pointer to a
					// service this client provides.
					//
					// An example from a Sonos Play3 speaker
					//     dns.PTR name=_services._dns-sd._udp.local. ptr=_spotify-connect._tcp.local."
					if rr.Hdr.Name == "_services._dns-sd._udp.local." {
						if enableService(rr.Ptr) > 0 {
							if LogAll {
								log.Debugf("mdns send query ptr=%s", rr.Ptr)
							}
							c.SendQuery(rr.Ptr)
						}
						discoverResponse = true
						break
					}

					// Example spotify ptr answer
					//   	dns.PTR name=_spotify-connect._tcp.local. ptr=sonosB8E9372ACF56._spotify-connect._tcp.local.
					if LogAll {
						log.Debugf("mdns skipping dns.PTR name=%s ptr=%s", rr.Hdr.Name, rr.Ptr)
					}

				case *dns.SRV:
					// Service record :
					//    _service._proto.name. TTL class SRV priority weight port target
					// example:
					//	  dns.SRV name=sonosB8E9372ACF56._spotify-connect._tcp.local. target=sonosB8E9372ACF56.local. port=1400

					if LogAll {
						log.Debugf("mdns dns.SRV name=%s target=%s port=%v", rr.Hdr.Name, rr.Target, rr.Port)
					}

					// rr.Target is the host name and Hdr.Name contains the FQN
					entry.addSRV(rr.Hdr.Name, rr.Target, rr.Port)

				case *dns.TXT:
					if LogAll {
						log.Debugf("mdns dns.TXT name=%s txt=%s", rr.Hdr.Name, rr.Txt)
					}

					// Pull out the txt
					//   dns.TXT name=sonosB8E9372ACF56._spotify-connect._tcp.local. txt=[VERSION=1.0 CPath=/spotifyzc]"
					entry.addTXT(rr.Hdr.Name, rr.Txt)

				case *dns.NSEC:
					if LogAll {
						log.Debugf("mdns dns.NSEC name=%s nextdomain=%s", rr.Hdr.Name, rr.NextDomain)
					}

				default:
					if LogAll {
						log.Debugf("mdns unknown answer=%+s", answer)
					}
				}

			}

			// we need a hostname and IPv4 to continue
			if entry.IPv4 == nil || entry.IPv4.Equal(net.IPv4zero) {
				if !discoverResponse && LogAll && log.IsLevelEnabled(log.DebugLevel) {
					log.Debugf("mdns skipping record no IP answer=%+v ns=%v extra=%v", resp.Answer, resp.Ns, resp.Extra)
				}
				continue
			}

			entry, updated := c.table.processEntry(entry)

			// Notify if channel given
			if updated && c.notification != nil {
				if LogAll {
					log.WithFields(log.Fields{"name": entry.Name, "ip": entry.IPv4, "model": entry.Model}).Info("mdns updated entry")
				}
				go func() {
					c.notification <- *entry
				}()
			}

		}
	}
}
