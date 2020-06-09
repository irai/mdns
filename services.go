package mdns

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type serviceDef struct {
	service        string
	enabled        bool
	classification string
}

var serviceTableMutex sync.Mutex

// full IANA list here:
//
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
var serviceTable = []serviceDef{
	{"_ident._tcp.local.", false, ""},
	{"_finger._tcp.local.", false, ""},
	{"_workstation._tcp.local.", false, ""},
	{"_ipp._tcp.local.", false, "printer"},
	{"_printer._tcp.local.", false, "printer"},
	{"_netbios-ns._udp.local.", false, ""},
	{"_spotify-connect._tcp.local.", false, "speaker"},
	{"_sonos._tcp.local.", false, "speaker"},
	{"_afpovertcp._tcp.local.", false, ""},
	{"_device-info._udp.local.", false, ""},
	{"_snmp._udp.local.", false, ""},
	{"_music._tcp.local.", false, ""},
	{"_http.tcp.local.", false, ""},
	{"_raop._tcp.local.", false, "apple device"},          // Remote Audio Output Protocol (AirTunes) - Apple
	{"_apple-mobdev2._tcp.local.", false, "apple device"}, // Apple Mobile Device Protocol - Apple
	{"_airplay._tcp.local.", false, "apple TV"},           //Protocol for streaming of audio/video content - Apple
	{"_touch-able._tcp.local.", false, "apple device"},    //iPhone and iPod touch Remote Controllable - Apple
	{"_nvstream._tcp.local.", false, ""},
	{"_googlecast._tcp.local.", false, "googlecast"},
	{"_sleep-proxy._udp.local.", false, ""},
	{"_ssh._tcp.local.", false, ""},
	{"_lb.dns-sd._udp.local.", false, ""},
	{"_xbox._tcp.local.", false, "xbox"},
	{"_xbox._udp.local.", false, "xbox"},
	{"_psams._tcp.local.", false, "playstation"}, // play station
	{"_psams._udp.local.", false, "playstation"}, // play station
}

func enableService(service string) int {
	serviceTableMutex.Lock()
	defer serviceTableMutex.Unlock()

	for i := range serviceTable {
		if serviceTable[i].service == service {
			if serviceTable[i].enabled != true {
				serviceTable[i].enabled = true
				return 1
			}
			return 0
		}
	}

	s := serviceDef{service: service, enabled: true, classification: ""}
	serviceTable = append(serviceTable, s)
	log.Warn("mdns enabled new mdns service ", s.service)
	return 1
}

// SendQuery is used to send a multicast a query
func (c *Handler) SendQuery(service string) error {

	// query packet
	q := new(dns.Msg)
	q.SetQuestion(service, dns.TypePTR)

	// RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
	// Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the qclass
	// field is used to indicate that unicast responses are preferred for this
	// particular question.  (See Section 5.4.)
	q.Question[0].Qclass |= 1 << 15
	q.RecursionDesired = false

	buf, err := q.Pack()
	if err != nil {
		return err
	}

	if LogAll && log.IsLevelEnabled(log.DebugLevel) {
		log.Debug("mdns sending multicast query ", service)
	}
	if c.uconn4 != nil {
		if _, err = c.uconn4.WriteToUDP(buf, mdnsIPv4Addr); err != nil {
			return err
		}
	}
	/**
	if c.uconn6 != nil {
		if _, err = c.uconn6.WriteToUDP(buf, mdnsIPv6Addr); err != nil {
			return err
		}
	}
	**/
	return nil
}

// queryLoop will continuosly scan for new services
func (c *Handler) queryLoop(ctx context.Context, queryInterval time.Duration) {
	log.Debug("mdns queryLoop started")
	defer log.Debug("mdns queryLoop terminated")

	for {
		if LogAll {
			log.Debug("mdns sending mdns queries")
		}

		// Do a round of service discovery
		// The listener will pickup responses and call enableService for each
		c.SendQuery("_services._dns-sd._udp.local.")
		time.Sleep(time.Second * 3)

		serviceTableMutex.Lock()
		for i := range serviceTable {
			if serviceTable[i].enabled {
				if err := c.SendQuery(serviceTable[i].service); err != nil {
					log.Error("mdns error sending mdns query", serviceTable[i].service, err)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		serviceTableMutex.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(queryInterval):
		}
	}
}
