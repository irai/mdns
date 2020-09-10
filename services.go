package mdns

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type serviceDef struct {
	service       string
	enabled       bool
	defaultModel  string
	authoritative bool
	keyName       string
}

var serviceTableMutex sync.RWMutex

// full IANA list here:
//
// https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
//
// Bonjour
// see spec http://devimages.apple.com/opensource/BonjourPrinting.pdf
var serviceTable = []serviceDef{
	{"_http._tcp.local.", false, "Network server", false, ""},
	{"_workstation._tcp.local.", false, "", false, ""},
	{"_ipp._tcp.local.", false, "printer", true, "ty"},
	{"_ipps._tcp.local.", false, "printer", true, "ty"},
	{"_printer._tcp.local.", false, "printer", true, "ty"},
	{"_pdl-datastream._tcp.local.", false, "printer", false, "ty"},
	{"_privet._tcp.local.", false, "printer", false, "ty"},
	{"_scanner._tcp.local.", false, "scanner", false, "ty"},
	{"_uscan._tcp.local.", false, "scanner", false, "ty"},
	{"_uscans._tcp.local.", false, "scanner", false, "ty"},
	{"_smb._tcp.local.", false, "", false, "model"},
	{"_device-info._udp.local.", false, "computer", false, "model"},
	{"_device-info._tcp.local.", false, "computer", false, "model"},
	{"_netbios-ns._udp.local.", false, "", false, ""},
	{"_spotify-connect._tcp.local.", false, "Spotify speaker", false, ""},
	{"_sonos._tcp.local.", false, "Sonos speaker", true, ""},
	{"_snmp._udp.local.", false, "", false, ""},
	{"_music._tcp.local.", false, "", false, ""},
	{"_raop._tcp.local.", false, "Apple device", false, ""},           // Remote Audio Output Protocol (AirTunes) - Apple
	{"_apple-mobdev2._tcp.local.", false, "Apple device", false, ""},  // Apple Mobile Device Protocol - Apple
	{"_airplay._tcp.local.", false, "Apple TV", true, "model"},        //Protocol for streaming of audio/video content - Apple
	{"_touch-able._tcp.local.", false, "Apple device", false, "DvTy"}, //iPhone and iPod touch Remote Controllable - Apple
	{"_nvstream._tcp.local.", false, "", false, ""},
	{"_googlecast._tcp.local.", false, "Chromecast", true, "md"},
	{"_googlezone._tcp.local.", false, "Google device", false, ""},
	{"_sleep-proxy._udp.local.", false, "", false, ""},
	{"_xbox._tcp.local.", false, "xbox", true, ""},
	{"_xbox._udp.local.", false, "xbox", true, ""},
	{"_psams._tcp.local.", false, "playstation", true, ""}, // play station
	{"_psams._udp.local.", false, "playstation", true, ""}, // play station
}

// PrintServices log the services table
func PrintServices() {
	for i := range serviceTable {
		fmt.Printf("service=%v poll=%v\n", serviceTable[i].service, serviceTable[i].enabled)
	}
}

func findServiceIndex(service string) int {
	serviceTableMutex.RLock()
	defer serviceTableMutex.RUnlock()

	for i := range serviceTable {
		if strings.Contains(service, serviceTable[i].service) {
			return i
		}
	}
	return -1
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

	s := serviceDef{service: service, enabled: true}
	serviceTable = append(serviceTable, s)
	if Debug {
		log.Print("mdns enabled new mdns service ", s.service)
	}
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

// QueryAll send a mdns discovery packet plus a mdns query for each active service on the LAN
func (c *Handler) QueryAll() error {

	// Do a round of service discovery
	// The listener will pickup responses and call enableService for each
	if err := c.SendQuery("_services._dns-sd._udp.local."); err != nil {
		return fmt.Errorf("mdns query fail _services._dns-sd._udp.local.: %w", err)

	}
	time.Sleep(time.Millisecond * 5)

	serviceTableMutex.Lock()
	for i := range serviceTable {
		if err := c.SendQuery(serviceTable[i].service); err != nil {
			return fmt.Errorf("mdns query fail %s: %w", serviceTable[i].service, err)
		}
		time.Sleep(time.Millisecond * 5)
	}
	serviceTableMutex.Unlock()
	return nil
}
