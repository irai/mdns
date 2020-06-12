package mdns

import (
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

type srv struct {
	fqn    string
	target string
	port   uint16
	txt    map[string]string
	s      *serviceDef
}

// Entry contains a full record of a mDNS entry
//
// Simplified mdns entry to show the record by IPv4
type Entry struct {
	IPv4     net.IP
	IPv6     net.IP
	Name     string
	Model    string
	services map[string]*srv
}

// String return a simple Entry string
func (e *Entry) String() string {
	return fmt.Sprintf("%16s %s %s - %v services", e.IPv4, e.Name, e.Model, len(e.services))
}

func (e *Entry) addSRV(fqn string, target string, port uint16) {
	if r, ok := e.services[fqn]; ok {
		r.target = target
		r.port = port
		return
	}
	e.services[fqn] = &srv{fqn: fqn, target: target, port: port, txt: make(map[string]string)}
}

func (e *Entry) addTXT(fqn string, txt []string) {

	// copy to a map
	m := make(map[string]string)
	for i := range txt {
		a := strings.Split(txt[i], "=")
		if len(a) > 1 {
			m[a[0]] = a[1]
		}
	}

	// Merge txt attributes if service exist
	if r, ok := e.services[fqn]; ok {
		for k, v := range m {
			r.txt[k] = v
		}
		return
	}

	e.services[fqn] = &srv{fqn: fqn, txt: m}
}

type mdnsTable struct {
	table        map[string]*Entry
	sync.RWMutex // anynymous
}

func (c *mdnsTable) processEntry(entry *Entry) (*Entry, bool) {

	authoritative := false
	for _, value := range entry.services {

		// Populate name with first available name
		if entry.Name == "" && value.target != "" {
			entry.Name = value.target
		}

		switch {
		case strings.Contains(value.fqn, "_ipp._") ||
			strings.Contains(value.fqn, "_ipps._") ||
			strings.Contains(value.fqn, "_printer._"):
			// see spec http://devimages.apple.com/opensource/BonjourPrinting.pdf
			// 9.2.6 ty
			// The value of this key provides a user readable description of the make and model of the printer
			// which is suitable for display in a user interface when describing the printer.
			entry.Model = value.txt["ty"]
			authoritative = true

		case strings.Contains(value.fqn, "_privet._") ||
			strings.Contains(value.fqn, "_uscans._") ||
			strings.Contains(value.fqn, "_uscan._") ||
			strings.Contains(value.fqn, "_pdl-datastream._tcp.local.") ||
			strings.Contains(value.fqn, "_scanner._"):
			if !authoritative {
				entry.Model = value.txt["ty"]
			}

		case strings.Contains(value.fqn, "_airplay._") || strings.Contains(value.fqn, "_raop._"):
			entry.Model = value.txt["model"]
			authoritative = true

		case strings.Contains(value.fqn, "_touch-able._tcp.local."):
			if !authoritative {
				if m := value.txt["DvTy"]; m != "" { // could also use CtLn
					entry.Model = m
				}
			}

		case strings.Contains(value.fqn, "_device-info._"):
			if !authoritative {
				entry.Model = value.txt["model"]
			}

		case strings.Contains(value.fqn, "_xbox._"):
			entry.Model = "XBox"
			authoritative = true

		case strings.Contains(value.fqn, "_sonos._"):
			entry.Model = "Sonos speaker"
			authoritative = true

		case strings.Contains(value.fqn, "_googlecast._"):
			entry.Model = "Chromecast"
			authoritative = true

		case strings.Contains(value.fqn, "_spotify-connect._"):
			if !authoritative {
				entry.Model = "Speaker"
			}

		case strings.Contains(value.fqn, "_smb._tcp.local."):
			if !authoritative {
				if m := value.txt["model"]; m != "" { // Macbook publishes a smb service with model
					entry.Model = m
				}
			}

		case strings.Contains(value.fqn, "_sleep-proxy._udp.local.") || // Apple TV unsolicited mdns multicast
			strings.Contains(value.fqn, "_http._tcp.local."):
			if LogAll {
				log.Debugf("mdns ignoring service %+v", value)
			}

		default:
			log.Errorf("mdns unknown service %+v", value)

		}
	}

	if entry.IPv4 == nil || entry.IPv4.Equal(net.IPv4zero) || entry.Name == "" {
		if LogAll && log.IsLevelEnabled(log.DebugLevel) {
			log.Errorf("mdns invalid entry %+v", *entry)
		}
		return nil, false
	}

	// spaces and special character are escaped with \\
	// iphone send  "Bob's\ iphone"
	entry.Name = strings.Replace(entry.Name, "\\", "", -1)

	modified := false

	c.Lock()
	current := c.table[string(entry.IPv4)]
	if current == nil {
		current = &Entry{}
		*current = *entry
		modified = true
		log.Tracef("mdns new entry %+v", current)
	} else {
		if (authoritative && current.Model != entry.Model) || (!authoritative && current.Model == "") {
			current.Model = entry.Model
			current.Name = entry.Name
			modified = true
			log.Tracef("mdns updated model %v", current)
		}

		// update services
		for k, v := range entry.services {
			current.services[k] = v
		}
	}
	c.table[string(current.IPv4)] = current
	c.Unlock()
	return current, modified
}

func (c *mdnsTable) getEntryByIP(ip net.IP) *Entry {
	c.RLock()
	defer c.RUnlock()

	return c.table[string(ip)]
}

// PrintTable will print entries to stdout
func (c *mdnsTable) printTable() {
	c.RLock()
	defer c.RUnlock()

	for _, v := range c.table {
		log.Infof("MDNS %16s %v %v ", v.IPv4, v.Name, v.Model)
	}
}

func (c *mdnsTable) findByName(hostname string) *Entry {
	c.RLock()
	defer c.RUnlock()

	return c.table[hostname]
}
