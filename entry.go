package mdns

import (
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

type srv struct {
	fqn  string
	port uint16
	txt  map[string]string
	s    *serviceDef
}

// Entry contains a full record of a mDNS entry
//
// Simplified mdns entry to show the record by IPv4
type Entry struct {
	Hostname string
	IPv4     net.IP
	IPv6     net.IP
	Name     string
	Model    string
	services map[string]srv
}

// String return a simple Entry string
func (e *Entry) String() string {
	return fmt.Sprintf("%s %s - %v services", e.Hostname, e.IPv4, len(e.services))
}

func (e *Entry) addSRV(fqn string, port uint16) {
	if r, ok := e.services[fqn]; ok {
		r.port = port
		return
	}
	e.services[fqn] = srv{fqn: fqn, port: port, txt: make(map[string]string)}
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

	e.services[fqn] = srv{fqn: fqn, txt: m}
}

type mdnsTable struct {
	table        map[string]*Entry
	sync.RWMutex // anynymous
}

func (c *mdnsTable) processEntry(entry *Entry) (*Entry, bool) {

	for _, value := range entry.services {
		switch {
		case strings.Contains(value.fqn, "_ipp._") ||
			strings.Contains(value.fqn, "_ipps._") ||
			strings.Contains(value.fqn, "_printer._") ||
			strings.Contains(value.fqn, "_privet._") ||
			strings.Contains(value.fqn, "_uscans._") ||
			strings.Contains(value.fqn, "_scanner._"):
			// see spec http://devimages.apple.com/opensource/BonjourPrinting.pdf
			// 9.2.6 ty
			// The value of this key provides a user readable description of the make and model of the printer
			// which is suitable for display in a user interface when describing the printer.
			if v, ok := value.txt["ty"]; ok && v != "" {
				entry.Model = v
			}

		case strings.Contains(value.fqn, "_airplay._") || strings.Contains(value.fqn, "_raop._"):
			entry.Model = value.txt["model"]

		case strings.Contains(value.fqn, "_xbox._"):
			entry.Model = "XBox"

		case strings.Contains(value.fqn, "_sonos._"):
			entry.Model = "Sonos"

		case strings.Contains(value.fqn, "_googlecast._"):
			entry.Model = "Chromecast"

		case strings.Contains(value.fqn, "_spotify-connect._"):
			entry.Model = "Speaker"

		default:
			log.Infof("mdns unknown service %+v", value)

		}
	}

	if entry.Hostname == "" || entry.IPv4.Equal(net.IPv4zero) {
		if LogAll && log.IsLevelEnabled(log.DebugLevel) {
			log.Debugf("mdns invalid entry %+v", entry)
		}
		return nil, false
	}

	// spaces and special character are escaped with \\
	// iphone send  "Bob's\ iphone"
	entry.Name = strings.Replace(entry.Hostname, "\\", "", -1)

	modified := false
	c.Lock()
	current := c.table[entry.Hostname]
	if current == nil {
		current = &Entry{}
		*current = *entry
		modified = true
		log.Debugf("mdns new entry %+v", current)
	} else {
		if entry.Model != "" && current.Model != entry.Model {
			current.Model = entry.Model
			modified = true
		}

		// update services
		for k, v := range entry.services {
			current.services[k] = v
		}

		log.Debugf("mdns updated entry %+v", *current)
	}
	c.table[current.Hostname] = current
	c.Unlock()
	return current, modified
}

func (c *mdnsTable) getEntryByIP(ip net.IP) *Entry {
	c.RLock()
	defer c.RUnlock()

	for _, value := range c.table {
		if value.IPv4.Equal(ip) {
			return value
		}
	}
	return nil
}

// PrintTable will print entries to stdout
func (c *mdnsTable) printTable() {
	c.RLock()
	defer c.RUnlock()

	for _, v := range c.table {
		log.Infof("MDNS %16s %v %v", v.IPv4, v.Model, v.Hostname)
	}
}

func (c *mdnsTable) findByName(hostname string) *Entry {
	c.RLock()
	defer c.RUnlock()

	return c.table[hostname]
}
