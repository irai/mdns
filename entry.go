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

func (c *mdnsTable) findByNameNoLock(name string) *Entry {
	for _, v := range c.table {
		if v.Name == name {
			return v
		}
	}
	return nil
}

func (c *mdnsTable) processEntry(entry *Entry) (*Entry, bool) {

	authoritative := false
	for _, value := range entry.services {

		// Populate name with first available
		if entry.Name == "" && value.target != "" {
			entry.Name = value.target
		}

		// find model from TXT entry if available
		if index := findServiceIndex(value.fqn); index != -1 {
			s := serviceTable[index]
			model := ""
			if s.keyName != "" {
				model = value.txt[s.keyName]
			} else {
				model = s.defaultModel
			}

			if s.authoritative {
				entry.Model = model
				authoritative = true
			} else {
				if entry.Model == "" && model != "" {
					entry.Model = model
				}
			}
		} else {
			if LogAll {
				log.Debugf("mdns ignoring service %+v", value)
			}
		}
	}

	if entry.IPv4 == nil || entry.IPv4.Equal(net.IPv4zero) || entry.Name == "" {
		if LogAll && log.IsLevelEnabled(log.DebugLevel) {
			if LogAll {
				log.Debugf("mdns invalid entry %+v", *entry)
			}
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
		// delete stale entry if IP changed
		if e := c.findByNameNoLock(entry.Name); e != nil {
			if LogAll {
				log.WithFields(log.Fields{"name": entry.Name, "ip": e.IPv4, "new_ip": entry.IPv4}).Debug("mdns changed IP ")
			}
			delete(c.table, string(e.IPv4))
		}
		current = &Entry{}
		*current = *entry
		modified = true
		c.table[string(current.IPv4)] = current
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
		fmt.Printf("MDNS %16s %v %v ", v.IPv4, v.Name, v.Model)
	}
}

func (c *mdnsTable) findByName(hostname string) *Entry {
	c.RLock()
	defer c.RUnlock()

	return c.table[hostname]
}
