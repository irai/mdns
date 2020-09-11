package mdns

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
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

	model := ""
	defaultModel := ""
	name := ""

	for _, value := range entry.services {
		// Get name
		if value.target != "" {
			switch name {
			case "":
				name = value.target
			default:
				if name != value.target {
					log.Printf("mdns ignoring dual name=%s target=%s", name, value.target)
				}
			}
		}

		// find model from TXT entry if available
		if index := findServiceIndex(value.fqn); index != -1 {
			s := serviceTable[index]
			m := ""
			if s.keyName != "" {
				m = value.txt[s.keyName]
				if m != "" {
					m = strings.Split(m, ",")[0] // remove trailing ,xxxx
				}
			}

			if s.authoritative && m != "" { //Sonos entry does not have model txt; m will be ""
				model = m
			}

			if m != "" && !strings.Contains(model, m) { // append if string is new only
				if model != "" {
					model = model + ","
				}
				model = model + m
			}

			if !strings.Contains(defaultModel, s.defaultModel) {
				if defaultModel != "" {
					defaultModel = defaultModel + ","
				}
				defaultModel = defaultModel + s.defaultModel
			}
		} else {
			log.Printf("mdns service not registered %+v", value)
		}
	}

	entry.Name = name
	if model != "" {
		entry.Model = model
	} else {
		entry.Model = defaultModel
	}

	if entry.IPv4 == nil || entry.IPv4.IsUnspecified() || entry.Name == "" || entry.Model == "" {
		if Debug {
			log.Printf("mdns invalid entry %+v", *entry)
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
		// delete stale name if IP changed
		if e := c.findByNameNoLock(entry.Name); e != nil {
			if Debug {
				log.Printf("mdns changed IP name=%s ip=%s new_ip=%s", entry.Name, e.IPv4, entry.IPv4)
			}
			delete(c.table, string(e.IPv4))
		}
		current = &Entry{}
		*current = *entry
		modified = true
		c.table[string(current.IPv4)] = current
		if Debug {
			log.Printf("mdns new entry %+v", current)
		}
	} else {
		if current.Model != entry.Model && len(current.Model) < len(entry.Model) {
			current.Model = entry.Model
			current.Name = entry.Name
			modified = true
			if Debug {
				log.Printf("mdns updated model %v", current)
			}
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
		fmt.Printf("MDNS %16s %v %v\n", v.IPv4, v.Name, v.Model)
	}
}

func (c *mdnsTable) findByName(hostname string) *Entry {
	c.RLock()
	defer c.RUnlock()

	return c.table[hostname]
}
