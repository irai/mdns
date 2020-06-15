package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/irai/mdns"
	log "github.com/sirupsen/logrus"
)

func newEntry(ctx context.Context, c chan mdns.Entry) {
	select {
	case <-ctx.Done():
		return
	case entry := <-c:
		fmt.Println("got new entry ", entry.Name, entry.IPv4)
	}
}

func main() {
	flag.Parse()

	mdns.LogAll = true
	setLogLevel("trace")

	ctx, cancel := context.WithCancel(context.TODO())

	handler, err := mdns.NewHandler("nic")
	if err != nil {
		log.Fatal("error in mdns", err)
	}

	c := make(chan mdns.Entry, 10)
	handler.AddNotificationChannel(c)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		newEntry(ctx, c)
		wg.Done()
	}()
	go func() {
		handler.ListenAndServe(ctx, time.Minute*3)
		wg.Done()
	}()

	cmd(handler)
	cancel()

	wg.Wait()
}

func cmd(c *mdns.Handler) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit | (e) query | (s) <end _service._protocol.> | (l) list protocols | (p)rint | (g) <log_level>")
		fmt.Print("Enter command: ")
		text, _ := reader.ReadString('\n')
		text = strings.ToLower(strings.TrimRight(text, "\r\n")) // remove \r\n in windows or \n in linux
		fmt.Println(text)

		if text == "" || len(text) < 1 {
			continue
		}

		switch text[0] {
		case 'q':
			return
		case 'g':
			if len(text) < 3 {
				text = text + "   "
			}
			err := setLogLevel(text[2:])
			if err != nil {
				log.Error("invalid level. valid levels (error, warn, info, debug) ", err)
				break
			}
		case 'e':
			c.SendQuery("_services._dns-sd._udp.local.")

		case 'l':
			mdns.PrintServices()

		case 's':
			if len(text) < 3 {
				break
			}
			if err := c.SendQuery(text[2:]); err != nil {
				log.Error("error sending query ", err)
				break
			}

		case 'p':
			c.PrintTable()

		}
	}
}

func setLogLevel(level string) (err error) {

	if level != "" {
		l, err := log.ParseLevel(level)
		if err != nil {
			return err
		}
		log.SetLevel(l)
	}

	return nil
}
