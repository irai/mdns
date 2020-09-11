package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/irai/mdns"
)

func newEntry(ctx context.Context, c chan mdns.Entry) {
	for {
		select {
		case <-ctx.Done():
			return
		case entry := <-c:
			fmt.Println("mdnslistener got new entry ", entry.Name, entry.IPv4, entry.Model)
		}
	}
}

func main() {
	flag.Parse()

	mdns.Debug = true

	ctx, cancel := context.WithCancel(context.TODO())

	handler, err := mdns.NewHandler("nic")
	if err != nil {
		log.Fatal("error in mdns", err)
	}

	c := make(chan mdns.Entry, 10)
	handler.AddNotificationChannel(c)

	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		defer wg.Done()
		newEntry(ctx, c)
	}()
	go func() {
		wg.Add(1)
		defer wg.Done()
		handler.ListenAndServe(ctx)
	}()

	go func(ctx context.Context) {
		wg.Add(1)
		defer wg.Done()

		handler.QueryAll()
		tick := time.NewTicker(time.Minute * 3)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				handler.QueryAll()
			}
		}
	}(ctx)

	cmd(handler)
	cancel()

	wg.Wait()
}

func cmd(c *mdns.Handler) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("Command: (q)uit | (e) query | (s) <end _service._protocol.> | (l) list protocols | (p)rint | (g) debug|error")
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
			switch text[2:] {
			case "debug":
				mdns.Debug = true
			case "error":
				mdns.Debug = false
			default:
				log.Print("invalid level. valid levels (error, debug) ")
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
				log.Print("error sending query ", err)
				break
			}

		case 'p':
			c.PrintTable()

		}
	}
}
