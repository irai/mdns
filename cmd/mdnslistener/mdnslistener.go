package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/irai/mdns"
	log "github.com/sirupsen/logrus"
)

func main() {
	flag.Parse()

	mdns.LogAll = true
	setLogLevel("debug")

	mdns, err := mdns.NewHandler("nic")
	if err != nil {
		log.Fatal("error in mdns", err)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	go mdns.ListenAndServe(ctx, time.Minute*3)

	cmd(mdns)

	cancel()

	time.Sleep(time.Second)

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
