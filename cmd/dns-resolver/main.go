package main

import (
	"dns-resolver/pkg/dns"
	"fmt"
	"net"
)

func main() {
	fmt.Printf("Starting DNS Server...\n")

	packetConn, err := net.ListenPacket("udp", ":53")
	if err != nil {
		panic(err)
	}

	defer packetConn.Close()

	for {
		buf := make([]byte, 512)
		bytesRead, addr, err := packetConn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("Error reading packet: %s \n", err)
			continue
		}
		go dns.HandlePacket(packetConn, addr, buf[:bytesRead])

	}
}
