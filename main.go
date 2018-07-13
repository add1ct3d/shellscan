package main

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

// create : Initialize a new scanner that will scan our target IP address.
func create(ip net.IP, router routing.Router) (*SSHScanner, error) {
	// Initialize a new SSHScanner.
	sshScanner := &SSHScanner{
		// Set the destination IP.
		DestIP: ip,

		// And set the helper options and buffer.
		Buffer: gopacket.NewSerializeBuffer(),
		Options: gopacket.SerializeOptions{
			FixLengths: true,
			ComputeChecksums: true,
		},
	}

	// Figure out the route to the IP address of choice.
	iface, gateway, src, err := router.Route(ip)

	if err != nil {
		return nil, err
	}

	sshScanner.Gateway = gateway
	sshScanner.SourceIP = src
	sshScanner.Interface = iface

	// Open a PCAP handle for editing ops.
	pcapHandle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)

	if err != nil {
		return nil, err
	}

	sshScanner.PCAPHandle = pcapHandle

	return sshScanner, nil
}

// expand : A helper function to manage an IP group.
func expand(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++

		if ip[j] > 0 {
			break
		}
	}
}

// remove : Removes an item form an array.
func remove(slice []string, sshScanner int) []string {
	return append(slice[:sshScanner], slice[sshScanner + 1:]...)
}

func main() {
	// Parse all command line arguments, which should just be IPs.
	flag.Parse()

	// Instanciate a new router.
	router, err := routing.New()

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Collect the command line arguments.
	args := flag.Args()
	i := 0

	// Go through the IP nets and expand everything.
	for _, arg := range args {
		if strings.ContainsAny(arg, "/") {
			ip, ipnet, err := net.ParseCIDR(arg)

			if err != nil {
				fmt.Println(err)
			}

			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); expand(ip) {
				args = append(args, ip.String())
			}

			remove(args, i)
			i++
		}
	}

	// A counter that will help us wait until all these jobs are done.
	wait := len(args)

	// Now loop through the expanded args and scan everything.
	for _, arg := range args {
		var ip net.IP

		if ip = net.ParseIP(arg); ip == nil {
			fmt.Printf("Invalid IP entered: %q\n", arg)
			continue
		} else if ip = ip.To4(); ip == nil {
			fmt.Printf("Non-IPv4 target: %q\n", arg)
			continue
		}

		go func() bool {
			// Create a new SSH scanner.
			sshScanner, err := create(ip, router)

			if err != nil {
				fmt.Printf("Unable to create scanner for %v: %v\n", ip, err)
				wait--
				return false
			}

			// Run the scanner.
			if err := sshScanner.ScanAddress(); err != nil {
				wait--
				return false
			}

			// Stop the scanner.
			sshScanner.Close()

			wait--

			return true
		}()
	}

	// A bit hacky, but it works for now.
	for {
		if wait == 0 {
			break
		}
	}
}

