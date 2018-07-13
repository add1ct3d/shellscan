package main

import (
	"errors"
	"fmt"
	"net"
	"time"
	"bufio"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Scanner handles scanning a single IP address.
type SSHScanner struct {
	// The interface is the interface to SendPacket packets on.
	Interface *net.Interface

	// All the IP addresses that we need to send and receive packets.
	DestIP net.IP
	Gateway net.IP
	SourceIP net.IP

	// The PCAP read/write handle.
	PCAPHandle *pcap.Handle

	// The following help to easily serialize packets in the SendPacket() method.
	Options gopacket.SerializeOptions
	Buffer gopacket.SerializeBuffer
}

// DestMACAddress : Gets the network address.
func (sshScanner *SSHScanner) DestMACAddress() (net.HardwareAddr, error) {
	start := time.Now()
	arpDst := sshScanner.DestIP

	if sshScanner.Gateway != nil {
		arpDst = sshScanner.Gateway
	}

	// Prepare the layers to SendPacket for an ARP request.
	eth := layers.Ethernet{
		SrcMAC: sshScanner.Interface.HardwareAddr,
		DstMAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6,
		ProtAddressSize: 4,
		Operation: layers.ARPRequest,
		SourceHwAddress: []byte(sshScanner.Interface.HardwareAddr),
		SourceProtAddress: []byte(sshScanner.SourceIP),
		DstHwAddress: []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress: []byte(arpDst),
	}

	// Send the ARP packet.
	if err := sshScanner.SendPacket(&eth, &arp); err != nil {
		return nil, err
	}

	// Wait for an ARP reply and then return the address.
	for {
		// Has time run out?
		if time.Since(start) > time.Second * 3 {
			return nil, errors.New("No ARP reply within 3 seconds")
		}

		data, _, err := sshScanner.PCAPHandle.ReadPacketData()

		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)

			if net.IP(arp.SourceProtAddress).Equal(net.IP(arpDst)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

// ScanAddress scans the DestIP IP address of this scanner.
func (sshScanner *SSHScanner) ScanAddress() error {
	// Before we do anything, we ensure we have the MAC address of where
	// we're sending packets to.
	hwaddr, err := sshScanner.DestMACAddress()

	if err != nil {
		return err
	}

	// Construct all the network layers we need.
	eth := layers.Ethernet{
		SrcMAC: sshScanner.Interface.HardwareAddr,
		DstMAC: hwaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Craft the IPv4 portion.
	ip4 := layers.IPv4{
		SrcIP: sshScanner.SourceIP,
		DstIP: sshScanner.DestIP,
		Version: 4,
		TTL: 64,
		Protocol: layers.IPProtocolTCP,
	}

	// Craft a plain-ole SYN packet.
	tcp := layers.TCP{
		SYN: true,
		SrcPort: 63323,
		DstPort: 22,
	}

	// Set the checksum of the network.
	tcp.SetNetworkLayerForChecksum(&ip4)

	// Create the flow we expect returning packets to have, so we can check
	// against it and discard useless packets.
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, sshScanner.DestIP, sshScanner.SourceIP)
	start := time.Now()
	sent := false

	for {
		// We SendPacket only one packet to port 22, which is the port we're looking
		// for.
		if !sent {
			start = time.Now()
			if err := sshScanner.SendPacket(&eth, &ip4, &tcp); err != nil {
				fmt.Printf("Error sending to port %v: %v\n", tcp.DstPort, err)
			} else {
				sent = true
			}
		}

		// Set a timeout if no response was received.
		if time.Since(start) > time.Second * 3 {
			return nil
		}

		// Read in the next packet.
		data, _, err := sshScanner.PCAPHandle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			fmt.Printf("Error reading packet: %v\n", err)
			continue
		}

		// Here we need to parse the packet in order to conduct some checks as to
		// whether it'sshScanner the one we're looking for.
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		netLayer := packet.NetworkLayer()
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, ok := tcpLayer.(*layers.TCP);

		if netLayer != nil && netLayer.NetworkFlow() == netFlow && tcpLayer != nil && ok {
			// This *is* the packet we're looking for...
			if tcp.DstPort == 63323 && tcp.SYN && tcp.ACK {
				start = time.Now()
				conn, _ := net.Dial("tcp", sshScanner.DestIP.String() + ":22")
				connbuf := bufio.NewReader(conn)
				data := ""
				str, err := connbuf.ReadString('\n')

				if len(str) > 0 {
					data = strings.Trim(str, "\n")
				}

				if err != nil {
					data = "Unable to get banner"
				}

				fmt.Printf("%sshScanner:%d,%sshScanner\n", sshScanner.DestIP.String(), (uint16)(tcp.SrcPort), data)

				return nil
			}
		}
	}

	// Check if the port is open.
	return errors.New("The port is not open")
}

// SendPacket : This function sends a packet, as serialized by gopacket.
func (sshScanner *SSHScanner) SendPacket(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(sshScanner.Buffer, sshScanner.Options, l...); err != nil {
		return err
	}

	// Return an error, if there was one.
	return sshScanner.PCAPHandle.WritePacketData(sshScanner.Buffer.Bytes())
}

// Close : This function cleans up the PCAPHandle.
func (sshScanner *SSHScanner) Close() {
	sshScanner.PCAPHandle.Close()
}

