package main

import (
	"flag"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"log"
	"net"
	"os"
	"time"
)

type nwDevice struct {
	macAddr  net.HardwareAddr
	ipv6Addr net.IP
}

func getMacAddr(ifname string) net.HardwareAddr {
	netifs, _ := net.Interfaces()
	for _, netif := range netifs {
		if netif.Name == ifname {
			return netif.HardwareAddr
		}
	}
	return nil
}

func parseMac(macaddr string) net.HardwareAddr {
	parsedMac, _ := net.ParseMAC(macaddr)
	return parsedMac
}

type segmentRoutingHeader struct {
	nextHeader  uint8
	hdrLen      uint8
	routingType uint8
	segLeft     uint8
	lastEntry   uint8
	flags       uint8
	tags        []byte
	segmentList []net.IP
}

func (srh *segmentRoutingHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8 + len(srh.segmentList)*16)
	if err != nil {
		return err
	}
	bytes[0] = srh.nextHeader
	bytes[1] = srh.hdrLen
	bytes[2] = srh.routingType
	bytes[3] = srh.segLeft
	bytes[4] = srh.lastEntry
	bytes[5] = srh.flags
	copy(bytes[6:7], srh.tags)
	for i, ip := range srh.segmentList {
		offset := 8 + i*16
		copy(bytes[offset:offset+16], ip.To16())
	}
	return nil
}

func (srh *segmentRoutingHeader) LayerType() gopacket.LayerType {
	return gopacket.LayerType(47)
}

type icmpRequestInfo struct {
	srcMac net.HardwareAddr
	srcIp  string
	destIp string
	srv6Ip string
	seq    uint16
}

func createICMPv6EchoRequest(icmpReq icmpRequestInfo) []byte {
	// Ethernetヘッダを作成
	ethernet := &layers.Ethernet{
		SrcMAC:       icmpReq.srcMac,
		DstMAC:       parseMac("62:3b:ab:c6:56:de"), // r2 mac addr
		EthernetType: layers.EthernetTypeIPv6,
	}
	// IPv6ヘッダを作成
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		//NextHeader: layers.IPProtocolICMPv6,
		HopLimit:  64,
		FlowLabel: 0xb3124,
		SrcIP:     net.ParseIP(icmpReq.srcIp),  // "fc00:a::1"
		DstIP:     net.ParseIP(icmpReq.srv6Ip), // "fc00:e::2"
	}

	segList := []net.IP{
		net.ParseIP(icmpReq.destIp), // "fc00:d::2"
		net.ParseIP(icmpReq.srv6Ip), // "fc00:e::2"
	}
	// Segment Routing Headerを作成
	srh := segmentRoutingHeader{
		nextHeader:  uint8(layers.IPProtocolICMPv6),
		hdrLen:      uint8(len(segList) * 16 / 8),
		routingType: 4,
		segLeft:     1,
		lastEntry:   1,
		flags:       0,
		tags:        []byte{0x00, 0x00},
		segmentList: segList,
	}

	// ICMPv6 Echo Requestの作成
	icmp6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
		Checksum: 0x879c - icmpReq.seq,
	}

	// ICMPv6 Echo RequestのPayload
	var payload []byte
	payload = append(payload, []byte{0x00, 0x01}...)              // identifier
	payload = append(payload, []byte{0x00, byte(icmpReq.seq)}...) // sequence
	payload = append(payload, []byte{0x00, 0x00, 0x00, 0x00}...)  // payload

	// パケットのバッファを作成
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}

	// パケットをシリアライズ
	err := gopacket.SerializeLayers(buf, opts, ethernet, ip6, &srh, icmp6, gopacket.Payload(payload))
	if err != nil {
		log.Fatal(err)
	}

	return buf.Bytes()
}

func main() {
	var iface = flag.String("I", "r1-r2", "Interface to read packets from")
	var sr = flag.String("sr", "fc00:e::2", "SRv6 Header IPv6 Addr")
	var srcIp = flag.String("src", "fc00:a::1", "Source IPv6 Addr")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		fmt.Println("Usage: ping-srv6 -I <interface> <target>")
		os.Exit(1)
	}
	dstIP := args[0]

	pingInterval := 1 * time.Second

	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Pingのシーケンス番号
	seq := uint16(0)
	// Pingを送信する
	go func() {
		for {
			time.Sleep(pingInterval)
			echoRequest := createICMPv6EchoRequest(icmpRequestInfo{
				srcMac: getMacAddr(*iface),
				srcIp:  *srcIp,
				destIp: dstIP,
				srv6Ip: *sr,
				seq:    seq,
			})
			seq++
			// パケットを送信
			if err := handle.WritePacketData(echoRequest); err != nil {
				log.Fatalf("Failed to send packet: %v", err)
			}
		}
	}()

	for {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
			reply := icmpLayer.(*layers.ICMPv6)
			if reply.TypeCode.Type() == layers.ICMPv6TypeEchoReply {
				fmt.Printf("recieve echo reply from %s\n", dstIP)
				break
			}
		}
	}
}
