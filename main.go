package main

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"log"
	"net"
	"time"
)

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

func createICMPv6EchoRequest(seq uint16) []byte {
	// Ethernetヘッダを作成
	ethernet := &layers.Ethernet{
		SrcMAC:       parseMac("f2:8c:86:be:f9:a3"),
		DstMAC:       parseMac("62:3b:ab:c6:56:de"),
		EthernetType: layers.EthernetTypeIPv6,
	}
	// IPv6ヘッダを作成
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		//NextHeader: layers.IPProtocolICMPv6,
		HopLimit:  64,
		FlowLabel: 0xb3124,
		SrcIP:     net.ParseIP("fc00:a::1"),
		DstIP:     net.ParseIP("fc00:d::1"),
	}

	segList := []net.IP{
		net.ParseIP("fc00:d::1"),
		net.ParseIP("fc00:e::2"),
	}
	// Segment Routing Headerを作成
	srh := segmentRoutingHeader{
		nextHeader:  uint8(layers.IPProtocolICMPv6),
		hdrLen:      uint8(len(segList) * 16 / 8),
		routingType: 4,
		segLeft:     0,
		lastEntry:   0,
		flags:       0,
		tags:        []byte{0x00, 0x00},
		segmentList: segList,
	}

	// ICMPv6 Echo Requestの作成
	icmp6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
		Checksum: 0x879d - seq,
	}

	// ICMPv6 Echo RequestのPayload
	var payload []byte
	payload = append(payload, []byte{0x00, 0x01}...)             // identifier
	payload = append(payload, []byte{0x00, byte(seq)}...)        // sequence
	payload = append(payload, []byte{0x00, 0x00, 0x00, 0x00}...) // payload

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

	pingInterval := 1 * time.Second

	handle, err := pcap.OpenLive("r1-r2", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Pingのシーケンス番号
	seq := uint16(0)
	// ICMPv6エコーリクエストを作成
	go func() {
		for {
			time.Sleep(pingInterval)
			echoRequest := createICMPv6EchoRequest(seq)
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
				fmt.Printf("recieve echo reply\n")
				break
			}
		}
	}
}
