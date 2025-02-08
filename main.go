package main

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"log"
	"net"
)

var echoPacket = []byte{
	0x80, 0x00, 0xd7, 0x99, 0x70, 0xf1, 0x00, 0x02,
	0x86, 0xd7, 0xa6, 0x67, 0x00, 0x00, 0x00, 0x00,
	0x4a, 0xca, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
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

func main() {
	// Ethernetヘッダを作成
	ethernet := &layers.Ethernet{
		SrcMAC:       parseMac("52:ca:fe:e3:f1:c0"),
		DstMAC:       parseMac("f2:8c:86:be:f9:a3"),
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
		DstIP:     net.ParseIP("fc00:d::2"),
	}

	segList := []net.IP{
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
		Checksum: 0x879b,
	}

	// ICMPv6 Echo RequestのPayload
	var payload []byte
	payload = append(payload, []byte{0x00, 0x01}...)             // identifier
	payload = append(payload, []byte{0x00, 0x01}...)             // sequence
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

	//fmt.Printf("%x\n", buf.Bytes())
	handle, err := pcap.OpenLive("h1-r1", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// pingを送信
	handle.WritePacketData(buf.Bytes())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		icmpLayer := packet.Layer(layers.LayerTypeICMPv6)
		reply := icmpLayer.(*layers.ICMPv6)
		if reply.TypeCode == layers.ICMPv6TypeEchoReply {
			fmt.Printf("recieve echo reply %+v\n", reply)
			break
		}
	}
}
