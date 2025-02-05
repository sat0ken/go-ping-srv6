package main

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"log"
	"net"
)

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
	// IPv6ヘッダを作成
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   63,
		SrcIP:      net.ParseIP("fc00:b::1"),
		DstIP:      net.ParseIP("fc00:e::2"),
	}

	segList := []net.IP{
		net.ParseIP("fc00:e::2"),
	}
	// Segment Routing Headerを作成
	srh := segmentRoutingHeader{
		nextHeader:  uint8(layers.IPProtocolIPv6),
		hdrLen:      uint8(len(segList) * 16 / 8),
		routingType: 4,
		segLeft:     0,
		lastEntry:   0,
		flags:       0,
		tags:        []byte{0x00, 0x00},
		segmentList: segList,
	}

	// IPv6 Next ヘッダを作成
	ip6Next := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   64,
		SrcIP:      net.ParseIP("fc00:a::1"),
		DstIP:      net.ParseIP("fc00:d::2"),
	}

	// ICMPv6 Echo Requestの作成
	icmp6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}

	// パケットのバッファを作成
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}

	// パケットをシリアライズ
	err := gopacket.SerializeLayers(buf, opts, ip6, &srh, ip6Next, icmp6)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x\n", buf.Bytes())
}
