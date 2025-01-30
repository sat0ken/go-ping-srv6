package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"log"
	"net"
)

func uint16ToByte(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

type segmentRoutingHeader struct {
	nextHeader  uint8
	hdrLen      uint8
	routingType uint8
	segLeft     uint8
	lastEntry   uint8
	flags       uint8
	tags        uint16
	segmentList []net.IP
}

func (srh *segmentRoutingHeader) toPacket() []byte {
	var b bytes.Buffer

	b.WriteByte(srh.nextHeader)
	b.WriteByte(srh.hdrLen)
	b.WriteByte(srh.routingType)
	b.WriteByte(srh.segLeft)
	b.WriteByte(srh.lastEntry)
	b.WriteByte(srh.flags)
	b.Write(uint16ToByte(srh.tags))

	for _, ip := range srh.segmentList {
		b.Write(ip)
	}

	return b.Bytes()
}

func main() {
	// IPv6ヘッダを作成
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8:3::3"),
		DstIP:      net.ParseIP("2001:db8:200::222"),
	}

	segList := []net.IP{
		net.ParseIP("2001:db8:100::1:0:1e"),
		net.ParseIP("2001:db8:100::111"),
		net.ParseIP("2001:db8:200::222"),
	}
	// Segment Routing Headerを作成
	srh := segmentRoutingHeader{
		nextHeader:  uint8(layers.IPProtocolIPv4),
		hdrLen:      uint8(len(segList) * 16 / 8),
		routingType: 4,
		segLeft:     2,
		lastEntry:   2,
		flags:       0,
		tags:        0,
		segmentList: segList,
	}
	// ICMPv6 Echo Requestの作成
	//icmpv6 := &layers.ICMPv6{
	//	TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	//}

	// ICMPv6 Echo Requestのペイロード
	//payload := []byte("Hello, SRV6!")

	// パケットのバッファを作成
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// パケットをシリアライズ
	err := gopacket.SerializeLayers(buf, opts, ip6)
	if err != nil {
		log.Fatal(err)
	}

	b := buf.Bytes()
	b = append(b, srh.toPacket()...)

	fmt.Printf("%x\n", b)

}
