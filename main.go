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
	tags        uint16
	segmentList []net.IP
}

func main() {
	// IPv6ヘッダを作成
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolIPv6Routing,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	// Segment Routing Headerを作成
	srh := &layers.IPv6Routing{
		RoutingType:  4,
		SegmentsLeft: 2, // 残りのセグメント数
		SourceRoutingIPs: []net.IP{
			net.ParseIP("2001:db8::2"),
			net.ParseIP("2001:db8::3"),
		},
	}
	// ICMPv6 Echo Requestの作成
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}

	// ICMPv6 Echo Requestのペイロード
	payload := []byte("Hello, SRV6!")

	// パケットのバッファを作成
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// パケットをシリアライズ
	err := gopacket.SerializeLayers(buf, opts, ip6, srh, icmpv6, gopacket.Payload(payload))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x\n", buf.Bytes())

}
