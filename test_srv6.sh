#!/bin/bash

# https://blog.bobuhiro11.net/2021/01-17-srv6linux.html

# create namespaces
for ns in h1 h2 r1 r2 r3 r4
do
  ip netns del $ns
  ip netns add $ns
  ip netns exec $ns sysctl net.ipv6.conf.all.forwarding=1
  ip netns exec $ns sysctl net.ipv6.conf.all.seg6_enabled=1
done

# setup veth pair
ip link add h1-r1 type veth peer name r1-h1
ip link add r1-r2 type veth peer name r2-r1
ip link add r2-r3 type veth peer name r3-r2
ip link add r3-h2 type veth peer name h2-r3
ip link add r2-r4 type veth peer name r4-r2

# assign veth to namespace
ip link set h1-r1 netns h1
ip link set r1-r2 netns r1
ip link set r2-r3 netns r2
ip link set r3-h2 netns r3
ip link set r2-r4 netns r2

ip link set r1-h1 netns r1
ip link set r2-r1 netns r2
ip link set r3-r2 netns r3
ip link set h2-r3 netns h2
ip link set r4-r2 netns r4

# link up
ip netns exec h1 ip link set h1-r1 up
ip netns exec r1 ip link set r1-r2 up
ip netns exec r2 ip link set r2-r3 up
ip netns exec r3 ip link set r3-h2 up
ip netns exec r2 ip link set r2-r4 up

ip netns exec r1 ip link set r1-h1 up
ip netns exec r2 ip link set r2-r1 up
ip netns exec r3 ip link set r3-r2 up
ip netns exec h2 ip link set h2-r3 up
ip netns exec r4 ip link set r4-r2 up

# assign ipv6 addr
ip netns exec h1 ip addr add fc00:a::1/64 dev h1-r1
ip netns exec r1 ip addr add fc00:b::1/64 dev r1-r2
ip netns exec r2 ip addr add fc00:c::1/64 dev r2-r3
ip netns exec r3 ip addr add fc00:d::1/64 dev r3-h2
ip netns exec r2 ip addr add fc00:e::1/64 dev r2-r4

ip netns exec r1 ip addr add fc00:a::2/64 dev r1-h1
ip netns exec r2 ip addr add fc00:b::2/64 dev r2-r1
ip netns exec r3 ip addr add fc00:c::2/64 dev r3-r2
ip netns exec h2 ip addr add fc00:d::2/64 dev h2-r3
ip netns exec r4 ip addr add fc00:e::2/64 dev r4-r2

# add route
ip netns exec h1 ip -6 route add fc00:d::/64 via fc00:a::2
ip netns exec h1 ip -6 route add fc00:e::/64 via fc00:a::2
ip netns exec r1 ip -6 route add fc00:d::/64 via fc00:b::2
ip netns exec r1 ip -6 route add fc00:e::/64 via fc00:b::2
ip netns exec r2 ip -6 route add fc00:d::/64 via fc00:c::2
ip netns exec r4 ip -6 route add fc00:d::/64 via fc00:e::1

ip netns exec h2 ip -6 route add fc00:a::/64 via fc00:d::1
ip netns exec r4 ip -6 route add fc00:a::/64 via fc00:e::1
ip netns exec r3 ip -6 route add fc00:a::/64 via fc00:c::1
ip netns exec r2 ip -6 route add fc00:a::/64 via fc00:b::1

# start tcpdump
rm -rf /tmp/srv6-demo.pcap
timeout 20 ip netns exec r2 tcpdump -i r2-r1 ip6 -w /tmp/srv6-demo.pcap &

# ping with default path from h1 to h2
sleep 3
ip netns exec h1 ping -6 -c 1 fc00:d::2

# enable seg6
ip netns exec r4 sysctl net.ipv6.conf.r4-r2.seg6_enabled=1
ip netns exec r2 sysctl net.ipv6.conf.r2-r4.seg6_enabled=1
ip netns exec r3 sysctl net.ipv6.conf.r3-r2.seg6_enabled=1
ip netns exec h2 sysctl net.ipv6.conf.h2-r3.seg6_enabled=1

for mode in encap inline
do
  # add seg6 route
  ip netns exec r1 ip -6 route del fc00:d::/64
  ip netns exec r1 ip -6 route add fc00:d::/64 encap seg6 mode $mode \
    segs fc00:e::2 dev r1-r2
  ip netns exec r1 ip -6 route show

  # ping with SRv6 path from h1 to h2
  sleep 3
  ip netns exec h1 ping -6 -c 1 fc00:d::2
done

for job in `jobs -p`
do
  wait $job
done
