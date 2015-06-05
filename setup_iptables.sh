#!/usr/bin/env sh
echo "Creating chains"
iptables -t mangle -N NFSHUNT_PRE
iptables -t mangle -N NFSHUNT_POST
iptables -t mangle -N NFSHUNT_POLICY
iptables -t mangle -N NFSHUNT_PRE_PD_IN
iptables -t mangle -N NFSHUNT_POST_PD_OUT

echo "Adding test user mark to FORWARD"
iptables -t filter -A FORWARD -j MARK --set-xmark 0x1234/0xffff

echo "Populating NFSHUNT_PRE_PD_IN"
iptables -t mangle -A NFSHUNT_PRE_PD_IN -m physdev --physdev-in eth1 -j MARK --set-xmark 0x41000000/0x4f000000
iptables -t mangle -A NFSHUNT_PRE_PD_IN -m physdev --physdev-in eth2 -j MARK --set-xmark 0x42000000/0x4f000000
iptables -t mangle -A NFSHUNT_PRE_PD_IN -j RETURN

echo "Populating NFSHUNT_PRE"
iptables -t mangle -A NFSHUNT_PRE -m physdev --physdev-in 'eth0' -j RETURN # ignore packets not coming from the interfaces on the slow path
iptables -t mangle -A NFSHUNT_PRE -j CONNMARK --restore-mark # copy mark from connection state to packet
iptables -t mangle -A NFSHUNT_PRE -m mark ! --mark 0x40000000/0x40000000 -j NFSHUNT_PRE_PD_IN # if physdev_in is not marked, send to chain where we do this
iptables -t mangle -A NFSHUNT_PRE -j RETURN

echo "Populating NFSHUNT_POST_PD_OUT"
iptables -t mangle -A NFSHUNT_POST_PD_OUT -m physdev --physdev-out eth1 -j MARK --set-xmark 0x20100000/0x20f00000
iptables -t mangle -A NFSHUNT_POST_PD_OUT -m physdev --physdev-out eth2 -j MARK --set-xmark 0x20200000/0x20f00000
iptables -t mangle -A NFSHUNT_POST_PD_OUT -j RETURN

echo "Populating NFSHUNT_POLICY"
iptables -t mangle -A NFSHUNT_POLICY -p tcp --dport 4999 -m conntrack --ctstate RELATED,ESTABLISHED -j MARK --set-xmark 0x10000000/0x100f0000 # ignore
iptables -t mangle -A NFSHUNT_POLICY -p tcp --dport 5000 -m conntrack --ctstate RELATED,ESTABLISHED -j MARK --set-xmark 0x10010000/0x100f0000 # shunt
iptables -t mangle -A NFSHUNT_POLICY -p tcp --dport 5001 -m conntrack --ctstate RELATED,ESTABLISHED -j MARK --set-xmark 0x10010000/0x100f0000 # shunt
iptables -t mangle -A NFSHUNT_POLICY -p tcp --dport 5666 -m conntrack --ctstate RELATED,ESTABLISHED -j MARK --set-xmark 0x10020000/0x100f0000 # block
iptables -t mangle -A NFSHUNT_POLICY -j RETURN

echo "Populating NFSHUNT_POST"
iptables -t mangle -A NFSHUNT_POST -m physdev ! --physdev-is-bridged -j RETURN # don't bother with non-bridged packets
iptables -t mangle -A NFSHUNT_POST -m mark ! --mark 0x40000000/0x40000000 -j RETURN # if we didn't mark physdev_in, then it's another bridge
iptables -t mangle -A NFSHUNT_POST -m mark ! --mark 0x20000000/0x20000000 -j NFSHUNT_POST_PD_OUT # if physdev_out is not marked, send to chain where we do this
iptables -t mangle -A NFSHUNT_POST -m mark ! --mark 0x10000000/0x10000000 -j NFSHUNT_POLICY # if flow flag is not set, we need to jump to the shunt policy table
iptables -t mangle -A NFSHUNT_POST -j CONNMARK --save-mark
iptables -t mangle -A NFSHUNT_POST -j RETURN

echo "Adding rule to PREROUTING to go to NFSHUNT_PRE"
iptables -t mangle -A PREROUTING -j NFSHUNT_PRE
echo "Adding rule to POSTROUTING to go to NFSHUNT_POST"
iptables -t mangle -A POSTROUTING -j NFSHUNT_POST
