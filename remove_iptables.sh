#!/usr/bin/env sh
echo "Flushing..."
echo "FORWARD"
iptables -t filter -F FORWARD
echo "NFSHUNT_PRE_PD_IN"
iptables -t mangle -F NFSHUNT_PRE_PD_IN
echo "NFSHUNT_POST_PD_OUT"
iptables -t mangle -F NFSHUNT_POST_PD_OUT
echo "NFSHUNT_POLICY"
iptables -t mangle -F NFSHUNT_POLICY
echo "NFSHUNT_PRE"
iptables -t mangle -F NFSHUNT_PRE
echo "NFSHUNT_POST"
iptables -t mangle -F NFSHUNT_POST
echo "POSTROUTING"
iptables -t mangle -F POSTROUTING
echo "PREROUTING"
iptables -t mangle -F PREROUTING
echo "Done."

echo "Deleting..."
echo "NFSHUNT_POLICY"
iptables -t mangle -X NFSHUNT_POLICY
echo "NFSHUNT_PRE"
iptables -t mangle -X NFSHUNT_PRE
echo "NFSHUNT_POST"
iptables -t mangle -X NFSHUNT_POST
echo "NFSHUNT_POST_PD_OUT"
iptables -t mangle -X NFSHUNT_POST_PD_OUT
echo "NFSHUNT_PRE_PD_IN"
iptables -t mangle -X NFSHUNT_PRE_PD_IN
echo "Done."
