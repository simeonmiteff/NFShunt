# NFShunt
NFShunt is an OpenFlow controller integrated with Linux’s Netfilter connection tracking. It allows L2 bridged TCP connections to be accellerated (bypass switched) mid-connection via a hardware data-plane, based on policy expressed as part of a stateful iptables firewall rule-set.

This code is a proof-of-concept for a project I'm working for [SANReN](http://www.sanren.ac.za) and  the research topic for my MSc studies at [WITS University](http://www.wits.ac.za). The idea is to enhance the [Science DMZ](https://fasterdata.es.net/science-dmz/) design without abandoning stateful filtering entirely. In some ways it is similar to [SciPass](http://globalnoc.iu.edu/sdn/scipass.html) (with a focus on tight integration with a firewall, instead of an intrusion detection system).

Note: this code is distributed without warranties of any kind. It has been tested in our lab with a Pica8 P-3290 switch, and on Mininet with OVS, but [YMMV](http://en.wiktionary.org/wiki/your_mileage_may_vary).

For questions or comments, please drop me an email at <simeon.miteff@gmail.com>

# Installation

## Install POX (carp release)
Run:
```
wget -O carp.tgz https://github.com/noxrepo/pox/tarball/carp?_=pox.tgz
mkdir pox
tar -xzf carp.tgz -C pox --strip-components=1
```

Then, from this repo, copy **nfshunt.py** into **pox/ext/** and copy **nfshunt.json** into **pox/**
 
## Install conntrack userspace utility
For Debian/Ubuntu, run: `sudo apt-get install conntrack`

## Create a Linux standard kernel bridge
For Debian/Ubuntu, add a section to **/etc/network/interfaces**:
```
auto br0
iface br0 inet manual
        bridge_ports eth1 eth2
        bridge_stp off       # disable Spanning Tree Protocol
        bridge_waitport 0    # no delay before a port becomes available
        bridge_fd 0          # no forwarding delay
```

You may need to change the bridge interface name, depending on your system. This example assumes `eth1` and `eth2` are being used for the firewall. Remember to adjust the MTU of the bridge and bridge ports as required, and depending on the distro, enable IP forwarding, and netfilter processing for bridged traffic (not needed by default on Debian/Ubuntu). Finally, remember to bring the interface up with: `ifup br0`

# OpenFlow configuration

Set up an OpenFlow switch instance with the slow path host as controller (TCP port 6633). Two external swith ports are *fast*, and two ports connected to the host are those configured in the kernel bridge above, are the *slow* ports.

# NFShunt configuration

* Edit **nfshunt.json**, pair up the external (*fast*) OpenFlow switch ports with *slow path* ports. The `physdevin` numbers match the OpenFlow port connected to the host to the Netfilter bridge physical ports.

* Edit **setup_iptables.sh**, set the interface names (change `eth1` and `eth2` if required), and also interfaces that need to be ignored (such as `eth0`).

# Running

The **run.sh** scripts starts up pox with the nfshunt module, and **debug.sh** does the same, but is more verbose. You should see the OpenFlow switch connect, and the code fork an instance of `conntrack` to monitor Netflow connection tracking events. Now TCP connections matching your policy (configured via **setup_iptables.sh**) will trigger the controller to bypass (or blackhole).

# Copyright and license
This code is copyright 2014-2015 the CSIR, and released under [the Apache 2.0 license](LICENSE).