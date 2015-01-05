pkt_clone
=========

Cloning network packet tool for reducing the impact of packet loss. 


##install

make


##Usage: ./pkt_clone interface 'filter expression'

#"interface"

Listen on interface. for example, "eth0", ONLY supports Ethernet and does Not support loopback.

#"filter expression"

Range cloning packet, refer to the "man tcpdump", or search for keywords tcpdump.

#e.g.: ./pkt_clone eth0 'udp and dst port domain'
