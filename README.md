# Traceroute

Programming exercise in the course of the lecture _Introduction to Computer Networking and Distributed Systems_ (IN0010) at the Technical University of Munich.

Traceroute makes it possible to determine paths to a target computer and to identify the associated nodes (routers) that forward packets. For this purpose, in the simplest case ICMP Echo Requests are sent to the corresponding destination address with ascending hop limit (starting with a hop limit of 1). When a node in the network receives a packet with a hop limit of 0 or decrements it to 0, it sends an ICMP Time Exceeded back to the sender of the packet. By successively incrementing the hop limit, the sender receives information about all responding nodes. Several echo requests are sent for each hop to compensate for packet loss or to detect parallel paths.

The program implements traceroute for IPv6. Echo requests are sent with ascending hop limit and the respective responses are interpreted and output.

The timeout per attempt (-t <timeout in sec>, default 5), the number of attempts per hop (-q <attempts>, default 3), the maximum number of hops (-m <max hops>, default 15) and the network interface to be used (-i <interface>) are passed as program parameters. To a sent ICMPv6 Echo Request different answers can be given, which are interpreted accordingly. The received packets are checked for plausibility and validity. This includes especially the verification of the header checksum.

Furthermore, the implementation deals with the reception of faulty or incomplete packets.

The following responses are processed:

- Time Exceeded: If valid, this is a response from a node on the path to the target computer.

- Echo Reply: If valid and sent from the target computer, the path to the target is now completely known. After completion of the current hop, no further probes with higher hop limit are sent.

- Destination Unreachable: If valid, the destination computer could not be reached. After completion of the current hop, no more samples with a higher hop limit are sent.

- Timeout: No (other) valid answer was received. The echo request for the next try or hop limit is sent. A timeout can occur because not all routers send error messages or error messages can be lost.
