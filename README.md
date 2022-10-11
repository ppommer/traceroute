# Traceroute

This repository contains an IPv6 traceroute implementation determining paths to a target computer and identifying all associated nodes that forward packets. In the simplest case, ICMP Echo Requests are sent to the corresponding destination address with ascending hop limit (starting with 1). When a node in the network receives a packet with a hop limit of 0 or decrements it to 0, it returns an ICMP Time Exceeded. By successively incrementing the hop limit, the sender receives information about all responding nodes. Several echo requests are sent for each hop to compensate for packet loss or to detect parallel paths.

The timeout per attempt `-t <timeout in sec>` (default 5), the number of attempts per hop `-q <attempts>` (default 3), the maximum number of hops `-m <max hops>` (default 15), and the network interface `-i <interface>` are passed as program parameters. The received response packets are checked for plausibility and validity before being interpreted (e.g., verification of the header checksum). The implementation handles faulty or incomplete packets.

The following responses are processed:

- _Time Exceeded_: If valid, this is a response from a node on the path to the target computer.

- _Echo Reply_: If valid and sent from the target computer, the path to the target is now completely known. After completion of the current hop, no further probes with higher hop limit are sent.

- _Destination Unreachable_: If valid, the destination computer could not be reached. After completion of the current hop, no more samples with a higher hop limit are sent.

- _Timeout_: No (other) valid answer was received. The echo request for the next try or hop limit is sent. A timeout can occur because not all routers send error messages or error messages can be lost.
