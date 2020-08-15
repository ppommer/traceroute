#include <net/ethernet.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <asm/byteorder.h>

#include "traceroute.h"
#include "raw.h"
#include "hexdump.h"
#include "checksums.h"

/*
 * We do not use the kernel's definition of the IPv6 header (struct ipv6hdr)
 * because the definition there is slightly different from what we would expect
 * (the problem is the 20bit flow label - 20bit is brain-damaged).
 *
 * Instead, we provide you struct that directly maps to the RFCs and lecture
 * slides below.
 */

struct ipv6_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    uint32_t tc1:4, version:4, flow_label1:4, tc2:4, flow_label2:16;
#elif defined(__BIG_ENDIAN_BITFIELD)
    uint32_t version:4, tc1:4, tc2:4, flow_label1:4, flow_label2:16;
#else
#error "You did something wrong"
#endif
    uint16_t plen;
    uint8_t nxt;
    uint8_t hlim;
    struct in6_addr src;
    struct in6_addr dst;
} __attribute__((packed));

/* IPv6 and ICMPv6 header frames structuring packet array */
uint8_t packet[1514];
uint8_t echo_request[48];
struct ipv6_hdr *ip6_header = (struct ipv6_hdr *) packet;
struct ip6_ext *ip6_ext_header = (struct ip6_ext *) (packet + 40);
struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *) (packet + 40);

/**
 * This is the entry point for student code.
 * We do highly recommend splitting it up into multiple functions.
 *
 * A good rule of thumb is to make loop bodies functions and group operations
 * that work on the same layer into functions.
 *
 * For reading from the network have a look at assignment2. Also read the
 * comments in libraw/include/raw.h
 *
 * To get your own IP address use the grnvs_get_ip6addr function.
 * This one is also documented in libraw/include/raw.h
 */

/*
 * Returns 1 if machine is little endian, 0 otherwise.
 */
int little_endian()
{
    int i = 0x3210;
    char *c = (char*) &i;

    if (*c == 0x10)
        return 1; // little endian
    return 0; // big endian
}

/*
 * Initializes/updates IPv6 and ICMPv6 header.
 */
void set_hdr(struct in6_addr *dstip, struct in6_addr *srcip, int hops, int seq, int length)
{
    // Set IPv6 header
    ip6_header->version = 6;
    ip6_header->tc1 = 0;
    ip6_header->tc2 = 0;
    ip6_header->flow_label1 = 0;
    ip6_header->flow_label2 = 0;
    if (little_endian())
        ip6_header->plen = htons(8);
    else
        ip6_header->plen = 8;
    ip6_header->nxt = IPPROTO_ICMPV6;
    ip6_header->hlim = hops;
    ip6_header->src = *srcip;
    ip6_header->dst = *dstip;

    // Set ICMPv6 header
    icmp6_header->icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6_header->icmp6_code = 0;
    icmp6_header->icmp6_cksum = 0;
    if (little_endian()) {
        icmp6_header->icmp6_dataun.icmp6_un_data16[0] = htons(0xc3d4); // Identifier
        icmp6_header->icmp6_dataun.icmp6_un_data16[1] = htons(seq + 33000); // Sequence Number
    } else {
        icmp6_header->icmp6_dataun.icmp6_un_data16[0] = 0xc3d4; // Identifier
        icmp6_header->icmp6_dataun.icmp6_un_data16[1] = seq + 33000; // Sequence Number
    }
    icmp6_header->icmp6_cksum = icmp6_checksum((struct ip6_hdr *) packet, packet + 40, length - 40);

    // Copy content to echo_request (used for validity check)
    memcpy(echo_request, packet, 48);
}

/*
 * Handles extension header. Returns offset of ICMPv6 message (needed for checksum check in check_packet).
 */
int ext_header()
{
    int offset;

    // Hop-by-Hop (0/0x00) | IPv6-Route (43/0x2b) | IPv6-Opts (60/0x3c)
    if (ip6_header->nxt == IPPROTO_HOPOPTS ||
        ip6_header->nxt == IPPROTO_ROUTING ||
        ip6_header->nxt == IPPROTO_DSTOPTS) {
        offset = 40, ip6_ext_header = (struct ip6_ext *) (packet + offset);
        while (ip6_ext_header->ip6e_nxt == IPPROTO_HOPOPTS ||
               ip6_ext_header->ip6e_nxt == IPPROTO_ROUTING ||
               ip6_ext_header->ip6e_nxt == IPPROTO_DSTOPTS) {
            offset += 8 + ip6_ext_header->ip6e_len * 8;
            ip6_ext_header = (struct ip6_ext *) (packet + offset);
        }
        offset += 8 + ip6_ext_header->ip6e_len * 8;
        icmp6_header = (struct icmp6_hdr *) (packet + offset);
        return offset;
    }
    return 40;
}

/*
 * Check IPv6 header and ICMPv6 packet validity.
 */
int check_packet(char *ipname, const char *ipaddr, int ret, int seq)
{
    int cksum1, cksum2, offset;
    char srcipname[INET6_ADDRSTRLEN], dstipname[INET6_ADDRSTRLEN], ipaddr2[INET6_ADDRSTRLEN];
    struct in6_addr temp;

    /// IPv6 header
    // Version
    if (ip6_header->version != 6)
        return 1;
    // Payload Length
    if ((little_endian() && ntohs(ip6_header->plen) != ret - 40) ||
        (!little_endian() && ip6_header->plen != ret - 40))
        return 1;
    // Next Header
    offset = ext_header();
    if (ip6_header->nxt != IPPROTO_ICMPV6 && ip6_ext_header->ip6e_nxt != IPPROTO_ICMPV6)
        return 1;

    // Destination Address
    inet_ntop(AF_INET6, ip6_header->dst.s6_addr, dstipname, INET6_ADDRSTRLEN);
    if (strcmp(dstipname, ipname) != 0)
        return 1;

    /// ICMPv6 header
    // Type
    if (icmp6_header->icmp6_type != ICMP6_ECHO_REPLY &&
        icmp6_header->icmp6_type != ICMP6_DST_UNREACH &&
        icmp6_header->icmp6_type != ICMP6_TIME_EXCEEDED)
        return 1;

    // Checksum
    cksum1 = icmp6_header->icmp6_cksum;
    icmp6_header->icmp6_cksum = 0;
    cksum2 = icmp6_checksum((struct ip6_hdr *) packet, packet + offset, ret - offset);
    if (cksum1 != cksum2)
        return 1;

    // Echo Reply
    if (icmp6_header->icmp6_type == ICMP6_ECHO_REPLY) {

        // Code
        if (icmp6_header->icmp6_code != 0)
            return 1;

        // Identifier
        if ((little_endian() == 1 && ntohs(icmp6_header->icmp6_dataun.icmp6_un_data16[0]) != 0xc3d4) ||
            (little_endian() == 0 && icmp6_header->icmp6_dataun.icmp6_un_data16[0] != 0xc3d4))
            return 1;

        // Sequence
        if ((little_endian() == 1 && ntohs(icmp6_header->icmp6_dataun.icmp6_un_data16[1]) != seq + 33000 - 1) ||
            (little_endian() == 0 && icmp6_header->icmp6_dataun.icmp6_un_data16[1] != seq + 33000 - 1))
            return 1;

        // Force ipaddr to right format to check source address
        inet_pton(AF_INET6, ipaddr, &temp);
        inet_ntop(AF_INET6, &temp, ipaddr2, INET6_ADDRSTRLEN);

        // Check source address and print output to stdout
        inet_ntop(AF_INET6, ip6_header->src.s6_addr, srcipname, INET6_ADDRSTRLEN);
        if (strcmp(ipaddr2, srcipname) != 0)
            return 1;
        fprintf(stdout,"  %s", srcipname);

    } else if (icmp6_header->icmp6_type == ICMP6_DST_UNREACH) {

        // Data Field
        for (int i = 0; i < 7; ++i)
            if (echo_request[i] != packet[48 + i])
                return 1;
        for (int i = 8; i < 48; ++i)
            if (echo_request[i] != packet[48 + i])
                return 1;

        // Print output to stdout
        inet_ntop(AF_INET6, ip6_header->src.s6_addr, srcipname, INET6_ADDRSTRLEN);
        fprintf(stdout, "  %s!X", srcipname);

    } else if (icmp6_header->icmp6_type == ICMP6_TIME_EXCEEDED) {

        // Code
        if (icmp6_header->icmp6_code != 0)
            return 1;

        // Data Field
        for (int i = 0; i < 7; ++i)
            if (echo_request[i] != packet[48 + i])
                return 1;
        for (int i = 8; i < 48; ++i)
            if (echo_request[i] != packet[48 + i])
                return 1;

        // Print output to stdout
        inet_ntop(AF_INET6, ip6_header->src.s6_addr, srcipname, INET6_ADDRSTRLEN);
        fprintf(stdout, "  %s", srcipname);
    }
    return 0;
}

void run(int fd, const char *ipaddr, int timeoutval, int attempts, int hoplimit)
{
    char ipname[INET6_ADDRSTRLEN];
    struct in6_addr dstip;
    struct in6_addr srcip;
    size_t length;
    ssize_t ret;
    int seq, hops, terminate = 0;
    unsigned int timeout;

    // Initialize address
    memcpy(&srcip, grnvs_get_ip6addr(fd), sizeof(srcip));
    inet_ntop(AF_INET6, &srcip, ipname, INET6_ADDRSTRLEN);
    inet_pton(AF_INET6, ipaddr, &dstip);

    // Initialize counter
    seq = 0, hops = 1;

    // Traceroute start
    while (hops <= hoplimit) {

        // Send echo request <attempts> times
        for (int i = 0; i < attempts; ++i) {

            // Set IPv6 header and ICMPv6 header
            length = sizeof(struct ipv6_hdr) + sizeof(struct icmp6_hdr);
            set_hdr(&dstip, &srcip, hops, seq, length);

            // Print hop limit to stdout
            if (i == 0)
                fprintf(stdout, "%d", hops);

            // Send echo request
            if (( ret = grnvs_write(fd, packet, length)) < 0 ) {
                fprintf(stderr, "grnvs_write() failed: %ld\n", ret);
                hexdump(packet, length);
                exit(-1);
            }

            // Increment sequence counter and initialize/update timeout
            seq++, timeout = timeoutval * 1000;

            // Receive packets
            receive_next_packet:
            if (( ret = grnvs_read(fd, packet, sizeof(packet), &timeout)) < 0 ) {
                fprintf(stderr, "grnvs_read() failed: %ld\n", ret);
                hexdump(packet, length);
                exit(-1);
                // Timeout
            } else if (ret == 0) {
                fprintf(stdout, "  *");
                // Packet received
            } else {

                // Not the right packet
                icmp6_header = (struct icmp6_hdr *) (packet + 40);
                if (check_packet(ipname, ipaddr, ret, seq))
                    goto receive_next_packet;

                // Terminate if destination unreachable or echo reply
                if (icmp6_header->icmp6_type == ICMP6_DST_UNREACH || icmp6_header->icmp6_type == ICMP6_ECHO_REPLY)
                    terminate = 1;

            }
            if (i == attempts - 1)
                fprintf(stdout, "\n");
        }
        if (terminate)
            exit(0); // Graceful termination
        hops++;
    }
}

int main(int argc, char ** argv)
{
    struct arguments args;
    int sock;

    if ( parse_args(&args, argc, argv) < 0 ) {
        fprintf(stderr, "Failed to parse arguments, call with "
                        "--help for more information\n");
        return -1;
    }

    if ( (sock = grnvs_open(args.interface, SOCK_DGRAM)) < 0 ) {
        fprintf(stderr, "grnvs_open() failed: %s\n", strerror(errno));
        return -1;
    }

    setbuf(stdout, NULL);

    run(sock, args.dst, args.timeout, args.attempts, args.hoplimit);

    grnvs_close(sock);

    return 0;
}
