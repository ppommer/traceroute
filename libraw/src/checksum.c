#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <string.h>

#include "checksums.h"
#include "hexdump.h"
#include <stdio.h>

struct pseudo_hdr {
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
	uint32_t ulplen;
	uint16_t padding1;
	uint8_t padding2;
	uint8_t next_hdr;
} __attribute__((packed));

uint16_t icmp6_checksum (const struct ip6_hdr *hdr, const uint8_t *payload,
								size_t len)
{
	long sum;
	size_t offset;
	uint8_t buffer[sizeof(struct pseudo_hdr)];
	struct pseudo_hdr *pseudo = (struct pseudo_hdr *)buffer;

	/* Build pseudo header */
	memset(buffer, 0, sizeof(buffer));

	memcpy(&pseudo->src_addr, &hdr->ip6_src, sizeof(struct in6_addr));
	memcpy(&pseudo->dst_addr, &hdr->ip6_dst, sizeof(struct in6_addr));
	pseudo->ulplen = (uint32_t)htonl(len);
	pseudo->next_hdr = 58;

	sum = 0;
	for (offset = 0; offset < sizeof(buffer); offset+=2) {
		sum += *(uint16_t *)(buffer+offset);
	}

	for (offset = 0; len > 0 && offset < len-1; offset+=2) {
		sum += *(uint16_t *)(payload+offset);
	}

	/* If uneven length */
	if (len % 2)
		sum += payload[len-1];

	/* Carry */
	while (sum >> 16)
		sum = (sum >> 16) + (sum & 0xffff);

	return ~((uint16_t)sum);
}
