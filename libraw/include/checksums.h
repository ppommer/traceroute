#ifndef _CHECKSUMS_H_
#define _CHECKSUMS_H_

#include <inttypes.h>
#include <netinet/in.h>

struct ip6_hdr;

/*
 * Calculate the Internet-Checksum for an icmpv6 packet.
 * This function takes a pointer to the ip header of the packet to build its own
 * pseudo header and a pointer to the actual payload of the packet.
 * The 16bit Internet-Checksum is byteorder independent i.e. the sum returned
 * will already be in correct byte order.
 * For more information refer to rfc1071.
 * Important note: It is assumed that the field for the checksum is set to 0.
 *
 * This function takes a pointer to the struct provided by linux, not the struct
 * given to you by us. They are the same, but you will have to cast the pointer.
 */
uint16_t icmp6_checksum(const struct ip6_hdr *hdr, const uint8_t * payload,
								size_t len);

/*
 * Calculate the crc32 over a continues area in memory.
 */
uint32_t get_crc32(void *frame, size_t length);

#endif /*_CHECKSUMS_H_*/
