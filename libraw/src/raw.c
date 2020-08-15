#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <time.h>
#include <ifaddrs.h>

#include "raw.h"
#include "timespec.h"


static int ifindex = -1;
static int write_six = -1;
static int write_four = -1;
static uint8_t mac[ETH_ALEN];
static struct in_addr ip;
static struct in6_addr ip6;

/* Do simple check if an IPv6 address is global.
 * This is done by a simple match against well known reserved address spaces.
 */
static int is_global(struct in6_addr *addr)
{
	if(addr->s6_addr[0] == 0xFE && addr->s6_addr[1] == 0x80)
		return 0;
	return 1;
}

/* Get the addresses for an interface and write them into our static buffers so
 * they can be requested by the user later.
 *
 * This uses the last (global) address found for each address type.
 */
static void grnvs_get_addresses(const char * ifname, int layer)
{
	struct ifaddrs * ifa;
	struct ifaddrs * ifc;
	struct in6_addr *tmp;

	if(getifaddrs(&ifa) < 0) {
		fprintf(stderr, "could not determine interface addresses: %s\n",
							strerror(errno));
		exit(-1);
	}

	for(ifc = ifa; ifc; ifc=ifc->ifa_next) {
		if(strcmp(ifc->ifa_name, ifname) || ifc->ifa_addr == NULL)
			continue;
		if(ifc->ifa_addr->sa_family == AF_INET) {
			memcpy(&ip,
				&((struct sockaddr_in*)ifc->ifa_addr)->sin_addr,
				sizeof(ip));
		}
		if(ifc->ifa_addr->sa_family == AF_INET6) {
			tmp = &((struct sockaddr_in6*)ifc->ifa_addr)->sin6_addr;
			if(layer == SOCK_DGRAM && !is_global(tmp))
				continue;
			memcpy(&ip6, tmp, sizeof(ip6));
		}
	}

	freeifaddrs(ifa);
}

/* Open a socket usable for the low level access we need.
 * This function also looks up the addresses on our interface, since the ioctls
 * use the interface name as string and not just our socket.
 *
 * For ethernet this is a simple AF_PACKET SOCK_RAW with ETH_P_ALL.
 * For IP we run into the problem that either
 * * AF_PACKET does no route lookup or arp for us, and that would be to much
 *   work
 * * AF_INET(6) even with IPPROTO_RAW filters to much on the reading side and
 *   can only do either v4 or v6 not both.
 * The solution we implemented is a combination. We open 1 AF_PACKET for
 * reading and 2 AF_INET(6) for writing. Read doesn't change because of this,
 * write has to do a bit of special handling.
 */
int grnvs_open(const char * ifname, int layer)
{
	struct sockaddr_ll sa;
	struct ifreq if_idx;
	int fd;

	memset(&ip6, 0, sizeof(ip6));

	if(layer != SOCK_DGRAM && layer != SOCK_RAW) {
		fprintf(stderr, "Could not open socket: %s\n",
							strerror(EINVAL));
		exit(-1);
	}

	if(layer == SOCK_DGRAM) {
		write_six =  socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
		if(write_six < 0) {
			fprintf(stderr, "socket() failed(6): %s\n",
				strerror(errno));
			exit(-1);
		}
		write_four =  socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if(write_four < 0) {
			fprintf(stderr, "socket() failed(4): %s\n",
				strerror(errno));
			exit(-1);
		}
	}

	if (0 > (fd = socket(AF_PACKET, layer, htons(ETH_P_ALL)))) {
		fprintf(stderr, "socket() failed: %s\n", strerror(errno));
		exit(-1);
	}

	memset(&if_idx, 0, sizeof(if_idx));
	strcpy(if_idx.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0) {
		fprintf(stderr, "ioctl() failed: %s\n", strerror(errno));
		exit(-1);
	}

	ifindex = if_idx.ifr_ifindex;

	memset(&if_idx, 0, sizeof(if_idx));
	strcpy(if_idx.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &if_idx) < 0) {
		fprintf(stderr, "ioctl() failed: %s\n", strerror(errno));
		exit(-1);
	}

	memcpy(&mac, if_idx.ifr_hwaddr.sa_data, ETH_ALEN);

	grnvs_get_addresses(ifname, layer);

	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifindex;
	sa.sll_protocol = htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		fprintf(stderr, "bind() failed: %s\n", strerror(errno));
		exit(-1);
	}

	return fd;

}

/* Overload the normal libc read with an additional timeout argument.
 * Implemented with a loop over select.
 */
ssize_t grnvs_read(int fd, void * buf, size_t maxlen, unsigned int * timeout)
{
	ssize_t len;
	int ret;
	fd_set rfd, rfds;
	struct timespec time;
	struct timespec before, after;
	struct timespec * tp = &time;

	if(ifindex < 0) {
		fprintf(stderr, "tried to read from closed socket, aborting\n");
		exit(-1);
	}

	if (!timeout) {
		tp = NULL;
	}
	else {
		if (*timeout <= 0)
			return 0;
		timespecmset(&time, *timeout);
	}

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	do {
		rfd = rfds;
		if (timeout)
			clock_gettime(CLOCK_MONOTONIC, &before);

		ret = pselect(fd+1, &rfd, NULL, NULL, tp, 0);

		if (timeout) {
			clock_gettime(CLOCK_MONOTONIC, &after);
			timespecsub(&after, &before);
			timespecsub(&time, &after);
			*timeout = time.tv_sec*1000 + time.tv_nsec/1000000;
		}

		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "pselect() failed: %s\n",
								strerror(errno));
			exit(-1);
		}

		if (ret == 0) {
			*timeout = 0;
			return 0;
		}

		len = read(fd, buf, maxlen);
	} while (0 > len && errno == EINTR);

	if(0 > len) {
		fprintf(stderr, "read() failed: %s\n", strerror(errno));
		exit(-1);
	}

	return len;
}

/* The write function which handles our 3fd setup for writing.
 *
 * When l3 was requested while creating the socket, this function will check if
 * the packet starts with a 0x60 or 0x40 so we can direct it to the correct
 * output fd and let the kernel handle routing and arp.
 */
ssize_t grnvs_write(int fd, const void * buf, size_t len)
{
	ssize_t ret;
	struct sockaddr_in6 sa;

	if(write_six > 0) {
		memset(&sa, 0, sizeof(sa));
		sa.sin6_family = AF_INET6;
		memcpy(&sa.sin6_addr, (uint8_t *) buf + 24, 16);
	}

	if(ifindex < 0) {
		fprintf(stderr, "tried to write on closed socket, aborting\n");
		exit(-1);
	}

	do {
		if(write_six > 0) {
			if((*((uint8_t *)buf) & 0xF0) == 0x60)
				ret = sendto(write_six, buf, len, 0,
					     (struct sockaddr *)&sa,
					     sizeof(sa));
			else if ((*((uint8_t *)buf) & 0xF0) == 0x40)
				ret = send(write_four, buf, len, 0);
			else {
				fprintf(stderr,
					"write() on layer 3 socket "
					"with unknown IP version 0x%x\n",
						(*((uint8_t *)buf)) >> 4);
				return -EINVAL;
			}
		}
		else
			ret = write(fd, buf, len);

	} while (0 > ret && errno == EINTR);

	if (0 > ret) {
		fprintf(stderr, "write() failed: %s\n", strerror(errno));
		exit(-1);
	}

	return ret;
}

int grnvs_close(int fd)
{
	ifindex = -1;
	memset(&mac, 0, sizeof(mac));
	memset(&ip6, 0, sizeof(ip6));
	ip.s_addr = 0;
	return close(fd);
}

const uint8_t  * grnvs_get_hwaddr(int fd)
{
	(void) fd;
	if(ifindex < 0)
		return NULL;
	return mac;
}


struct in_addr grnvs_get_ipaddr(int fd)
{
	(void) fd;
	return ip;
}

const struct in6_addr  * grnvs_get_ip6addr(int fd)
{
	(void) fd;
	if(ifindex < 0)
		return NULL;
	return &ip6;
}
