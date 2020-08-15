#ifndef _RAW_H_
#define _RAW_H_
#include <sys/types.h>
#include <netinet/in.h>
#include <net/ethernet.h>


/*
 * Opens a raw socket on the specified layer
 * This should only be called once
 *
 * \param ifname The device the socket should read/write on
 * \param layer The layer the device should operate on
 *
 * layer should be either SOCK_DGRAM, or SOCK_RAW for l3 / l2
 */
int grnvs_open(const char * ifname, int layer);


/*
 * Reads from a socket opened by grnvs_open
 * extends the posix read by providing a builtin timeout function.
 *
 * \param fd The socket to read from
 * \param buf A pointer to allocated space, the read data will be written to
 * 	  this buffer
 * \param maxlen The size of the allocated buffer in bytes
 * \param timeout A pointer to an unsigned integer containing the length time
 * 	  this should block in milliseconds, this value will be updated, so it
 * 	  only has to be set once if multiple reads should be done within the
 * 	  the same timeout
 */
ssize_t grnvs_read(int fd, void * buf, size_t maxlen, unsigned int * timeout);

/*
 * Writes to a socket opened by grnvs_open
 *
 * \param fd The socket to write to
 * \param buf A pointer to the data to be written
 * \param The size of the buffer in bytes
 */
ssize_t grnvs_write(int fd, const void * buf, size_t len);

/*
 * Close a socket opened by grnvs_open, after this the socket should not be used
 * anymore
 */
int grnvs_close(int fd);

/*
 * Get the layer 2 address of the device a socket opened by grnvs_open is
 * associated with
 */
const uint8_t * grnvs_get_hwaddr(int fd);


/*
 * Get the layer 3 address of the device a socket opened by grnvs_open is
 * associated with
 *
 * This version retrieves the IPv4 address
 */
struct in_addr grnvs_get_ipaddr(int fd);

/*
 * Get the layer 3 address of the device a socket opened by grnvs_open is
 * associated with
 *
 * This version retrieves the IPv6 address
 */
const struct in6_addr * grnvs_get_ip6addr(int fd);

#endif /*_RAW_H_*/
