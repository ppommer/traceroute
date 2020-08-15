#ifndef _HEXDUMP_H
#define _HEXDUMP_H

#include <stddef.h>

void hexdump(const void *buffer, ssize_t len);

char * hexdump2(const void *buffer, ssize_t len);

#endif
