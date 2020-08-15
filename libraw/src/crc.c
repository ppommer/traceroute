#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define ALG_SET_KEY 1

#define EXIT(x) do {fprintf(stderr, x ": %s\n", strerror(errno)); exit(-1);} while(0)

struct sockaddr_alg {
	uint16_t salg_family;
	uint8_t  salg_type[14];
	uint32_t salg_feat;
	uint32_t salg_mask;
	uint8_t  salg_name[64];
};

static int get_crc_sock()
{
	uint32_t key = ~0;
	struct sockaddr_alg salg;
	int ret;
	int sk;

	sk = socket(PF_ALG, SOCK_SEQPACKET, 0);
	if (sk < 0)
		EXIT("Couldn't open PF_ALG socket");

	memset(&salg, 0, sizeof(salg));

	salg.salg_family = AF_ALG;
	/* Not going to do strncpy for fixed length strings */
	strcpy((char *) salg.salg_type, "hash");
	strcpy((char *) salg.salg_name, "crc32");

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0)
		EXIT("Couldn't bind the PF_ALG socket");

	if (setsockopt(sk, SOL_ALG, ALG_SET_KEY, &key, sizeof(key)) < 0)
		EXIT("Couldnt set the \"key\"");

	ret = accept(sk, NULL, 0);
	if (ret < 0)
		EXIT("Couldn't accept the crc socket");

	close(sk);


	return ret;
}

uint32_t get_crc32(void *frame, size_t length)
{
	uint32_t ret;
	int sock = get_crc_sock();

	if (send(sock, frame, length, 0) < 0)
		EXIT("Couldn't feed data into crc socket");

	if (recv(sock, &ret, sizeof(ret), 0) < 0)
		EXIT("Couldn't read checksum from crc socket");

	close(sock);
	return ret;
}
