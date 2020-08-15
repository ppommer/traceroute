#ifndef _TRACEROUTE_H_
#define _TRACEROUTE_H_

struct arguments {
	char * interface;
	char * dst;
	int timeout;
	int attempts;
	int hoplimit;
};

int parse_args(struct arguments * args, int argc, char ** argv);

#endif /*_TRACEROUTE_H_*/
