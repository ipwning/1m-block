#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <stdbool.h>
#include <thread>
#include <libnetfilter_queue/libnetfilter_queue.h>

#define TCP 6
#define IP_STR "%hhu.%hhu.%hhu.%hhu"
#define IP_ARG(ip) ip[0], ip[1], ip[2], ip[3]

u_int32_t print_pkt (struct nfq_data *tb);

void dump(char* buf, int size);

void get_ban_list(char *fname);

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data);
