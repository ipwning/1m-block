#include "1m_block.h"
#include "header.h"

const char *HOST;
const char **BAN_LIST;
uint32_t LIST_SIZE;
bool IS_SEARCHED;

/* returns packet id */

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void get_ban_list(char *fname) {
    FILE *fp = fopen(fname, "r");
    char buf[4096] __attribute__ ((aligned));
    uint32_t end;
    char *ptr;
    const char **save_ptr;
    int idx = 0;

    LIST_SIZE = 1000000;
    BAN_LIST = (const char**)calloc(1, sizeof(char*) * LIST_SIZE);

    if(!fp) {
        printf("%s is not file or can't open the file\n", fname);
        exit(-1);
    }
    if(!BAN_LIST) {
        puts("Can't calloc :(");
        exit(-1);
    }
    while(!feof(fp)) {
        fgets(buf, 4096, fp);
        ptr = strchr(buf, ',') + 1;
        if(!ptr) {
            puts("File syntax error.");
            puts("Syntax: ");
            puts("\t1,aa.com");
            puts("\t2,bb.net");
            puts("\t3,cc.co.kr");
            puts("\t4,dd.jp");
            puts("\t...");
            puts("\t999999,999999.tw");
            exit(-1);
        }
        while(*(ptr+1) == ' ') ++ptr;
        end = strlen(ptr) - 1;
        if(ptr[end] == '\n') ptr[end] = '\0';
        BAN_LIST[idx] = strdup(ptr);
        if(++idx >= LIST_SIZE - 1) {
            save_ptr = BAN_LIST;
            BAN_LIST = (const char**)calloc(1, sizeof(char*) * LIST_SIZE + 500);
            if(!BAN_LIST) {
                puts("Can't calloc :(");
                exit(-1);
            }
            memcpy(BAN_LIST, save_ptr, LIST_SIZE * sizeof(char*));
            LIST_SIZE += 500;
            free(save_ptr);
        }
    }
    LIST_SIZE = idx;
}

void ip_debug(ip_header *ip) {
    printf("=========================================\n");
    printf("ver=%d\n", ip->ver);
    printf("header_len=%#x\n", ip->h_len);
    printf("type_of_service=%#x\n", ip->tos);
    printf("total_len=%d\n", ip->total_len);
    printf("id=%#x\n", ip->id);
    printf("reserved flags=%#x\n", ip->frag.reserved_bit);
    printf("no fragment flags=%#x\n", ip->frag.no_fragment_bit);
    printf("more fragment flags=%#x\n", ip->frag.more_fragment_bit);
    printf("fragment_offset=%#x\n", ip->frag.f_off);
    printf("ttl=%#x\n", ip->ttl);
    printf("protocol=%#x\n", ip->protocol);
    printf("checksum=%#x\n", ip->checksum);
    printf("source ip="IP_STR"\n", IP_ARG( ( (uint8_t*)&ip->sip) ) );
    printf("destination ip="IP_STR"\n", IP_ARG( ( (uint8_t*)&ip->dip) ) );
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
}

void tcp_debug(tcp_header *tcp) {
    printf("=========================================\n");
    printf("source port=%d\n", tcp->sport);
    printf("destination port=%d\n", tcp->dport);
    printf("sequence number=%#x\n", tcp->seq_num);
    printf("ack number=%d\n", tcp->ack_num);
    printf("offset=%#x\n", tcp->flags.offset);
    printf("reserved flags=%#x\n", tcp->flags.reserved);
    printf("ns flags=%#x\n", tcp->flags.ns);
    printf("cwr flags=%#x\n", tcp->flags.cwr);
    printf("ece flags=%#x\n", tcp->flags.ece);
    printf("urg flags=%#x\n", tcp->flags.urg);
    printf("ack flags=%#x\n", tcp->flags.ack);
    printf("psh flags=%#x\n", tcp->flags.psh);
    printf("rst flags=%#x\n", tcp->flags.rst);
    printf("syn flags=%#x\n", tcp->flags.syn);
    printf("fin flags=%#x\n", tcp->flags.fin);
    printf("window size=%#x\n", tcp->window);
    printf("checksum=%#x\n", tcp->checksum);
    printf("urgent pointer=%#x\n", tcp->urgent_ptr);
    printf("+++++++++++++++++++++++++++++++++++++++++\n");
}

void search_routine(const char *host, uint32_t host_len, uint32_t start, uint32_t end) {
    for(int i = start; i < end; ++i) {
        if(IS_SEARCHED) break;
        if(!strncmp(host, BAN_LIST[i], host_len)) {
            printf("%s is banned!\n", BAN_LIST[i]);
            IS_SEARCHED = true;
        }
    }
}

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data) {
    
    struct nfqnl_msg_packet_hdr *ph = NULL;
    tcp_header *tcp = NULL;
    ip_header *ip = NULL;
    int ret;
    int id = 0;
    int http_size;
    int state = NF_ACCEPT;
    unsigned char *_data = NULL;
    unsigned char *http = NULL;
    unsigned char *host = NULL;
    unsigned char *nl = NULL;
    uint32_t host_len;
    std::thread search_th[8];

    ph = nfq_get_msg_packet_hdr(nfa);
    
    if (ph) id = ntohl(ph->packet_id);
    else return -1;

    ret = nfq_get_payload(nfa, &_data);
    ip = (ip_header*)calloc(1, sizeof(ip_header) + 1);
    if(!ip) return -1;
    
    memcpy(ip, _data, sizeof(ip_header));
    *(uint16_t*)&ip->frag = ntohs(*(uint16_t*)&ip->frag);
    ip->total_len = ntohs(ip->total_len);
    ip->checksum = ntohs(ip->checksum);
    //ip_debug(ip);

    if(ip->protocol == TCP) {
        tcp = (tcp_header*)calloc(1, sizeof(tcp_header) + 1);
        if(!tcp) return -1;
        
        memcpy(tcp, _data + (ip->h_len * 4), sizeof(tcp_header));
        *(uint16_t*)&tcp->flags = ntohs(*(uint16_t*)&tcp->flags);
        tcp->sport = ntohs(tcp->sport);
        tcp->dport = ntohs(tcp->dport);
        tcp->seq_num = ntohl(tcp->seq_num);
        tcp->ack_num = ntohl(tcp->ack_num);
        tcp->checksum = ntohs(tcp->checksum);
        tcp->urgent_ptr = ntohs(tcp->urgent_ptr);
        //tcp_debug(tcp);
        
        if(tcp->dport == 80) {
            http_size = ip->total_len - (ip->h_len * 4 + tcp->flags.offset * 4);
            if(0 < http_size) { 
                puts("check the http host.");
                http = (unsigned char *)calloc(1, http_size + 1);
                if(!http) return -1;
                memcpy(http, _data + (ip->h_len * 4 + tcp->flags.offset * 4), http_size);
                host = (unsigned char *)strstr((char *)http, "Host: ");
                if(host) {
                    host += 6;
                    nl = (unsigned char *)strstr((char *)host, "\r\n");
                    if(nl) {
                        *nl = '\0';
                        host_len = nl - host;
                        for(int i = 0; i < 8; ++i) {
                            if(i != 7) 
                                search_th[i] = std::thread(search_routine, (const char *)host, host_len, (LIST_SIZE / 8) * i, (LIST_SIZE / 8) * (i + 1));
                            else
                                search_th[i] = std::thread(search_routine, (const char *)host, host_len, (LIST_SIZE / 8) * i, LIST_SIZE);
                        }
                        for(int i = 0; i < 8; ++i) 
                            search_th[i].join();
                        if(IS_SEARCHED) state = NF_DROP;
                        IS_SEARCHED = false;
                    }
                }
            }
        }
    }
    if(ip)      free(ip);
    if(tcp)     free(tcp);
    if(http)    free(http);
    return nfq_set_verdict(qh, id, state, 0, NULL);
}

uint32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    uint32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        printf("payload_len=%d\n", ret);
        dump(data, ret);
    }
    
    fputc('\n', stdout);

    return id;
}
