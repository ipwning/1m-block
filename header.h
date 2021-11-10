#include <stdint.h>

typedef struct _ip_fragment {
    uint16_t f_off:13;
    uint8_t reserved_bit:1;
    uint8_t no_fragment_bit:1;
    uint8_t more_fragment_bit:1;
} ip_fragment;

typedef struct _ip_header {
    uint8_t h_len:4;
    uint8_t ver:4;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    ip_fragment frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t sip;
    uint32_t dip;
} ip_header;

typedef struct _tcp_flags {
    uint8_t fin:1;  
    uint8_t syn:1;
    uint8_t rst:1;
    uint8_t psh:1;
    uint8_t ack:1;
    uint8_t urg:1;
    uint8_t ece:1;
    uint8_t cwr:1;
    uint8_t ns:1; 
    uint8_t reserved:3; 
    uint8_t offset:4; //header lengtn / 4 
} tcp_flags;

typedef struct _tcp_header {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    tcp_flags flags; 
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header;
