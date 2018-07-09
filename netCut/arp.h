#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string>


typedef struct arp_packet_s_ {
    struct ether_header eth_h;
    struct ether_arp    arp_h;
} arp_packet_t;

typedef struct arp_cheat_addr_s_ {
    int32_t op;
    uint8_t eth_src_mac[ETH_ALEN];
    uint8_t eth_dst_mac[ETH_ALEN];
    uint8_t arp_snd_mac[ETH_ALEN];
    uint8_t arp_tgt_mac[ETH_ALEN];
    const char* arp_snd_ip;
    const char* arp_tgt_ip;
    const char* if_name;
} arp_cheat_addr_t;

typedef struct {
    std::string ip;
    std::string mac;
    std::string name;
    std::string group;
} host_info;

#define IP_ADDR_LEN 4
#define BROADCAST_ADDR {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}


uint8_t* get_mac_addr(const char* src, uint8_t* tmac, int32_t len);
int32_t check_ip(const char* p);
void send_arp_packet(arp_cheat_addr_t* addrs);
void on_recv_arp_func();
std::string get_rand_mac();
std::string get_ip_mac(const char* ifname, const char* src_ip,
         const char* src_mac, const char* target_ip, uint8_t* ip_mac_addr,
         int32_t len);
