/*
 *
 * net cut by ivan
 *
 * email: float0001@gmail.com
 *
 * 2016-12-19 14:58:32
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <thread>
#include "get_interface.h"
#include "arp.h"

#define FORMLINE "%-3s%-10s%-16s%-16s%-18s%-16s%-18s%-5s\n"
const char* g_program_name = NULL;
typedef std::vector<interface_item_t> interface_list_t;
typedef std::vector<interface_item_t>::iterator interface_list_iter;
bool run = true;

static void get_ifs() {
    interface_list_t ifs;
    char stat_str[10];
    char buf[10];
    int i;
    get_interface_list(ifs);
    fprintf(stdout, "network interface list: [%zd]\n", ifs.size());
    fprintf(stdout, FORMLINE, "Id", "Name", "Ip", "Netmask",
            "Mac", "Gateway Ip", "Gateway Mac", "Status");
    interface_list_iter iter;
    for (i = 1, iter = ifs.begin(); iter != ifs.end();
            iter++, i++) {
        if ((*iter).status == 1) {
            snprintf(stat_str, sizeof(stat_str), "up");
        } else if ((*iter).status == 0) {
            snprintf(stat_str, sizeof(stat_str), "down");
        } else {
            snprintf(stat_str, sizeof(stat_str), "-");
        }
        snprintf(buf, sizeof buf, "%d", i);
        fprintf(stdout, FORMLINE, buf,
            (*iter).name.c_str(), (*iter).ip_str.c_str(),
            (*iter).netmask_str.c_str(),
            (*iter).mac_str.c_str(), (*iter).gw_ip_str.c_str(),
            (*iter).gw_mac_str.c_str(), stat_str);
    }
}
static void usage() {
    fprintf(stdout, "Usage: %s [OPTIONS...]\n", g_program_name);
    fprintf(stdout, "  OPTIONS\n");
    fprintf(stdout, "    -li            : get network interfaces info\n");
    fprintf(stdout, "    -t             : cut type:\n"
                    "                        "
                    "0-send request packet to target ip\n"
                    "                        "
                    "1-send response packet to target ip\n"
                    "                        "
                    "2-send request packet to getway\n"
                    "                        "
                    "3-send response packet to getway\n");
    fprintf(stdout, "    -i             : interface's name eg. eth0\n");
    fprintf(stdout, "    -scan          : scan inner host\n");
    fprintf(stdout, "    [-getway ip]   : specify getway ip\n");
    fprintf(stdout, "    [-tgt_ip ip]   : target ip\n");
    fprintf(stdout, "    [-tgt_mac mac] : target mac\n");
    fprintf(stdout, "    -fake_ip ip    : fake ip\n");
    fprintf(stdout, "    -fake_mac mac  : fake mac\n");
    fprintf(stdout, "    -h             : help\n");
    fprintf(stdout, "\nBest wishes!! Contact float0001@gmail.com.\n");
    exit(0);

}
int main(int argc, const char *argv[]) {
    char *p = (char *)memrchr((const void *)argv[0], (int)'/', strlen(argv[0]));
    g_program_name = p == NULL ? argv[0] : (p + 1);
    const char* ifname = NULL;
    bool is_scan = false;

    for (int i = 1; i < argc; ++i) {
        if (strncasecmp(argv[i], "-li", 3) == 0) {
            get_ifs();
            return 0;
       /* } else if (strncasecmp(argv[i], "-tgt_ip", 7) == 0) {
            i++;
            if (i < argc) {
                if (0 != check_ip(argv[i])) {
                    fprintf(stderr, "target ip invalid!\n");
                    return -1;
                }
                addrs.arp_tgt_ip = argv[i];
            } else {
                fprintf(stderr, "-tgt_ip need ip address.\n");
                return -1;
            }
        }  else if (strncasecmp(argv[i], "-tgt_mac", 8) == 0) {
            i++;
            if (i < argc) {
                if (NULL == get_mac_addr(argv[i], addrs.eth_dst_mac,
                            sizeof(addrs.eth_dst_mac))) {
                    fprintf(stderr, "ethernet destination mac invalid!\n");
                    return -1;
                }
                memcpy(addrs.arp_tgt_mac, addrs.eth_dst_mac,
                    sizeof(addrs.arp_tgt_mac));
            } else {
                fprintf(stderr, "-tgt_mac need mac address.\n");
                return -1;
            }
        } else if (strncasecmp(argv[i], "-fake_ip", 8) == 0) {
            i++;
            if (i < argc) {
                if (0 != check_ip(argv[i])) {
                    fprintf(stderr, "fake ip invalid!\n");
                    return -1;
                }
                addrs.arp_snd_ip = argv[i];
            } else {
                fprintf(stderr, "-fake_ip need ip address.\n");
                return -1;
            }
        } else if (strncasecmp(argv[i], "-fake_mac", 9) == 0) {
            i++;
            if (i < argc) {
                if (NULL == get_mac_addr(argv[i], addrs.eth_src_mac,
                            sizeof(addrs.eth_src_mac))) {
                    fprintf(stderr, "target mac invalid!\n");
                    return -1;
                }
                memcpy(addrs.arp_snd_mac, addrs.eth_src_mac,
                    sizeof(addrs.arp_snd_mac));
            } else {
                fprintf(stderr, "-fake_mac need mac address.\n");
                return -1;
            }
            */
        } else if (strncasecmp(argv[i], "-i", 2) == 0) {
            i++;
            if (i < argc) {
                ifname = argv[i];
            } else {
                fprintf(stderr, "-i need interface's name.\n");
                return -1;
            }
        } else if (strncasecmp(argv[i], "-scan", 5) == 0) {
            is_scan = true;
        } else if (strncasecmp(argv[i], "-h", 2) == 0) {
            usage();
        } else {}
    }
    if (ifname == NULL) {
         usage();
    }
    if (is_scan) {
        uint32_t self_ip, mask;
        uint8_t mac[ETH_ALEN];
        uint32_t start_ip, end_ip;
        struct in_addr start, end;
        char self_ip_str[32], start_s[32], end_s[32];
        int host_cnt = 0;
        arp_cheat_addr_t arp_pkt;
        if (0 != get_if_ip_mask(ifname, self_ip, mask, mac)) {
            fprintf(stderr, "get interface ip and mask error\n");
            return -1;
        }
        if ((self_ip & 0x7F000000) == 0x7F000000) {  // 排除lo网卡
            printf("ignore interface [%s]\n", ifname);
            return 0;
        }
        start.s_addr = htonl(self_ip);
        end.s_addr = htonl(mask);
        snprintf(self_ip_str, sizeof(self_ip_str), inet_ntoa(start));
        snprintf(end_s, sizeof(end_s), inet_ntoa(end));
        printf("self ip:%s mask:%s mac:", self_ip_str, end_s);
        for (int i = 0; i< ETH_ALEN; i++) {
            printf("%02X", mac[i]);
            if (i < ETH_ALEN -1) {
                printf(":");
            }
        }
        printf("\n");

        host_cnt = (mask ^ 0xFFFFFFFF) - 1;
        start_ip = (self_ip & mask) + 1;
        end_ip = start_ip + host_cnt - 1;
        start.s_addr = htonl(start_ip);
        end.s_addr = htonl(end_ip);
        snprintf(start_s, sizeof(start_s), inet_ntoa(start));
        snprintf(end_s, sizeof(end_s), inet_ntoa(end));
        printf("scan ip: %s - %s\n", start_s, end_s);
        printf("total: %d\n", host_cnt);

        std::thread recv(on_recv_arp_func);
        arp_pkt.op = 1;
        arp_pkt.if_name = ifname;
        memcpy(arp_pkt.eth_src_mac, mac, ETH_ALEN);
        arp_pkt.eth_src_mac = BROADCAST_ADDR;
        memcpy(arp_pkt.arp_snd_mac, mac, ETH_ALEN);
        bzero(arp_pkt.arp_tgt_mac, ETH_ALEN);
        arp_pkt.arp_snd_ip = self_ip_str;
        for (int i = 0; i < host_cnt; i++) {
            printf("send[%d]\n", i);
            start.s_addr = htonl(start_ip + i);
            snprintf(start_s, sizeof(start_s), inet_ntoa(start));
            arp_pkt.arp_tgt_ip = start_s;
            send_arp_packet(&arp_pkt);
        }
        sleep(5);
        run = false;

        recv.join();
        return 0;
    }
    return 0;
}

