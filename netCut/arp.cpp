/*
 *
 * arp.c
 *
 * email: float0001@gmail.com
 *
 * 2016-12-15 14:57:47
 *
 */
#include "arp.h"
#include "nbns.h"
#include <string>
#include <map>

extern int run;
unsigned char* get_mac_addr(const char* src, unsigned char* tmac, int32_t len) {
    int32_t tnum;
    char tsrc[25];
    const char* tok = src;
    long k = 0;
    unsigned char k1, k2;
    if (len < 6) {
        return NULL;

    }

    for (int32_t i = 0; i < 6; i++) {
        if (i == 5) {
            k = strlen(tok);

        } else {
            k = (long)strchr(tok, ':') - (long)tok;
        }

        if ((k < 0) || (k >= 3)) {
            return NULL;
        }

        strncpy(tsrc, tok, k);
        k1 = 0;
        k2 = 0;
        if (k == 1) {
            k1 = 0;
            if ((tsrc[0] >= '0') && (tsrc[0] <= '9')) {
                k2 = tsrc[0] - '0';
            } else if ((tsrc[0] >= 'A') && (tsrc[0] <= 'F')) {
                k2 = tsrc[0] - 'A' + 10;
            } else if ((tsrc[0] >= 'a') && (tsrc[0] <= 'f')) {
                k2 = tsrc[0] - 'a' + 10;
            } else {
                return NULL;
            }
        } else if (k == 2) {
            if ((tsrc[0] >= '0') && (tsrc[0] <= '9')) {
                k1 = tsrc[0] - '0';
            } else if ((tsrc[0] >= 'A') && (tsrc[0] <= 'F')) {
                k1 = tsrc[0] - 'A' + 10;
            } else if ((tsrc[0] >= 'a') && (tsrc[0] <= 'f')) {
                k1 = tsrc[0] - 'a' + 10;
            } else {
                return NULL;
            }
            if ((tsrc[1] >= '0') && (tsrc[1] <= '9')) {
                k2 = tsrc[1] - '0';
            } else if ((tsrc[1] >= 'A') && (tsrc[1] <= 'F')) {
                k2 = tsrc[1] - 'A' + 10;
            } else if ((tsrc[1] >= 'a') && (tsrc[1] <= 'f')) {
                k2 = tsrc[1] - 'a' + 10;
            } else {
                return NULL;
            }
        }
        tnum = k1 * 0x10 + k2;
        if (tnum < 0 || tnum > 255) {
            return NULL;
        }
        tmac[i] = tnum & 0xff;
        tok += k + 1;
    }

    return tmac;
}
int32_t check_ip(const char* p) {
    int32_t n[4];
    char c[4];
    if (p == NULL) {
        return 1;
    }
    if (sscanf(p, "%d%c%d%c%d%c%d%c",
                &n[0], &c[0], &n[1], &c[1],
                &n[2], &c[2], &n[3], &c[3])
            == 7) {
        int32_t i;
        for (i = 0; i < 3; ++i) {
            if (c[i] != '.') {
                return 1;
            }
        }
        for (i = 0; i < 4; ++i) {
            if (n[i] > 255 || n[i] < 0) {
                return 1;
            }
        }
        return 0;
    } else {
        return 1;
    }
}

static void fill_arp_packet(struct ether_arp* arp_packet,
        arp_cheat_addr_t* addrs) {
    struct in_addr src_in_addr, dst_in_addr;

    inet_pton(AF_INET, addrs->arp_snd_ip, &src_in_addr);
    inet_pton(AF_INET, addrs->arp_tgt_ip, &dst_in_addr);

    arp_packet->arp_hrd = htons(ARPHRD_ETHER);
    arp_packet->arp_pro = htons(ETHERTYPE_IP);
    arp_packet->arp_hln = ETH_ALEN;
    arp_packet->arp_pln = IP_ADDR_LEN;
    arp_packet->arp_op = htons(addrs->op);
    memcpy(arp_packet->arp_sha, addrs->arp_snd_mac, ETH_ALEN);
    memcpy(arp_packet->arp_tha, addrs->arp_tgt_mac, ETH_ALEN);
    memcpy(arp_packet->arp_spa, &src_in_addr, IP_ADDR_LEN);
    memcpy(arp_packet->arp_tpa, &dst_in_addr, IP_ADDR_LEN);
}

void send_arp_packet(arp_cheat_addr_t* addrs) {
    char buf[sizeof(arp_packet_t)];
    struct sockaddr_ll saddr_ll;
    arp_packet_t* arp_pkt = (arp_packet_t *)buf;
    struct ifreq ifr;
    int32_t fd = 0, ret_len;
    static unsigned char null_mac[ETH_ALEN] = { 0 };

    do {
        if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
            perror("socket error:");
            break;
        }

        bzero(&saddr_ll, sizeof(struct sockaddr_ll));
        bzero(&ifr, sizeof(struct ifreq));
        memcpy(ifr.ifr_name, addrs->if_name, strlen(addrs->if_name));

        if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
            perror("ioctl get ifindex error:");
            break;
        }
        saddr_ll.sll_ifindex = ifr.ifr_ifindex;
        saddr_ll.sll_family = PF_PACKET;

        if (addrs->arp_snd_ip == NULL) {
            if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
                perror("ioctl get ip error:");
                break;
            }
            addrs->arp_snd_ip =
                inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);
        }

        if (0 == memcmp(addrs->eth_src_mac, &null_mac, ETH_ALEN)) {
            if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
                perror("ioctl get mac error:");
                break;
            }
            memcpy(addrs->eth_src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        } if (0 == memcmp(addrs->arp_snd_mac, &null_mac, ETH_ALEN)) {
            if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
                perror("ioctl get mac error:");
                break;
            }
            memcpy(addrs->arp_snd_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        bzero(arp_pkt, sizeof(arp_packet_t));
        // ethernet packet
        memcpy(arp_pkt->eth_h.ether_shost, addrs->eth_src_mac, ETH_ALEN);
        memcpy(arp_pkt->eth_h.ether_dhost, addrs->eth_dst_mac, ETH_ALEN);
        arp_pkt->eth_h.ether_type = htons(ETHERTYPE_ARP);
        // arp packet
        fill_arp_packet(&arp_pkt->arp_h, addrs);

        time_t now;
        char timebuf[256];
        ret_len = sendto(fd, buf, sizeof buf, 0, (struct sockaddr *)&saddr_ll,
                sizeof(struct sockaddr_ll));
        if (ret_len != sizeof buf) {
            perror("sendto error");
        }
        now = time(0);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S",
                (struct tm *) localtime(&now));
    } while(0);

    if (fd > 0) {
        close(fd);
    }
}
typedef struct {
    std::string ip;
    std::string mac;
    std::string name;
    std::string group;
} host_info;
std::map<std::string, host_info> ips;
std::map<std::string, host_info>::iterator iter;
static int deal_arp_packet(struct ether_arp *arp_packet) {
    if (ntohs(arp_packet->arp_op) == 2) {
        host_info info;
        char mac_str[64];
        struct in_addr ippp;
        memcpy(&ippp, arp_packet->arp_spa, 4);
        info.ip = inet_ntoa(ippp);
        iter = ips.find(info.ip);
        if (iter == ips.end()) {
            snprintf(mac_str, sizeof(mac_str),
                    "%02X:%02X:%02X:%02X:%02X:%02X",
                    arp_packet->arp_sha[0],
                    arp_packet->arp_sha[1],
                    arp_packet->arp_sha[2],
                    arp_packet->arp_sha[3],
                    arp_packet->arp_sha[4],
                    arp_packet->arp_sha[5]);
            info.mac = mac_str;
            get_remote_name(info.ip.c_str(), info.name, info.group);
            printf("%-20s%-20s%-20s%-20s\n", info.ip.c_str(), mac_str,
                    info.name.c_str(), info.group.c_str());
            ips.insert(std::map<std::string, host_info>::value_type\
                    (info.ip, info));
            return 0;
        }
        return 2;
    }
    return 1;
}
void on_recv_arp_func() {
    char buf[sizeof(arp_packet_t)];
    int fd;
    struct timeval read_timeout;
    int rc = 0;
    ips.clear();
    printf("%-20s%-20s%-20s%-20s\n", "Ip", "Mac", "Host Name", "Group");
    do {
        if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1) {
            perror("socket error:");
            break;
        }
        int l_time = time(0);
        unsigned long arg = 1;
        ioctl(fd, FIONBIO, &arg);
        while (1) {
            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(fd, &read_fds);

            read_timeout.tv_sec = 2;
            read_timeout.tv_usec = 0;

            rc = select(fd + 1, &read_fds, NULL, NULL, &read_timeout);
            if (rc < 0) {
                break;
            } else if (rc == 0) {
                break;
            }
            if (FD_ISSET(fd, &read_fds)) {
                bzero(buf, sizeof(arp_packet_t));
                int ret_len = recv(fd, buf, sizeof(arp_packet_t), 0);
                if (ret_len > 0) {
                    if (0 == deal_arp_packet((struct ether_arp *)
                                (buf + sizeof(struct ether_header)))) {
                        l_time = time(0);
                    }
                }
            }
            if (time(0) - l_time > 5) {
                break;
            }
        }
        run = false;
        printf("found %zd host valid!!!!!!\n", ips.size());
        close(fd);
    } while(0);
}
/*
static int32_t check_arp_addr(arp_cheat_addr_t* addrs) {
    unsigned char null_mac[ETH_ALEN] = { 0 };
    if (0 == memcmp(addrs->eth_src_mac, &null_mac, ETH_ALEN)
     || 0 == memcmp(addrs->arp_snd_mac, &null_mac, ETH_ALEN)) {
        fprintf(stderr, "fake mac is null.\n");
        return 1;
     }
    if (0 == memcmp(addrs->eth_dst_mac, &null_mac, ETH_ALEN)
     || 0 == memcmp(addrs->arp_tgt_mac, &null_mac, ETH_ALEN)) {
        fprintf(stderr, "target mac is null.\n");
        return 1;
     }
    if (addrs->arp_tgt_ip == NULL) {
        fprintf(stderr, "target ip is null.\n");
        return 1;
    }
    if (addrs->arp_snd_ip == NULL) {
        fprintf(stderr, "fake ip is null.\n");
        return 1;
    }
    if (addrs->if_name == NULL) {
        fprintf(stderr, "interface name is null.\n");
        return 1;
    }

    return 0;
}
*/

