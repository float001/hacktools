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
#include "get_interface.h"

const char* g_program_name = NULL;
typedef std::vector<interface_item_t> interface_list_t;

static void get_ifs() {
    interface_list_t ifs;
    get_interface_list(ifs);
    fprintf(stdout, "network interface list: [%d]\n", ifs.size());
    fprintf(stdout, )
    std::vector<interface_item_t>::iterator iter;
    for (iter=ivector.begin();iter!=ivector.end();iter++)
    {
        cout<<*iter<<'\0';
    }
}
static void usage() {
    fprintf(stdout, "Usage: %s [OPTIONS...]\n", g_program_name);
    fprintf(stdout, "  OPTIONS\n");
    fprintf(stdout, "    -li            : get network interfaces info\n");
    fprintf(stdout, "    -t             : cut type:\n"
                    "           0-send request packet to target ip\n"
                    "           1-send response packet to target ip\n"
                    "           2-send request packet to getway\n"
                    "           3-send response packet to getway\n");
    fprintf(stdout, "    -i             : interface's name eg. eth0\n");
    fprintf(stdout, "    [-getway ip]   :  specify getway ip\n");
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

    for (int i = 1; i < argc; ++i) {
        if (strncasecmp(argv[i], "-li", 3) == 0) {
            get_ifs();
            return 0;
        } else if (strncasecmp(argv[i], "-tgt_ip", 7) == 0) {
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
        } else if (strncasecmp(argv[i], "-i", 2) == 0) {
            i++;
            if (i < argc) {
                addrs.if_name = argv[i];
            } else {
                fprintf(stderr, "-i need interface's name.\n");
                return -1;
            }
        } else if (strncasecmp(argv[i], "-h", 1) == 0) {
            usage();
        } else {}
    }

    return 0;
}

