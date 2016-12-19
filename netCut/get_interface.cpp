#include "./get_interface.h"
#include <vector>
#include <algorithm>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <linux/rtnetlink.h>
#include <string>

// static void get_mac_addr(const char* ip);
static int get_gateway(char* dev, char *gateway, int sizeof_gateeay);
static std::string arp_get(const char *ip, const char* dev);
#define MAXINTERFACES 16
#define GET_MAC_ITEM(a) static_cast<int>(static_cast<unsigned char>(a))

int get_interface_list(le_interface_list_t& ret_list) {
    int fd;
    int if_len;
    struct ifreq buf[MAXINTERFACES];
    struct ifconf ifc;
    char buff[256] = {0};
    char mac_str[256] = {0};

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket(AF_INET,SOCK_DGRAM,0) error:");
        return -1;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t)buf;

    if (ioctl(fd, SIOCGIFCONF, reinterpret_cast<char *>(&ifc)) == -1) {
        perror("SIOCGIFCONF ioctl error:");
        close(fd);
        return -2;
    }

    if_len = ifc.ifc_len / sizeof (struct ifreq);
    while (if_len-- > 0) {
        std::string item_str;
        std::string name;
        int status = 0;
        std::string gateway_ip;
        std::string gateway_mac;

        interface_item_t item;
        item.name = "-";
        item.ip = 0;
        item.ip_str = "-";
        item.netmask_str = "-";
        item.mac_str = "-";
        item.gw_ip_str = "-";
        item.gw_mac_str = "-";

        name = buf[if_len].ifr_name;
        item.name = name;

        if (!(ioctl(fd, SIOCGIFFLAGS,
            reinterpret_cast<char *>(&buf[if_len])))) {
            /* 接口状态 */
            if (buf[if_len].ifr_flags & IFF_UP) {
                status = 1;
            } else {
                status = 0;
            }
            item.status = (status != 0 ? 1 : 0);
        } else {
            perror("SIOCGIFFLAGS ioctl %s error :");
            status = -1;
        }

        /* IP地址 */
        if (!(ioctl(fd, SIOCGIFADDR, reinterpret_cast<char *>(&buf[if_len])))) {
            struct sockaddr_in *cur = reinterpret_cast<struct sockaddr_in*> \
                    (&buf[if_len].ifr_addr);
            item.ip = ntohl(cur->sin_addr.s_addr);
            item.ip_str = inet_ntoa(cur->sin_addr);
        } else {
            perror("SIOCGIFADDR ioctl %s error:");
        }

        /* 子网掩码 */
        if (!(ioctl(fd, SIOCGIFNETMASK,
            reinterpret_cast<char *>(&buf[if_len])))) {
            struct sockaddr_in *cur = reinterpret_cast<struct sockaddr_in*> \
                    (&buf[if_len].ifr_addr);
            item.netmask_str = inet_ntoa(cur->sin_addr.s_addr);
        } else {
            if (sf != NULL) {
                sf->warn_log(0, "SIOCGIFNETMASK ioctl %s error: %s",
                buf[if_len].ifr_name, strerror(errno));
            }
            ignore_item = true;
        }

        /*MAC地址 */
        if (!(ioctl(fd, SIOCGIFHWADDR,
                reinterpret_cast<char *>(&buf[if_len])))) {
            snprintf(mac_str, sizeof (mac_str), "%02x:%02x:%02x:%02x:%02x:%02x"
                    , GET_MAC_ITEM(buf[if_len].ifr_hwaddr.sa_data[0])
                    , GET_MAC_ITEM(buf[if_len].ifr_hwaddr.sa_data[1])
                    , GET_MAC_ITEM(buf[if_len].ifr_hwaddr.sa_data[2])
                    , GET_MAC_ITEM(buf[if_len].ifr_hwaddr.sa_data[3])
                    , GET_MAC_ITEM(buf[if_len].ifr_hwaddr.sa_data[4])
                    , GET_MAC_ITEM(buf[if_len].ifr_hwaddr.sa_data[5]));
            item.mac_str = mac_str;
        } else {
            perror("SIOCGIFHWADDR ioctl %s error:");
        }

        buff[0] = {0};
        if (0 == get_gateway(buf[if_len].ifr_name, buff, sizeof(buff))) {
            gateway_ip = buff;
        }
        if (gateway_ip.size() > 0) {
            item.gw_ip_str = buff;
        }

        uint32_t gateway_ip_int = 0;
        if (gateway_ip.size() > 0) {
            struct in_addr val;
            int ret = inet_aton(gateway_ip.c_str(), &val);
            if (ret == 0) {
                gateway_ip_int = ntohl(val.s_addr);
            }
        }
        if (gateway_ip.size() > 0 && gateway_ip_int > 0
            && INADDR_NONE != gateway_ip_int) {
            gateway_mac = arp_get(gateway_ip.c_str(), buf[if_len].ifr_name);
            if (gateway_mac.size() > 0) {
                item.gw_mac_str = gateway_mac;
            }
        }
        ret_list.push_back(item);
    }

    close(fd);
    return ret_list.size();
}

/*  arp_flags and at_flags field values */
#define ATF_INUSE   0x01    /* entry in use */
#define ATF_COM     0x02    /* completed entry (enaddr valid) */
#define ATF_PERM    0x04    /* permanent entry */
#define ATF_PUBL    0x08    /* publish entry (respond for other host) */
#define ATF_USETRAILERS 0x10    /* has requested trailers */
#define ATF_PROXY   0x20    /* Do PROXY arp */

std::string arp_get(const char *ip, const char* dev) {
    struct arpreq arpreq;
    struct sockaddr_in *sin;
    struct in_addr ina;
    unsigned char *hw_addr;
    int rc;
    int sd = -1;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0) {
        perror("socket");
        return "";
    }
    char mac_str[256] ={0};

    /*you must add this becasue some system will return "Invlid argument"
       because some argument isn't zero */
    memset(&arpreq, 0, sizeof (struct arpreq));

    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    memset(sin, 0, sizeof (struct sockaddr_in));
    sin->sin_family = AF_INET;
    ina.s_addr = inet_addr(ip);
    memcpy(&sin->sin_addr, reinterpret_cast<char *>(&ina),
        sizeof(struct in_addr));

    snprintf(arpreq.arp_dev, sizeof(arpreq.arp_dev), "%s", dev);
    rc = ioctl(sd, SIOCGARP, &arpreq);
    if (rc > 0) {
        hw_addr = (unsigned char *) arpreq.arp_ha.sa_data;

        snprintf(mac_str, sizeof (mac_str), "%02x:%02x:%02x:%02x:%02x:%02x"
                    , GET_MAC_ITEM(hw_addr[0])
                    , GET_MAC_ITEM(hw_addr[1])
                    , GET_MAC_ITEM(hw_addr[2])
                    , GET_MAC_ITEM(hw_addr[3])
                    , GET_MAC_ITEM(hw_addr[4])
                    , GET_MAC_ITEM(hw_addr[5]));
    }
    close(sd);

    return mac_str;
}
#define BUFSIZE 8192

struct route_info {
    u_int dstAddr;
    u_int srcAddr;
    u_int gateWay;
    char ifName[IF_NAMESIZE];
};

int readNlSock(int sockFd, char *bufPtr, int seqNum, int pId) {
    struct nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;
    do {
        if ((readLen = recv(sockFd, bufPtr, BUFSIZE - msgLen, 0)) < 0) {
            perror("get getway ip recv error:");
            return -1;
        }

        nlHdr = (struct nlmsghdr *) bufPtr;
        if ((NLMSG_OK(nlHdr, readLen) == 0)
            || nlHdr->nlmsg_type == NLMSG_ERROR) {
            perror("recieved packet error:\n");
            return -2;
        }


        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        } else {
            bufPtr += readLen;
            msgLen += readLen;
        }


        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            break;
        }
    } while ((nlHdr->nlmsg_seq != static_cast<uint32_t>(seqNum))
            || (nlHdr->nlmsg_pid != static_cast<uint32_t>(pId)));
    return msgLen;
}

void parseRoutes(const char* dev, struct nlmsghdr *nlHdr,
    struct route_info *rtInfo, char *gateway, int sizeof_gateway) {
    struct rtmsg *rtMsg;
    struct rtattr *rtAttr;
    int rtLen;
    char *tempBuf = NULL;
    struct in_addr dst;

    tempBuf = reinterpret_cast<char *>(malloc(100));
    rtMsg = (struct rtmsg *) NLMSG_DATA(nlHdr);
    // If the route is not for AF_INET or does not belong to main routing table
    // then return.
    // if ((rtMsg->rtm_family != AF_INET) ||
    if (rtMsg->rtm_table != RT_TABLE_MAIN) {
        free(tempBuf);
        return;
    }

    rtAttr = (struct rtattr *) RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
            case RTA_OIF:
                if_indextoname(*reinterpret_cast<int *>(RTA_DATA(rtAttr)),
                    rtInfo->ifName);
                break;
            case RTA_GATEWAY:
                rtInfo->gateWay = *reinterpret_cast<u_int *>(RTA_DATA(rtAttr));
                break;
            case RTA_PREFSRC:
                rtInfo->srcAddr = *reinterpret_cast<u_int *>(RTA_DATA(rtAttr));
                break;
            case RTA_DST:
                rtInfo->dstAddr = *reinterpret_cast<u_int *>(RTA_DATA(rtAttr));
                break;
        }
    }
    dst.s_addr = rtInfo->dstAddr;
    std::string dst_addr = inet_ntoa(dst.s_addr);
    if (strstr(dst_addr.c_str(), "0.0.0.0")
            && strcmp(rtInfo->ifName, dev) == 0) {
        std::string gate_addr = inet_ntoa(rtInfo->gateWay);
        snprintf(gateway, sizeof_gateway, "%s", gate_addr.c_str());
    }
    free(tempBuf);
    return;
}

int get_gateway(char* dev, char *gateway, int sizeof_gateway) {
    struct nlmsghdr *nlMsg;
    //struct rtmsg *rtMsg;
    struct route_info *rtInfo;
    char msgBuf[BUFSIZE];

    int sock, len, msgSeq = 0;

    if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0) {
        perror("Socket Creation error:");
        return -1;
    }


    memset(msgBuf, 0, BUFSIZE);

    nlMsg = (struct nlmsghdr *) msgBuf;
    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof (struct rtmsg));
    nlMsg->nlmsg_type = RTM_GETROUTE;
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0) {
        perror("get getway send error:");
        close(sock);
        return -2;
    }


    if ((len = readNlSock(sock, msgBuf, msgSeq, getpid())) < 0) {
        close(sock);
        return -3;
    }

    rtInfo = (struct route_info *) calloc(1, sizeof (struct route_info));
    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        memset(rtInfo, 0, sizeof (struct route_info));
        parseRoutes(dev, nlMsg, rtInfo, gateway, sizeof_gateway);
    }
    free(rtInfo);
    close(sock);
    return 0;
}