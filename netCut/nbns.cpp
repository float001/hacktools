#include "nbns.h"

static std::string trim_right(const std::string& str) {
    if (str.begin() == str.end()) {
        return str;
    }

    std::string t = str;
    std::string::iterator i;
    for (i = t.end() - 1; ;--i) {
        if (!isspace(*i)) {
            t.erase(i + 1, t.end());
            break;
        }
        if (i == t.begin()) {
            t.clear();
            break;
        }
    }
    return t;
}

std::string get_remote_name(const char* ip, std::string &name,
        std::string &group) {
    int fd;
    int d_len = 0;
    int d_cnt = 0;
    int one_l = 0;
    struct sockaddr_in sockaddr;
    int len = sizeof(sockaddr);
    name = "";
    group = "";
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_port = htons(137);
    sockaddr.sin_addr.s_addr = inet_addr(ip);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd <= 0) {
        perror("socket error:");
        return name;
    }

    struct timeval tv_out;
    tv_out.tv_sec = 0;
    tv_out.tv_usec = 500 * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out,
            sizeof(tv_out));

    uint8_t cNBNS[] = { /* Packet 50 */
                0xf6, 0x45, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
                0x00, 0x01 };

    if(sendto(fd, (const char*)cNBNS, 50, 0, (struct sockaddr*)&sockaddr, len)
            == 50) {
        uint8_t buf[1024] = "\0";
        int ret = 0;
        if ((ret = recvfrom(fd, buf, sizeof(buf), 0,
                    (struct sockaddr*)&sockaddr, (socklen_t *)&len)) > 57) {
            if ((buf[0] == 0xf6) && (buf[1] == 0x45)) {
                uint16_t llen;
                memcpy(&llen, &buf[54], 2);
                d_len = ntohs(llen);
                d_cnt = (int)buf[56];
                if (d_cnt > 0) {
                    one_l = (d_len - 46) / d_cnt;
                    for (int i = 0; i < d_cnt; i++) {
                        if ((buf[57 + i * one_l + one_l - 2] & 0x80) == 0x00) {
                            if (name.length() <= 0
                             || buf[57 + i * one_l + one_l - 3] == 0x00) {
                                name = std::string((const char *)
                                        &buf[57 + i * one_l], one_l - 2);
                                name = trim_right(name);
                            }
                        } else {
                            if (group.length() <= 0
                             || buf[57 + i * one_l + one_l - 3] == 0x00) {
                                group = std::string((const char *)
                                        &buf[57 + i * one_l], one_l - 2);
                                group = trim_right(group);
                            }
                        }
                    }
                }
            }
        }
    } else {
        perror("send nbns error:");
    }
    if (name.length() == 0) {
         name = "-";
    }
    if (group.length() == 0) {
        group= "-";
    }
    close(fd);
    return name;
}

