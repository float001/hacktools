#ifndef __GET_INTERFACE_H__
#define __GET_INTERFACE_H__

#include <stdint.h>
#include <linux/if_ether.h>
#include <string>
#include <vector>

typedef struct {
    uint32_t    status;  // 1 -- up, 0 -- down, -1 -- error
    std::string name;
    uint32_t    ip;
    std::string ip_str;
    uint32_t    netmask;
    std::string netmask_str;
    uint8_t     mac[ETH_ALEN];
    std::string mac_str;
    uint32_t    gw_ip;
    std::string gw_ip_str;
    uint8_t     gw_mac[ETH_ALEN];
    std::string gw_mac_str;
} interface_item_t;

typedef std::vector<interface_item_t> interface_list_t;

int get_if_info(const char* name, interface_item_t& info);
int get_interface_list(interface_list_t& ret_list);

#endif  // __GET_INTERFACE_H__

