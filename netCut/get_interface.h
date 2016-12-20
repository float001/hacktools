#ifndef __GET_INTERFACE_H__
#define __GET_INTERFACE_H__

#include <stdint.h>
#include <string>
#include <vector>

typedef struct {
        uint32_t    status;  // 1 -- up, 0 -- down, -1 -- error
        std::string name;
        uint32_t    ip;
        std::string ip_str;
        std::string netmask_str;
        std::string mac_str;
        std::string gw_ip_str;
        std::string gw_mac_str;
} interface_item_t;

typedef std::vector<interface_item_t> interface_list_t;

int get_if_ip_mask(const char* name, uint32_t &ip, uint32_t &mask,
        uint8_t* mac);
int get_interface_list(interface_list_t& ret_list);

#endif  // __GET_INTERFACE_H__

