#pragma once

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <cstring>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

class arp_packet {
    public:
        arp_packet(const std::string& interface) : interface(interface) {};
        unsigned char* get_mac_address(const std::string& target_ip);
        
    private:
        const std::string& interface;
        int errexit(int errnum);
        int create_raw_socket();
        unsigned char* get_local_mac_address();
        std::string get_local_ip();
};