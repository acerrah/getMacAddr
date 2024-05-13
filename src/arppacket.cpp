#include "arppacket.hpp"

///////////////////////////////
int arp_packet::errexit(int errnum) {
    std::cerr << "Error: " << strerror(errnum) << std::endl;
    exit (1);
}

///////////////////////////////
// Create a raw socket
int arp_packet::create_raw_socket() {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        std::cerr << "Failed to create socket." << std::endl;
        errexit(errno);
    }
    return sockfd;
}

///////////////////////////////
// Gets the MAC address of the local machine
unsigned char* arp_packet::get_local_mac_address() {
    int fd;
    struct ifreq ifr;
    unsigned char* mac = new unsigned char[6];
    const char* inter = interface.c_str();

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, inter, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    for (int i = 0; i < 6; i++) {
        mac[i] = ifr.ifr_hwaddr.sa_data[i];
    }

    return mac;
}

///////////////////////////////
// Gets the IP address of the local machine
std::string arp_packet::get_local_ip() {
    int fd;
    struct ifreq ifr;
    std::string ip;
    const char* inter = interface.c_str();

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, inter, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

    return ip;
}
///////////////////////////////
// Gets the MAC address of the target IP address
unsigned char* arp_packet::get_mac_address(const std::string target_ip) {
    // Create a raw socket
    int sockfd = create_raw_socket();
    
    // Bind the socket to the interface
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(interface.c_str());  // Replace with your interface name


    if (bind(sockfd, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0) {
        errexit(errno);
    }

    // Create the ARP request packet
    struct ether_header eth_header;
    struct ether_arp arp_header;
    memset(&eth_header, 0, sizeof(struct ether_header));
    memset(&arp_header, 0, sizeof(struct ether_arp));

    // Set the destination MAC address to broadcast
    for (int i = 0; i < ETH_ALEN; ++i) {
        eth_header.ether_dhost[i] = 0xff;
    }
    eth_header.ether_type = htons(ETH_P_ARP);

    // Set the source MAC address
    unsigned char* mac = get_local_mac_address();
    memcpy(eth_header.ether_shost, mac, ETH_ALEN);

    // Set the ARP header fields
    arp_header.arp_hrd = htons(ARPHRD_ETHER);
    arp_header.arp_pro = htons(ETH_P_IP);
    arp_header.arp_hln = ETH_ALEN;
    arp_header.arp_pln = sizeof(in_addr);
    arp_header.arp_op = htons(ARPOP_REQUEST);

    // Set the sender MAC address
    memcpy(arp_header.arp_sha, &eth_header.ether_shost, ETH_ALEN);

    // Set the sender IP address
    std::string sender_ip = get_local_ip();
    if (inet_pton(AF_INET, sender_ip.c_str(), &arp_header.arp_spa)< 0) {
        errexit(errno);
    }

    // Set the target IP address
    if (inet_pton(AF_INET, target_ip.c_str(), &arp_header.arp_tpa) < 0) {
        errexit(errno);
    }

    // Construct the packet
    char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];
    memcpy(packet, &eth_header, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), &arp_header, sizeof(struct ether_arp));

    // Send the packet
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(struct sockaddr_ll)) < 0) {
        std::cerr << "Failed to send ARP request." << std::endl;
        errexit(errno);
    }

    // Wait for the ARP reply
    unsigned char buffer[42];
    if (recv(sockfd, buffer, sizeof(buffer), 0) < 0) {
        errexit(errno);
    }

    // Extract the MAC address from the ARP reply
    struct ether_arp* arp_reply = (struct ether_arp*)(buffer + sizeof(struct ether_header));
    unsigned char* ptr = (unsigned char*)arp_reply->arp_sha;
    unsigned char* ret = new unsigned char[6];
    memcpy(ret, ptr, 6);

    // Close the socket
    close(sockfd);
    return ret;
}
