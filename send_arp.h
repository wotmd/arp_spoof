#ifndef SEND_ARP_H
#define SEND_ARP_H

#include <pcap.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include "packet.h"


void getMyIpAddress(char* iface, u_char* my_ip);
void getMacAddress(u_char * uc_Mac, char* iface);
void GetGatewayForInterface(const char* interface, u_char* gateway_ip);
void findMacAddress(pcap_t* handle, ARPpacket* arp_packet, u_char* target_mac);
void make_arp_request(ARPpacket* packet, u_char* sender_mac, u_char* sender_ip, u_char* target_ip);
void make_arp_reply(ARPpacket* packet, u_char* sender_mac, u_char* sender_ip, u_char* target_mac, u_char* target_ip, u_char* gateway_ip);
void next_packet(pcap_t* handle, u_char* arp_packet);

#endif // SEND_ARP_H
