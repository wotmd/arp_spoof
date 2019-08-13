#include "send_arp.h"


void getMyIpAddress(char* iface, u_char* my_ip){
    char errbuf[PCAP_ERRBUF_SIZE];
    char ip_string[20];
    pcap_if_t *alldevs;
    int status = pcap_findalldevs(&alldevs, errbuf);
    if(status != 0) {
        printf("%s\n", errbuf);
        return ;
    }

    for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
        if(!strcmp(d->name, iface)){
            for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
                if(a->addr->sa_family == AF_INET)
                    sprintf(ip_string, "%s", inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
            }
        }
    }

    parsing_string2ip(my_ip, ip_string);
    pcap_freealldevs(alldevs);
    return ;
}

void getMacAddress(u_char * uc_Mac, char* iface)
{
    int fd;

    struct ifreq ifr;
    char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)reinterpret_cast<char *>(ifr.ifr_name) , (const char *)iface , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);

    mac = reinterpret_cast<char *>(ifr.ifr_hwaddr.sa_data);
    memcpy(uc_Mac, mac, 6);
}

void GetGatewayForInterface(const char* interface, u_char* gateway_ip) {
  char* gateway = nullptr;

  FILE* fp = popen("netstat -rn", "r");
  char line[256]={0x0};

  while(fgets(line, sizeof(line), fp) != NULL)
  {
    /*
     * Get destination.
     */
    char* destination;
    destination = strndup(line, 15);

    /*
     * Extract iface to compare with the requested one
     * todo: fix for iface names longer than eth0, eth1 etc
     */
    char* iface;
    iface = strndup(line + 73, 4);


    // Find line with the gateway
    if(strcmp("0.0.0.0        ", destination) == 0 && strcmp(iface, interface) == 0) {
        // Extract gateway
        gateway = strndup(line + 16, 15);
    }

    free(destination);
    free(iface);
  }

  pclose(fp);
  parsing_string2ip(gateway_ip, gateway);

}

void findMacAddress(pcap_t* handle, ARPpacket* arp_packet, u_char* target_mac)
{
    for(int i=0; i<5; i++){
      // send arp request
      pcap_sendpacket(handle, (u_char*)arp_packet,60);

      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;
      printf("%u bytes captured\n", header->caplen);

      const EthernetHeader* ether_header = reinterpret_cast<const EthernetHeader*>(packet);

      // type 0x0806 is ARP
      if(ether_header->type == my_ntohs(0x0806)){
          packet += sizeof(EthernetHeader);   // packet pointer move, EthernetHeader is 14 byte
          const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(packet);
          // opcode 0x02 is reply
          if(arp_header->opcode == my_ntohs(0x02)){
              // target_ip == recv packet sender_ip
              if(!memcmp(arp_packet->arp_header.target_ip, arp_header->sender_ip, 4)){
                  memcpy(target_mac, arp_header->sender_mac, 6);
                  return ;
              }
          }
      }
    }
}


void make_arp_request(ARPpacket* packet, u_char* sender_mac, u_char* sender_ip, u_char* target_ip){
    // broadcast setting
    for(int i=0; i<6; i++)
      packet->ether_header.ether_dst[i]=0xFF;

    // set my mac address
    for(int i=0; i<6; i++)
        packet->ether_header.ether_src[i]=sender_mac[i];
    // type = arp
    packet->ether_header.type = my_ntohs(0x0806);

    // ARP packet
    // hardware type = 1 ethernet  (6 IEE 802)
    packet->arp_header.hardware_type = my_ntohs(0x1);
    packet->arp_header.hardware_size = 0x6;

    // protocol type type IPV4
    packet->arp_header.protocol_type = my_ntohs(0x0800);
    packet->arp_header.protocol_size = 0x04;

    // opcode 1 = request , 2= reply
    packet->arp_header.opcode = my_ntohs(0x01);

    // set sender mac address
    for(int i=0; i<6; i++)
        packet->arp_header.sender_mac[i]=sender_mac[i];

    // set sender ip address
    for(int i=0; i<4; i++)
        packet->arp_header.sender_ip[i]=sender_ip[i];

    // set target mac address
    for(int i=0; i<6; i++)
        packet->arp_header.target_mac[i]=0;

    // set target ip address
    for(int i=0; i<4; i++)
        packet->arp_header.target_ip[i]=target_ip[i];
}

void make_arp_reply(ARPpacket* packet, u_char* sender_mac, u_char* sender_ip, u_char* target_mac, u_char* target_ip, u_char* gateway_ip){
    make_arp_request(packet, sender_mac, sender_ip, target_ip);
    // target mac address
    for(int i=0; i<6; i++)
      packet->ether_header.ether_dst[i]=target_mac[i];

    // opcode 1 = request , 2= reply
    packet->arp_header.opcode = my_ntohs(0x02);

    // set sender ip address
    for(int i=0; i<4; i++)
        packet->arp_header.sender_ip[i]=gateway_ip[i];

    // set target mac address
    for(int i=0; i<6; i++)
        packet->arp_header.target_mac[i]=target_mac[i];
}

void next_arp_reqPcap(pcap_t* handle, u_char* arp_packet)
{
    while(true){
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;
      //printf("%u bytes captured\n", header->caplen);

      const EthernetHeader* ether_header = reinterpret_cast<const EthernetHeader*>(packet);

      // type 0x0806 is ARP
      if(ether_header->type == my_ntohs(0x0806)){
          packet += sizeof(EthernetHeader);   // packet pointer move, EthernetHeader is 14 byte
          const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(packet);
          // opcode 0x01 is reply
          if(arp_header->opcode == my_ntohs(0x01)){
              memcpy(arp_packet, packet, header->caplen - sizeof(EthernetHeader));
              return ;
          }
      }
    }
}
