#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//ethernet headers are always 14 bytes
#define ETHER_ADDR_LEN 6

struct ethernet_h{
    u_char ether_dest_host[ETHER_ADDR_LEN]; //the destination host address
    u_char ether_src_host[ETHER_ADDR_LEN]; //the source host address
    u_int16_t ether_type; //to check if its ip etc
};

struct ip_header // by IP header order & Size : minimum 20 Bytes
{
    u_int8_t header_len : 4;
    u_int8_t version : 4;
    u_int8_t type_of_service;
    u_int16_t total_length;
    u_int16_t identification;
    u_int16_t frag_offset;
    u_int8_t time_to_live;
    u_int8_t protocol;
    u_int16_t header_checksum;
    u_int8_t source_address[4];
    u_int8_t destination_address[4];
};

struct tcp_header // by TCP header order & Size : minimum 20 Bytes
{
    u_short source_port;
    u_short dest_port;
    u_int32_t sequence;
    u_int32_t acknowledge;
    u_int8_t data_offset;
    u_int8_t Flags;
    u_short window_size_scaling;
    u_short checksum;
    u_short urgent_pointer;
};

void printMacAddr(const u_char* pdata)
{
    printf("MAC Address : %02x:%02x:%02x:%02x:%02x:%02x\n",
           pdata[0], pdata[1], pdata[2], pdata[3], pdata[4], pdata[5]);
}

void printIPAddr(u_int8_t* pdata)
{
    printf("%d.%d.%d.%d\n",pdata[0],pdata[1],pdata[2],pdata[3]);
}

void print_pData(int datalen, const u_char* Packet_DATA)
{
    if(datalen>10) datalen=10;
    for(int i = 0; i < datalen; i++)
        printf("%02X ", Packet_DATA[i]);
    printf("\n");
}

void usage()
{
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    while (true) {
        char* dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
            return -1;
        }

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        printf("===============================\n");
        printf(" %u Bytes captured\n", header->caplen);

        struct ethernet_h* Eth = (struct ethernet_h*)packet;
        printf(" Source");
        printMacAddr(Eth->ether_src_host);

        printf(" Destination");
        printMacAddr(Eth->ether_dest_host);

        if(ntohs(Eth->ether_type) == 0x0800){
            // type == 0x0800 : IPv4, type == 0x0806 : ARP
            struct ip_header* IP = (struct ip_header*)(packet + sizeof(struct ethernet_h));

            if(IP->version < 4 || IP->version > 9) break;
            // 4 : IP / 5 : ST / 6 : SIP, SIPP, IPv6
            // 7 : TP/IX / 8 : PIP / 9 : TUBA

            printf(" Source IP Address : ");
            printIPAddr(IP->source_address);
            printf(" Destination IP Address : ");
            printIPAddr(IP->destination_address);

            if(IP->protocol== 0x06) // 06 : TCP, 17: UDP
            {
                struct tcp_header* P_TCP = (struct tcp_header*)(packet+ + sizeof(struct ethernet_h) + IP->header_len *4);

                printf(" Source Port Number : %d\n", ntohs(P_TCP->source_port));
                printf(" Destination Port Number : %d\n", ntohs(P_TCP->dest_port));

                int TCP_Data_Len = header->caplen - (sizeof(struct ethernet_h)+ IP->header_len *4 + sizeof(struct tcp_header));
                printf(" TCP Data Length : %d\n", TCP_Data_Len);
                if(TCP_Data_Len>0)
                {
                    printf(" Print Data : ");
                    print_pData(TCP_Data_Len, packet + sizeof(struct ethernet_h)+ IP->header_len *4 + sizeof(struct tcp_header));
                }
            }
        }
        pcap_close(handle);
    }
    return 0;
}
