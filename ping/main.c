#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define PING_PACKET_SIZE    64

typedef struct
{
    struct icmp icmp_header;
    char data[PING_PACKET_SIZE];
} ping_packet;

typedef struct
{
    struct ip ip_header;
    ping_packet ping_pkt;
} ip_packet;

static ulong curent_time_ms();
static short ping(const char* ip, int timeout, int packets_quantity);
static void prepare_icmp_packet(ping_packet* packet);
unsigned short checksum (char *pBuffer, int nLen);


int main(int argc,char** argv)
{
    if(argc < 4)
    {
        printf("not enough input, exiting \n");
        return 0;
    }

    const char* const ip = argv[1];
    int timeout = atoi(argv[2]);
    int packets_quantity = atoi(argv[3]);
    time_t time_now = time(0);

    printf("Timeout set: %dsec | Time: %s", timeout ,ctime(&time_now));

    if(ping(ip, timeout, packets_quantity)<0)
    {
        printf("Failed to ping, exiting\n");
        return 0;
    }
    else printf("done, exiting\n");

    return 0;
}

static short ping(const char *ip, int timeout, int packets_quantity )
{
    int ping_sock;
    ulong time_ms=0;
    struct sockaddr_in ping_addres;
    ping_packet packet;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;


    if(ip == NULL)
    {
        perror("Could not get ip");
        return -1;
    }

    prepare_icmp_packet(&packet);
    ping_addres.sin_family = AF_INET;
    ping_addres.sin_port = htons(0);

    if (!inet_aton(ip, (struct in_addr*)&ping_addres.sin_addr.s_addr))
    {
        printf("Could not convert ip");
        return -1;
    }

    if((ping_sock = socket(PF_INET,SOCK_RAW, 1)) == -1)
    {
        perror("Raw socket creation failed");
        return -1;
    }

    setsockopt(ping_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    ip_packet received_packet;
   // struct sockaddr_in received_addres;
   // socklen_t lenght = sizeof(struct sockaddr_in);

    printf("Pinging: %s\n",ip);
    for(int i = 0;i < packets_quantity; i++)
    {
        int res = sendto(ping_sock, &packet, sizeof(ping_packet), 0, (struct sockaddr*)&ping_addres, sizeof(struct sockaddr_in));

        if (res <= 0)
        {
           perror("Could not send");
           return -1;
        }

        time_ms = curent_time_ms();

        if (recv(ping_sock, &received_packet, sizeof(ip_packet), 0 ) <= 0)
        {
           perror("Timeout or recv failed");
           return -1;
        }

    short delay_ms = curent_time_ms() - time_ms;
    printf("Reply from: %s | Bytes: %d | %d ms\n",ip, PING_PACKET_SIZE, delay_ms);

    }

    return 1;
}

static void prepare_icmp_packet(ping_packet *packet)
{
    memset(packet->data, 'x', PING_PACKET_SIZE);
    packet->icmp_header.icmp_hun.ih_idseq.icd_id = rand();
    packet->icmp_header.icmp_type = ICMP_ECHO;
    packet->icmp_header.icmp_hun.ih_idseq.icd_seq = 0;
    packet->icmp_header.icmp_cksum = 0;

    char packet_checksum[PING_PACKET_SIZE + sizeof( packet->icmp_header)];
    memcpy(packet_checksum, &packet->icmp_header, sizeof(packet->icmp_header));
    memcpy(packet_checksum + sizeof(struct icmp), packet->data, PING_PACKET_SIZE);
    packet->icmp_header.icmp_cksum = htons(checksum(packet_checksum, sizeof(packet_checksum)));
}

unsigned short checksum (char *pBuffer, int nLen)
{

    unsigned short nWord;
    unsigned int nSum = 0;
    int i;

    for (i = 0; i < nLen; i = i + 2)
    {
        nWord =((pBuffer [i] << 8)& 0xFF00) + (pBuffer [i + 1] & 0xFF);
        nSum = nSum + (unsigned int)nWord;
    }

    while (nSum >> 16)
    {
        nSum = (nSum & 0xFFFF) + (nSum >> 16);
    }

    nSum = ~nSum;

    return ((unsigned short) nSum);
    //взял с https://www.codeproject.com/KB/IP/Ping_and_Traceroute/Ping_and_Tracert_Codes.zip
}

static ulong curent_time_ms()
{
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    ulong time_ms = time.tv_sec * 1000 + (time.tv_nsec / 1000000);
    return time_ms;
}

