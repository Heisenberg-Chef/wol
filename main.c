#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>


//---------------------修改这里-------------------------------------
#define URL "localhost"
#define PORT 9
//----------------------------------------------------------------

#define FILLIT 0xFF
#define MAC "08:9e:01:ca:6d:5c"

unsigned char HEXCHAR[23]={'0','1','2','3','4','5','6','7','8','9','A','B','C',
                           'D','E','F','a','b','c','d','e','f',':'};

char * buildMagicPacket(char * mac);
char * macCheck(char mac[]);

int main(int argc,char ** argv)
{
    char * url = URL;
    int * port = malloc(sizeof(int));
    *port = PORT;
    char mac[50] = MAC;

    if(argc>3)
    {
        printf("Too many arguments are provided.\n");
        exit(1);
    }
    else if(argc == 1)
    {
        printf("Default Wol option in use.\n");
        printf("# URL : localhost\n");
        printf("# PORT: 9\n");
        printf("If you want to change the option,change source code where macro URL&PORT macro or using argument directly.\n");
        printf("# FORMAT : ./wol [URL or ip] [PORT]\n");
    }
    else{
        url = argv[1];

        port = (int *) argv[2];
    }

    int udp_socket_fd = socket(AF_INET,SOCK_DGRAM,0);
    if(udp_socket_fd<0)
    {
        perror("socket() failed!\n");
        exit(1);
    }

    struct hostent * host = gethostbyname(url);
    struct sockaddr_in addr = {0};
    addr.sin_port = htons(*port);
    addr.sin_family = AF_INET;
    char tmp[4];
    inet_ntop(AF_INET,*host->h_addr_list,tmp,32); // ipv4 length : 8 x 4 = 32 bit
    printf("\n- DNS report : target host's ip address is : %s\n",tmp);
    addr.sin_addr.s_addr = inet_addr(tmp);

//    sendto(udp_socket_fd,pack,strlen(pack),0,(struct sockaddr *)&addr,sizeof(addr));

    /**
     * UDP数据包，端口不限，数据内容是一个有着特定格式的数据包：
     * Magic Packet，其格式为：6个0xFF加16个目标网卡MAC地址，
     * 因此该Magic Packet总长度为。6+16*6+6=108字节
     */
    unsigned char * magic_packet = malloc(102);
    magic_packet = (unsigned char*)buildMagicPacket(mac);
    int size = sendto(udp_socket_fd,magic_packet,102,0,(struct sockaddr *)&addr,sizeof(addr));
    if(size == -1)
    {
        perror("sendto():");
        exit(1);
    }

    /**
     * 回显数据包
     */
    printf("- Sending Magic Packet completed.\n");
    for (int i = 0; i < 102; ++i) {
        if(i%6==0&&i!=0)
        {
            printf("| ");
        }
        if(i%30==0 && i!=0)
        {
            printf("\n");
        }
        printf("%c%c ",HEXCHAR[magic_packet[i]/16],HEXCHAR[magic_packet[i]%16]);
    }

    close(udp_socket_fd);
    return 0;
}

/**
 * 创建
 * @param mac
 * @return
 */
char * buildMagicPacket(char * mac)
{
    char * bitcodeMAC = macCheck(mac);
    if(bitcodeMAC==NULL)
    {
        perror("Error mac address format!!\n"
               "Example : FF:FF:FF:FF:FF:FF\n");
        exit(1);
    }
    char * packet = malloc(sizeof(char)*102);
    char * p = packet;

    int flag = 0;

    /**
     * UDP数据包，端口不限，数据内容是一个有着特定格式的数据包：
     * Magic Packet，其格式为：6个0xFF加16个目标网卡MAC地址，
     * 因此该Magic Packet总长度为。6+16*6=102个字节
     */
    memset(p,FILLIT,6);
    p+=6;
    for (int i = 0; i < 16; ++i) {
        memcpy(p,bitcodeMAC,6);
        p+=6;
    }
    /**
     * password位置 , WOL数据包有密码设定的选项 , 我没有加密所以默认填写了0.
     * 如果需要可以修改 . 看大家的需求了
     */
//    memset(p,0,6);
    return packet;
}


/**
 * 检查mac地址是否合法
 * @param mac
 * @return
 */
char* macCheck(char mac[])
{
    int i = 0;
    char * afterMatch = malloc(sizeof(char)*6);
    char * point = afterMatch;
    char * p = malloc(8);
    strcat(mac,":");
    // 如果检查含有非法字符返回-1,否则返回拆分好的数组 .
    int flag = 0; // 位置记录标记
    while(*mac!='\0')
    {
        for (i = 0; i < 23; ++i) {
            if(*mac==HEXCHAR[i])
            {
                if(*mac!=':')
                {
                    if(strlen(p)>2)
                    {
                        return NULL;
                    }
                    if(i>15)
                    {
                        i-=6;
                    }
                    *(p+(flag%2))=(char)i;
                }
                else{
                    *afterMatch = (*p << 4) + (*(p+1)) ;
                    afterMatch++;
                    flag=1;
                    memset(p,0,8); // 上文定义了8个缓冲区长度 . 实际上只用2个就够了 , 清零操作 , 防止dirty bit.
                }
                break;
            }
        }
        if(i>=23)
        {
            return NULL;
        }
        flag++;
        mac++;
    }
    return point;
}