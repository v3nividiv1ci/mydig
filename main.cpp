#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_SIZE 1024
#define SERVER_PORT 53

struct DNSHeader {
    unsigned short ID; // 2 byte

    // 注意位域中的位序：每个字节里面的位反着放
    // FLAGS: 2 byte
    unsigned char RD: 1;
    unsigned char TC: 1;
    unsigned char AA: 1;
    unsigned char opcode: 4;
    unsigned char QR: 1; // 1 bit

    unsigned char rcode: 4;
    unsigned char zero: 3;
    unsigned char RA: 1;

    //RRs: 8 byte
    unsigned short Ques;
    unsigned short AnsRR;
    unsigned short AuthRR;
    unsigned short AddRR;
};

// 根据wireshark的抓包逐位设置报文首部 共12字节
void SetHead (DNSHeader* header) {
    header->ID = (unsigned short) htons(getpid());
    header->QR = 0;
    header->opcode = 0;
    header->AA = 0;
    header->TC = 0;
    header->RD = 1; // 1
    header->RA = 0;
    header->zero = 0;
    header->rcode = 0;
    header->Ques = htons(1);
    header->AnsRR = 0;
    header->AuthRR = 0;
    header->AddRR = 0; // 自己写就不用设置为1了，不然写成1那段字段又不写东西会收不到响应
}

// 填充查询字段: 4 byte + len 查询名(不限长) 查询类型 查询类
void SetQuery (char *name, unsigned char *buf, int len) {
    memcpy(buf + 12, name, len); // 首部长12字节
    int pos = len + 12;
//    for (int i = 0; i < pos; i ++) {
//        printf("%x.", buf[i]);
//    }
//    printf("\n");
    buf[pos] = 0;
    /*
     * 下一步：查询类型根据输入更改
     * */
    buf[pos + 1] = 1; // Type: 2 byte A类型为1
    buf[pos + 2] = 0;
    buf[pos + 3] = 1; // Class: 2 byte  IN为互联网地址
//    for (int i = 0; i < pos + 4; i ++) {
//        printf("%x.", buf[i]);
//    }
}

// 将域名由www.xxxxx.yyy的形式变为 3www5xxxxx3yyy0
int ChangeDN (char *DN, char *name) {
    int i = strlen(DN) - 1;
    int j = i + 1;
    int k = 0; // 记录从后一个.到前一个.之间有多少个字符
    name[j + 1] = 0;
    // 从后向前遍历域名
    for ( ; i >= 0; i--, j--) {
        if (DN[i] == '.') {
            name[j] = k; // 赋值为ascii码
            k = 0;
        }
        else {
            name[j] = DN[i];
            k ++;
        }
    }
    name[0] = k;
    return (strlen(DN) + 2); // 比之前增加了2个字符
}

int SendRecvDNSPacket (unsigned char *buf, int len, unsigned char *RecvMsg) {
    int s;
    struct sockaddr_in MySock{};

    memset(&MySock, 0, sizeof(MySock)); // 初始化
    MySock.sin_addr.s_addr = inet_addr("114.114.114.114"); // 将点分十进制网络地址转换为二进制
    MySock.sin_family = AF_INET; // 协议族
    MySock.sin_port = htons(SERVER_PORT); // 指定端口，主机字节序转换为网络字节序

    // PF_INET 和 AF_INET 其实没什么区别 不过习惯上在建立socket指定协议时用PF_INET，设置地址时用AF_INET
    s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP); // 建立socket SOCK_DGRAM代表UDP
    sendto(s, buf, len, 0, (struct sockaddr *)&MySock, sizeof(MySock)); // 发送报文
    int a = recv(s, RecvMsg, MAX_SIZE, 0);
    return a; // 接收报文

}


int AnswerRRs(unsigned char* RecvMsg, int LenSend) {
    short * ptr;
    ptr = (short *)(RecvMsg + 7);
    int AnsRRs = *ptr;
    return AnsRRs;
}

int ParseMsg(unsigned char* RecvMsg, int LenSend, int RRs, int ** addr, int LenName) {
    int pos = LenSend;
    int AddrRRs = RRs;
    // 遍历每条answer
    /*
     * answer的格式：
     * Name:  2 byte || LenName
     * Type:  2 byte
     * Class: 2 byte
     * TTL:   4 byte
     * RDLength: 2 byte
     * RData: RDLength byte
     * */
    for (int i = 0; i < RRs; i++) {
        pos += LenName;
        // 判断TYPE是否为A类型 (1)
        // (但是我自己发的收到的并没有压缩...只有用dig的时候压缩了) Name 域名重复 故用指针压缩（见rfc1035 4.1.4 message compression）
        int a = RecvMsg[pos + 1];
        if ((int)RecvMsg[pos + 1] != 1) {
            short * ptr;
            ptr = (short *)(RecvMsg + (pos + 8));
            LenName = ntohs(*ptr); // 这个地方一定要记得转换大小端..但是AnswerRRs却已经是主机字节序..太怪了
            pos += 10 + LenName;
            AddrRRs --;
        }
        else {
            pos += 10;
            for(int j = 0; j < 4; j++) {
                addr[i][j] = RecvMsg[pos + j];
            }
            pos += 4;
        }
    }
    return AddrRRs;
}

int main () {
    DNSHeader header{};
    unsigned char buf[MAX_SIZE]; // socket发送的数据
    char DN[MAX_SIZE]; // 要解析的域名：www.xxx.yyy
    char name[MAX_SIZE]; // 转换成的符合DNS报文格式的域名
    unsigned char RecvMsg[MAX_SIZE]; // 接收的数据
    int LenSend = 0; // socket 发送数据的长度
    int LenRecv = 0; // socket 接收报文长度
    int LenName = 0; // 域名长度
    int s;

    /*
     * 先使用标准输入输出，之后改成命令行参数
     * */
    setbuf(stdout, 0);
    printf("输入需要解析的域名：");
    scanf("%s", DN);
    // printf("%s", DN);

    LenSend = ChangeDN(DN, name);
    LenName = LenSend;
//    printf("%d", LenSend);
//    for (int i = 0; i < LenSend; i ++) {
//        printf("%c.", name[i]);
//    }
    int j;

    // 填充首部
    SetHead(&header);
//    for (int i = 0; i < 12; i++) {
//        printf("%x", &header+i);
//    }
//    printf("%d", sizeof(header));
    memcpy(buf, &header, sizeof(header) );
    // 填充查询字段
    SetQuery(name, buf, LenSend);

    LenSend += 16; // 首部(12) + 查询类+类型(4) + len
    memset(RecvMsg, 0, MAX_SIZE);
    LenRecv = SendRecvDNSPacket(buf, LenSend, RecvMsg);

//    printf("接收报文长度为 %d 字节\n", LenRecv);
//    printf("接收报文的16进制表示：\n");
//    for (int i = 0; i < LenRecv; i++) {
//        printf("%x.", (unsigned char)RecvMsg[i]);
//    }


    int RR = AnswerRRs(RecvMsg,LenSend);
    int **addr = (int**)malloc(sizeof(int*) * RR);  //sizeof(int*),不能少*，一个指针的内存大小，每个元素是一个指针。
    for (int i = 0;i < RR;i++)
    {
        addr[i] = (int*)malloc(sizeof(int) * 4);
    }
    int AddrRR = ParseMsg(RecvMsg, LenSend, RR, addr, LenName);
    printf("%s的IP地址为：\n", DN);
    for (int i = RR - AddrRR; i < RR; i++) {
        printf("%d.%d.%d.%d\n", addr[i][0], addr[i][1], addr[i][2], addr[i][3]);
    }

    for (int i = 0;i < RR;i++)
        free(addr[i]);
    free(addr);


}