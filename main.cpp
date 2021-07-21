//
// Created by 王烨 on 2021/7/20.
//
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define MAX_SIZE 1024
#define SERVER_PORT 53

// 根据wireshark的抓包逐位设置报文首部。。。
void SetHead (unsigned char *buf) {
    buf[0] = 0x00fa; // ID
    buf[1] = 0; // QR
    buf[2] = 0000; // Opcode
    buf[3] = 0; // TC
    buf[4] = 1; // RD
    buf[5] = 0; // RA
    buf[6] = 0; // Z
    buf[7] = 0; // RCODE
    buf[8] = 1; // Questions
    buf[9] = 0; //Answer RRs
    buf[10] = 0; //Authority RRs
    buf[11] = 1; // Additional RRs
}

void SetQuery (char *name, unsigned char *buf, int len) {

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
            name[j] = k;
            k = 0;
        }
        else {
            name[j] = DN[i];
            k ++;
        }
    }
    name[0] = k;
    return (strlen(DN) + 2) // 比之前增加了2个字符
}

int Send&RecvDNSPacket (unsigned char *buf, int len, char *RecvMsg) {
    int s;
    struct sockaddr_in MySock;

    memset(&MySock, 0, sizeof(MySock)); // 初始化
    MySock.sin_addr.s_addr = inet_addr("127.0.0.1"); // 将点分十进制网络地址转换为二进制
    MySock.sin_family = AF_INET; // 协议族
    MySock.sin_port = htons(SERVER_PORT); // 指定端口，主机字节序转换为网络字节序

    // PF_INET 和 AF_INET 其实没什么区别 不过习惯上在建立socket指定协议时用PF_INET，设置地址时用AF_INET
    s = socket(PF_INET, SOCK_DGRAM, 0); // 建立socket SOCK_DGRAM代表UDP
    sendto(s, buf, len, 0, (struct sockaddr *)&sin, sizeof(sin)); // 发送报文
    return recv(s, RecvMsg, MAX_SIZE, 0); // 接收报文

}



int main () {
    unsigned char buf[MAX_SIZE]; // socket发送的数据
    char DN[MAX_SIZE]; // 要解析的域名：www.xxx.yyy
    char name[MAX_SIZE]; // 转换成的符合DNS报文格式的域名
    char RecvMsg[MAX_SIZE]; // 接收的数据
    int len; // socket 发送数据的长度
    int s;

    printf("输入需要解析的域名：");
    scanf("%s", DN);

    len = ChangeDN(DN, name);
    int j;

    // 填充首部
    SetHead(buf);
    // 填充查询字段


}